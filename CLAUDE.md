# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the MCP Testing Framework - a Python CLI tool for automated testing of MCP (Model Context Protocol) servers using AI agents. The framework simulates realistic conversations with MCP servers and provides automated pass/fail evaluation using LLM judges.

## Commands

### Installation
```bash
# Development install
pip install -e .

# Production install  
pip install mcp-testing
```

### Development Commands
```bash
# Linting and formatting
python -m ruff check src/
python -m ruff format src/
python -m black src/

# Type checking
python -m mypy src/

# Testing
python -m pytest
python -m pytest tests/  # if tests directory exists
python -m pytest -v --tb=short  # verbose with short traceback
```

### CLI Usage
```bash
# Main CLI entry point
mcp-t --help

# Complete onboarding (demo + configuration + shell completion)
mcp-t quickstart

# Create configurations
mcp-t create server          # Interactive server creation
mcp-t create suite           # Interactive test suite creation with templates
mcp-t create test-case --suite-id existing-suite

# Run tests
mcp-t run suite-id server-id
mcp-t run suite-id server-id --verbose

# Additional commands
mcp-t compliance server-id
mcp-t health server-id
mcp-t list                   # View configurations
mcp-t show server server-id  # View specific configuration

# Version update notifications
mcp-t --no-update-notifier COMMAND  # Disable update notifications for a command
```

### Version Update Notifications

The CLI automatically checks for updates and displays notifications after command execution.

**Configuration:**
- Checks occur weekly by default
- Notifications respect 24-hour cooldown
- Configuration stored in `~/.config/mcp-t/update_config.json`

**Opt-out options:**
- Command flag: `mcp-t --no-update-notifier COMMAND`
- Environment variable: `export NO_UPDATE_NOTIFIER=1`
- Configuration file: Set `"enabled": false` in update config

**Cache location:**
- Version check results cached in `~/.cache/mcp-t/version_check.json`
- Cache expires after 7 days by default

## Architecture

### Core Components

**CLI (`src/test_mcp/cli/`)**
- `main.py`: Primary CLI interface using Click framework
- Entry point: `mcp-t` command (defined in pyproject.toml)

**Agent System (`src/test_mcp/agent/`)**
- AI agent that connects to MCP servers and conducts test conversations
- Handles MCP protocol communication and tool interactions

**Testing Framework (`src/test_mcp/testing/`)**
- `conversation_manager.py`: Orchestrates multi-turn conversations
- `conversation_judge.py`: LLM-based evaluation of test success
- Core test models and execution logic

**Type-Safe Test Models (`src/test_mcp/models/`)**
- `compliance.py`: MCP protocol compliance testing models
- `security.py`: Authentication and vulnerability testing models
- `conversational.py`: Multi-turn dialogue testing models
- `factory.py`: Type-safe test suite creation and registry
- Replaces monolithic shared_models.py for better type safety

**Configuration (`src/test_mcp/config/config_manager.py`)**
- Type-safe configuration management with template system
- Supports both legacy and new type-specific models
- JSON-based configuration for servers and test cases

### Key Files
- `pyproject.toml`: Python project configuration, dependencies, and tool settings
- `src/test_mcp/__init__.py`: Package initialization and version info
- `examples/`: Sample configurations for servers and test suites
- `test_results/`: Output directory for test results and evaluations

### Configuration Format

**Server Config (`server.json`)**:
```json
{
  "type": "url",
  "url": "https://your-mcp-server.com/mcp", 
  "name": "server_name"
}
```

**Test Suite (`suite.json`)**:
```json
{
  "suite_id": "test_suite",
  "name": "Test Suite Name",
  "test_cases": [{
    "test_id": "test_case_id", 
    "user_message": "Test message",
    "success_criteria": "Expected outcome"
  }]
}
```

## Development Setup

### Environment Variables
Required API keys in `.env`:
```
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
```

### Python Requirements
- Python 3.9+
- Core dependencies: pydantic, anthropic, openai, httpx, click, rich
- Dev dependencies: pytest, black, ruff, mypy, pre-commit

### Testing Strategy
- Uses pytest for unit testing
- Test files follow pattern: `test_*.py` or `*_test.py`
- Test results saved to `test_results/` directory
- LLM judge provides automated evaluation with reasoning