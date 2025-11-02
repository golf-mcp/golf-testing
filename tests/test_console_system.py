"""Test suite for unified console system"""

from unittest.mock import patch

import pytest
from rich.console import Console as RichConsole

from test_mcp.shared.console_shared import MCPConsole, MessageType, get_console


class TestMCPConsole:
    """Test MCPConsole functionality"""

    def test_console_initialization(self):
        """Test console initializes correctly"""
        console = MCPConsole()
        assert isinstance(console.console, RichConsole)
        assert MessageType.SUCCESS in console.styles

    def test_message_formatting(self):
        """Test message types format correctly"""
        console = MCPConsole()

        with patch.object(console.console, "print") as mock_print:
            console.print_success("Test message")
            mock_print.assert_called_once()
            call_args = mock_print.call_args[0][0]
            assert "[green]" in call_args
            assert "✅" in call_args
            assert "Test message" in call_args

    def test_error_with_suggestions(self):
        """Test error messages with suggestions"""
        console = MCPConsole()

        with patch.object(console.console, "print") as mock_print:
            console.print_error("Error message", ["Suggestion 1", "Suggestion 2"])
            assert (
                mock_print.call_count == 4
            )  # Error + suggestions header + 2 suggestions

    def test_config_table_creation(self):
        """Test configuration table creation"""
        console = MCPConsole()
        test_configs = {
            "test-server": {"name": "Test Server", "type": "http", "source": "local"}
        }

        table = console.create_config_table(test_configs, "Server")
        assert table.title == "Server List"
        assert (
            len(table.columns) == 5
        )  # Server ID, Details, Transport, OAuth, Creation Date

    def test_singleton_console_access(self):
        """Test get_console returns same instance"""
        console1 = get_console()
        console2 = get_console()
        assert console1 is console2


class TestCLIIntegration:
    """Test CLI integration with console system"""

    def test_all_cli_commands_use_shared_console(self):
        """Test all CLI command files import shared console"""
        import os

        cli_dir = "src/test_mcp/cli"
        for filename in os.listdir(cli_dir):
            if filename.endswith(".py") and filename != "__init__.py":
                filepath = os.path.join(cli_dir, filename)
                with open(filepath) as f:
                    content = f.read()

                # Should have shared console import or no Console() usage
                assert "console_shared" in content or "Console()" not in content, (
                    f"{filename} should use shared console system"
                )


if __name__ == "__main__":
    pytest.main([__file__])
