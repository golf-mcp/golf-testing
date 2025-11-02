#!/usr/bin/env python3
"""
Generation CLI commands: wizard for auto-generating tests
"""

import asyncio
import re
from datetime import datetime

import click
from rich.prompt import Confirm, Prompt

from ..generation.models import GenerationRequest, UserResources
from ..generation.orchestrator import TestGenerationOrchestrator
from ..shared.console_shared import get_console
from .post_command_hooks import trigger_post_command_hooks
from .utils import validate_api_keys


def create_generate_command() -> click.Command:
    """Create the generate command"""

    @click.command(name="generate")
    @click.option(
        "--global",
        "use_global",
        is_flag=True,
        help="Save configuration globally instead of locally",
    )
    @click.pass_context
    def mcpt_generate(ctx, use_global: bool):
        """Generate tests automatically using AI

        Interactive wizard that researches your MCP server and generates
        comprehensive test cases automatically.

        Examples:
          mcp-t generate
          mcp-t generate --global
        """
        console = get_console()

        # Validate API keys
        anthropic_key, _ = validate_api_keys()
        if not anthropic_key:
            console.print_error(
                "Missing ANTHROPIC_API_KEY environment variable",
                ["Set API key: export ANTHROPIC_API_KEY=your_key_here"],
            )
            return

        console.print_header("Auto Test Generation Wizard")
        console.console.print(
            "[dim]This wizard will help you automatically generate comprehensive test cases[/dim]\n"
        )

        try:
            # Run the wizard
            request = run_generation_wizard(console)

            if not request:
                console.print_info("Generation cancelled")
                return

            # Execute generation with progress tracking
            console.console.print()
            console.print_header("Research & Generation Phase")

            suite = asyncio.run(generate_suite_async(request, use_global, console))

            # Success!
            console.console.print()
            console.print_success(f"Test suite generated: {suite.suite_id}")
            console.console.print(f"✅ Generated {len(suite.test_cases)} test cases")
            console.console.print(
                f"\n[bold]Run tests:[/bold] [cyan]mcp-t run {suite.suite_id} {request.server_id}[/cyan]"
            )

        except KeyboardInterrupt:
            console.console.print("\n[yellow]Generation cancelled by user[/yellow]")
        except ValueError as e:
            # Handle known validation errors
            error_msg = str(e)
            if "not found" in error_msg.lower():
                console.print_error(
                    f"Configuration error: {e!s}",
                    ["Use 'mcp-t list' to see available servers"],
                )
            elif "no tests" in error_msg.lower():
                console.print_error(
                    "Test generation failed",
                    [
                        "No tests could be generated from the server.",
                        "This may be due to:",
                        "  • No tools/resources discovered on the MCP server",
                        "  • API rate limiting or connectivity issues",
                        "  • Invalid server configuration",
                    ],
                )
            else:
                console.print_error(f"Generation failed: {e!s}")
        except ConnectionError as e:
            console.print_error(
                "Connection failed",
                [
                    f"Could not connect to server: {e!s}",
                    "Please check:",
                    "  • Server URL is correct",
                    "  • Server is running",
                    "  • Network connectivity",
                ],
            )
        except Exception as e:
            # Generic error handler
            error_msg = str(e)
            if "api key" in error_msg.lower() or "anthropic" in error_msg.lower():
                console.print_error(
                    "API key error",
                    [
                        "Please check your ANTHROPIC_API_KEY environment variable",
                        "Set it with: export ANTHROPIC_API_KEY=your_key_here",
                    ],
                )
            else:
                console.print_error(
                    f"Generation failed: {e!s}", ["Run with --verbose for more details"]
                )
        finally:
            trigger_post_command_hooks(ctx)

    return mcpt_generate


async def generate_suite_async(request: GenerationRequest, use_global: bool, console):
    """Async wrapper for generation with simple status display"""
    import logging
    import warnings

    from rich.status import Status

    # Suppress verbose logging
    logging.basicConfig(level=logging.WARNING, force=True)
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    warnings.filterwarnings("ignore", category=ResourceWarning)

    orchestrator = TestGenerationOrchestrator()

    # Simple status spinner - one line at a time
    status = Status("Starting...", console=console.console, spinner="dots")
    status.start()

    try:
        # Pass status to orchestrator for updates
        suite = await orchestrator.generate_test_suite(request, use_global, status)

        status.stop()
        console.console.print("[green]✓ Complete[/green]")

        return suite
    except Exception:
        status.stop()
        # Don't print error here - let the outer handler deal with it
        raise


def run_generation_wizard(console) -> GenerationRequest | None:
    """Run interactive wizard to gather generation requirements"""

    # Step 1: Server Selection
    console.console.print("[bold cyan]Step 1: Server Selection[/bold cyan]\n")

    from ..config.config_manager import ConfigManager

    config_manager = ConfigManager()

    # List available servers with numbering
    server_list = []
    try:
        servers = config_manager.list_servers()
        if servers:
            console.console.print("[bold]Available servers:[/bold]")
            for idx, (server_id, server_info) in enumerate(servers.items(), 1):
                server_name = server_info.get("name", server_id)
                source = server_info.get("source", "unknown")
                scope_label = "" if source == "local" else "[dim](global config)[/dim]"

                # Store server ID for number-based selection
                server_list.append(server_id)

                # Show number, ID, name, and scope
                if server_name and server_name != server_id:
                    console.console.print(
                        f"  {idx}. [cyan]{server_id}[/cyan] - {server_name} {scope_label}"
                    )
                else:
                    console.console.print(
                        f"  {idx}. [cyan]{server_id}[/cyan] {scope_label}"
                    )
            console.console.print()
    except Exception:
        pass

    # Prompt for server selection (by number or ID)
    if server_list:
        console.console.print("[dim]Enter server number or ID[/dim]")
        selection = Prompt.ask("Server")

        # Check if selection is a number
        try:
            server_idx = int(selection)
            if 1 <= server_idx <= len(server_list):
                server_id = server_list[server_idx - 1]
            else:
                console.print_error(
                    f"Invalid server number: {server_idx}",
                    [f"Please choose a number between 1 and {len(server_list)}"],
                )
                return None
        except ValueError:
            # Selection is not a number, treat it as server ID
            server_id = selection
    else:
        server_id = Prompt.ask("Server ID to test")

    # Verify server exists
    try:
        config_manager.get_server_by_id(server_id)
    except Exception:
        console.print_error(
            f"Server '{server_id}' not found",
            ["Use 'mcp-t list servers' to see available servers"],
        )
        return None

    # Step 1b: Test Suite Name/ID
    console.console.print("\n[bold cyan]Step 1b: Test Suite Name/ID[/bold cyan]\n")

    # Generate default suite_id with timestamp and collision safety
    import uuid

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")[:-3]  # Include milliseconds
    unique_id = uuid.uuid4().hex[:8]
    default_suite_id = f"{server_id}-generated-{timestamp}-{unique_id}"

    console.console.print(
        "[dim]This will be used as the suite ID, name, and filename (without .json)[/dim]"
    )
    console.console.print(f"[dim]Default: '{default_suite_id}'[/dim]\n")

    suite_id = Prompt.ask(
        "Suite ID/name (or press Enter for default)", default=""
    ).strip()

    if not suite_id:
        suite_id = default_suite_id
    else:
        # Sanitize suite_id to be filesystem-safe
        suite_id = re.sub(r"[^\w\-]", "-", suite_id).lower()

    # Step 2: Testing Focus (Optional)
    console.console.print("\n[bold cyan]Step 2: Testing Focus (Optional)[/bold cyan]\n")
    console.console.print(
        "[dim]By default, we'll generate comprehensive tests for all tools/resources.[/dim]"
    )
    console.console.print(
        "[dim]You can optionally specify a specific focus area.[/dim]\n"
    )

    if Confirm.ask("Specify a custom testing focus?", default=False):
        console.console.print("\n[dim]Examples:[/dim]")
        console.console.print("[dim]  • Focus on error handling[/dim]")
        console.console.print("[dim]  • Test search and filtering features[/dim]")
        console.console.print("[dim]  • Verify authentication flows[/dim]\n")
        user_intent = Prompt.ask("Your testing focus")
    else:
        user_intent = (
            "Comprehensive testing of all available tools, resources, and capabilities"
        )
        console.console.print(
            "[dim]Using default: Comprehensive testing of all capabilities[/dim]"
        )

    # Step 3: Additional Context
    console.console.print(
        "\n[bold cyan]Step 3: Additional Context (Optional)[/bold cyan]\n"
    )

    user_resources = None
    if Confirm.ask(
        "Do you have any URLs with additional context to share?", default=False
    ):
        console.console.print(
            "\n[dim]Paste any relevant URLs (documentation, GitHub repos, examples, etc.)[/dim]"
        )
        console.console.print(
            "[dim]Enter URLs one at a time, or press Enter to finish[/dim]\n"
        )

        urls = []
        while True:
            url = Prompt.ask("URL (or press Enter to finish)", default="")
            if not url:
                break
            urls.append(url)

        if urls:
            user_resources = UserResources(documentation_urls=urls)

    # Step 3B: Web Research
    console.console.print()
    enable_web_search = Confirm.ask(
        "Should I search the internet for additional information?",
        default=True,
    )

    # Build request - test parameters are now automatic
    request = GenerationRequest(
        server_id=server_id,
        suite_id=suite_id,
        user_intent=user_intent,
        user_resources=user_resources,
        enable_web_search=enable_web_search,
        web_search_focus="general",  # Always use general search
        custom_notes=[],  # No custom notes in simplified flow
    )

    # Show summary
    console.console.print("\n[bold]Generation Summary:[/bold]")
    console.console.print(f"  Server: {server_id}")
    console.console.print(f"  Suite ID/name: {suite_id}")
    console.console.print(f"  Focus: {user_intent}")
    console.console.print("  Mode: Auto-generate tests for each tool/resource")
    console.console.print(f"  Web search: {'Yes' if enable_web_search else 'No'}")
    num_urls = len(user_resources.documentation_urls) if user_resources else 0
    console.console.print(f"  Additional URLs: {num_urls}")

    console.console.print()
    if not Confirm.ask("Proceed with generation?", default=True):
        return None

    return request
