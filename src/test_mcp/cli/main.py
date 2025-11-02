#!/usr/bin/env python3
"""
MCP Testing Framework CLI - Main entry point and command coordination
"""

import sys
import time

import click

from .. import __version__
from ..shared.console_shared import get_console
from ..utils.command_tracker import get_command_tracker
from .config_commands import (
    create_list_command,
    create_show_command,
)
from .create_commands import (
    create_create_group,
)
from .generation_commands import (
    create_generate_command,
)
from .post_command_hooks import trigger_post_command_hooks
from .report_commands import (
    create_report_group,
)
from .setup_commands import (
    create_quickstart_group,
)

# Import command creators from modules
from .test_commands import (
    create_run_command,
)


class CLIErrorHandler:
    """Handles different types of CLI errors with appropriate user feedback"""

    def __init__(self, console, start_time: float):
        self.console = console
        self.start_time = start_time

    def handle_bad_parameter(self, error: click.BadParameter) -> None:
        """Handle parameter validation errors with helpful suggestions"""
        param_name = error.param.name if error.param else "parameter"

        # Extract the actual error message from Click's BadParameter
        error_msg = str(error).split(": ", 1)[-1] if ": " in str(error) else str(error)

        # Add suggestions if this is a choice parameter
        if hasattr(error.param, "type") and hasattr(error.param.type, "choices"):
            choices = list(error.param.type.choices)
            suggestions = [
                f"Try: mcp-t {' '.join(sys.argv[1:-1])} {choice}" for choice in choices
            ]
            self.console.print_error(f"Invalid {param_name}: {error_msg}", suggestions)
        else:
            self.console.print_error(f"Invalid {param_name}: {error_msg}")

        _handle_command_completion(self.start_time, exit_code=1)
        sys.exit(1)

    def handle_usage_error(self, error: click.UsageError) -> None:
        """Handle command not found errors with command suggestions"""
        # Extract command from message if it's a "No such command" error
        if "No such command" in str(error):
            # Try to extract the invalid command from the error message
            import re

            match = re.search(r"No such command '([^']+)'", str(error))
            if match:
                invalid_cmd = match.group(1)
                # Get available commands from the CLI
                available_commands = [
                    "quickstart",
                    "generate",
                    "create",
                    "run",
                    "list",
                    "show",
                    "report",
                ]
                # Get suggestions from the existing suggestion system
                from .suggestions import find_closest_matches

                suggestions = find_closest_matches(
                    invalid_cmd, available_commands, max_suggestions=3, cutoff=0.5
                )

                if suggestions:
                    suggestion_list = [
                        f"Did you mean: mcp-t {suggestion}"
                        for suggestion in suggestions
                    ]
                    self.console.print_error(
                        f"Unknown command: '{invalid_cmd}'", suggestion_list
                    )
                else:
                    self.console.print_error(
                        f"Unknown command: '{invalid_cmd}'",
                        ["Try: mcp-t --help for all commands"],
                    )
            else:
                self.console.print_error(str(error))
        else:
            self.console.print_error(str(error))

        _handle_command_completion(self.start_time, exit_code=1)
        sys.exit(1)

    def handle_system_exit(self, error: SystemExit) -> None:
        """Handle CLI system exits"""
        # SystemExit.code can be None, so provide default value
        exit_code = error.code if error.code is not None else 0
        # Ensure exit_code is an integer
        if isinstance(exit_code, str):
            try:
                exit_code = int(exit_code)
            except ValueError:
                exit_code = 1
        _handle_command_completion(self.start_time, exit_code=exit_code)
        raise


def show_mcpt_overview() -> None:
    """Show ultra-simple overview"""
    console = get_console()
    console.print_header("MCP Testing (mcp-t) - Ultra-simple MCP server testing")
    console.console.print()
    console.console.print("[bold]Common commands:[/bold]")
    console.print_command("mcp-t quickstart", "Complete onboarding (demo + config)")
    console.print_command("mcp-t generate [--global]", "Auto-generate tests with AI")
    console.print_command(
        "mcp-t create suite [--global] [--id <SUITE-ID>]", "Create test configurations"
    )
    console.print_command(
        "mcp-t create server [--global] [--id <SERVER-ID>]", "Add server configurations"
    )
    console.print_command(
        "mcp-t run <SUITE-ID> <SERVER-ID> [--verbose] [--global]", "Run tests"
    )
    console.print_command("mcp-t list [servers|suites]", "List configurations")
    console.print_command(
        "mcp-t show <server|suite> <CONFIG-ID>", "Show configuration details"
    )


def show_help(ctx, param, value):
    """Custom help callback that shows the same overview as when no command is given"""
    if value and not ctx.resilient_parsing:
        argv = sys.argv[1:]
        help_index = next(
            (i for i, arg in enumerate(argv) if arg in ["--help", "-h"]), -1
        )
        subcommands = [
            "quickstart",
            "generate",
            "create",
            "run",
            "list",
            "show",
            "report",
        ]

        if help_index >= 0:
            has_subcommand_before = any(arg in subcommands for arg in argv[:help_index])
            if not has_subcommand_before:
                show_mcpt_overview()
                ctx.exit()


@click.group(
    invoke_without_command=True,
    name="mcp-t",
    context_settings={"help_option_names": []},  # Disable default help at group level
)
@click.version_option(version=__version__, prog_name="mcp-t")
@click.option(
    "--help",
    "-h",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=show_help,
    help="Show this message and exit",
)
@click.option(
    "--no-update-notifier", is_flag=True, help="Disable version update notifications"
)
@click.option(
    "--no-report-suggestions", is_flag=True, help="Disable issue reporting suggestions"
)
@click.pass_context
def mcpt_cli(ctx, no_update_notifier, no_report_suggestions) -> None:
    """MCP Testing - Ultra-simple MCP server testing"""
    # Store flags in context for subcommands
    ctx.ensure_object(dict)
    ctx.obj["no_update_notifier"] = no_update_notifier
    ctx.obj["no_report_suggestions"] = no_report_suggestions

    # Track command start time for duration calculation
    ctx.obj["command_start_time"] = time.time()

    if ctx.invoked_subcommand is None:
        show_mcpt_overview()
        # Show notifications after main command (following update notifier pattern)
        trigger_post_command_hooks(ctx)


def mcpt_main() -> None:
    """Entry point for the ultra-simple mcp-t CLI"""
    start_time = time.time()
    error_handler = CLIErrorHandler(get_console(), start_time)

    try:
        mcpt_cli(standalone_mode=False)
        _handle_command_completion(start_time, exit_code=0)
    except click.BadParameter as e:
        error_handler.handle_bad_parameter(e)
    except click.UsageError as e:
        error_handler.handle_usage_error(e)
    except SystemExit as e:
        error_handler.handle_system_exit(e)
    except click.Abort:
        # Handle user interruption (Ctrl+C) - Click converts KeyboardInterrupt to Abort
        console = get_console()
        console.print("\n[dim]Operation cancelled by user[/dim]")
        _handle_command_completion(start_time, exit_code=130)
        sys.exit(130)
    except KeyboardInterrupt:
        # Handle user interruption (fallback, though Click usually catches this first)
        console = get_console()
        console.print("\n[dim]Operation cancelled by user[/dim]")
        _handle_command_completion(start_time, exit_code=130)
        sys.exit(130)
    except Exception as e:
        # Only for truly unexpected errors
        _handle_command_completion(start_time, exit_code=1)
        console = get_console()
        console.print(f"[red]Unexpected error: {e}[/red]")
        raise


def _handle_command_completion(start_time: float, exit_code: int) -> None:
    """Track command completion and show suggestions"""
    try:
        # Track command for analytics
        duration_ms = (time.time() - start_time) * 1000
        command_name = " ".join(sys.argv) if sys.argv else "mcp-t"

        command_tracker = get_command_tracker()
        command_tracker.record_command(command_name, exit_code, duration_ms)

        # Show suggestions for all commands (not just failures)
        # Skip for help commands and version commands
        if not any(flag in sys.argv for flag in ["--help", "-h", "--version"]):
            ctx = click.get_current_context(silent=True)
            if ctx and hasattr(ctx, "obj") and ctx.obj:
                trigger_post_command_hooks(ctx)
    except Exception:
        # Silent failure - don't break CLI for tracking/suggestion issues
        pass


# Register all commands from modules
mcpt_cli.add_command(create_run_command())
mcpt_cli.add_command(create_generate_command())
mcpt_cli.add_command(create_list_command())
mcpt_cli.add_command(create_show_command())
mcpt_cli.add_command(create_create_group())
mcpt_cli.add_command(create_quickstart_group())
mcpt_cli.add_command(create_report_group())


if __name__ == "__main__":
    mcpt_main()
