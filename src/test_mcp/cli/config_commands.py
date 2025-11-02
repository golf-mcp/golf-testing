#!/usr/bin/env python3
"""
Configuration management CLI commands: list, show, init (with completion setup)
"""

import click
from rich.prompt import Confirm

from ..config.config_manager import ConfigManager
from ..shared.console_shared import get_console
from .completion import complete_config_types, complete_list_filters
from .post_command_hooks import trigger_post_command_hooks


def setup_shell_completion() -> None:
    """Setup shell completion as part of init workflow"""
    from ..shell_integration.setup_completion import (
        setup_completion,
        verify_installation,
    )

    console = get_console()

    if not Confirm.ask("Would you like to set up shell tab completion?", default=True):
        return

    if not verify_installation():
        console.print_warning("mcp-t command not accessible, skipping completion setup")
        return

    try:
        # The setup_completion function handles its own messaging
        setup_completion()
    except Exception as e:
        console.print_error(f"Shell completion setup failed: {e!s}")


def create_list_command() -> click.Command:
    """Create the list command"""

    @click.command(name="list")
    @click.argument("type_filter", required=False, shell_complete=complete_list_filters)
    @click.pass_context
    def mcpt_list_complete(ctx, type_filter: str | None = None):
        """List available configurations by memorable ID

        Usage:
          mcp-t list [TYPE-FILTER]

        Arguments:
          TYPE-FILTER  Optional filter: 'servers' or 'suites' (use tab completion)

        Examples:
          mcp-t list           # List all configurations
          mcp-t list servers   # List only servers
          mcp-t list suites    # List only test suites
        """
        config_manager = ConfigManager()
        console = get_console()

        servers = config_manager.list_servers()
        suites = config_manager.list_suites()

        if not type_filter or type_filter == "servers":
            if servers:
                server_table = console.create_config_table(servers, "Server")
                console.console.print(server_table)

        if not type_filter or type_filter == "suites":
            if suites:
                console.console.print()
                suite_table = console.create_config_table(suites, "Test Suite")
                console.console.print(suite_table)

        if not servers and not suites:
            console.print_warning("No configurations found")
            console.print_info(
                "Use 'mcp-t create server' or 'mcp-t create suite' to create configurations"
            )

        trigger_post_command_hooks(ctx)

    return mcpt_list_complete


def create_show_command() -> click.Command:
    """Create the show command"""

    @click.command(name="show")
    @click.argument(
        "config_type",
        type=click.Choice(["server", "suite"]),
        shell_complete=complete_config_types,
    )
    @click.argument("config_id")
    @click.pass_context
    def mcpt_show_complete(ctx, config_type: str, config_id: str):
        """Show configuration details by type and ID

        Usage:
          mcp-t show <CONFIG-TYPE> <CONFIG-ID>

        Arguments:
          CONFIG-TYPE  Configuration type: 'server' or 'suite' (use tab completion)
          CONFIG-ID    Configuration identifier

        Examples:
          mcp-t show server test-local
          mcp-t show suite basic-tests
        """
        config_manager = ConfigManager()
        console = get_console()

        try:
            if config_type == "server":
                config = config_manager.get_server_by_id(config_id)
                console.print_json(data=config)
            else:
                config = config_manager.get_suite_by_id(config_id)
                console.print_json(data=config)

        except KeyError:
            console.print_error(
                f"Configuration '{config_id}' not found",
                [f"Use 'mcp-t list {config_type}s' to see available options"],
            )

        trigger_post_command_hooks(ctx)

    return mcpt_show_complete
