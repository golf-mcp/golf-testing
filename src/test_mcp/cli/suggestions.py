"""Command suggestion system with fuzzy matching for MCP Testing CLI"""

import difflib

from ..shared.console_shared import get_console


def find_closest_matches(
    target: str, options: list[str], max_suggestions: int = 3, cutoff: float = 0.6
) -> list[str]:
    """Find closest matches using fuzzy string matching"""
    # Get close matches using difflib
    matches = difflib.get_close_matches(
        target, options, n=max_suggestions, cutoff=cutoff
    )

    # If no close matches, try substring matching
    if not matches:
        substring_matches = [
            opt
            for opt in options
            if target.lower() in opt.lower() or opt.lower() in target.lower()
        ]
        matches = substring_matches[:max_suggestions]

    # If still no matches, try very loose matching
    if not matches and cutoff > 0.3:
        matches = difflib.get_close_matches(
            target, options, n=max_suggestions, cutoff=0.3
        )

    return matches


def suggest_command_corrections(
    invalid_command: str, available_commands: list[str]
) -> str | None:
    """Suggest corrections for invalid commands"""
    suggestions = find_closest_matches(
        invalid_command, available_commands, max_suggestions=3, cutoff=0.5
    )

    if suggestions:
        console = get_console()
        suggestion_list = [
            f"Did you mean: mcp-t {suggestion}" for suggestion in suggestions
        ]
        console.print_error(f"Unknown command: '{invalid_command}'", suggestion_list)
        return suggestions[0]  # Return best suggestion

    return None


def suggest_config_corrections(
    invalid_id: str, config_type: str, available_configs: dict[str, dict]
) -> bool:
    """Suggest corrections for invalid configuration IDs"""
    available_ids = list(available_configs.keys())
    suggestions = find_closest_matches(invalid_id, available_ids, max_suggestions=3)

    console = get_console()

    if suggestions:
        suggestion_list = []
        for suggestion in suggestions:
            config_info = available_configs[suggestion]
            description = ""
            if config_type == "server":
                description = f" ({config_info.get('url', 'unknown URL')})"
            elif config_type == "suite":
                description = f" ({config_info.get('test_count', 0)} tests)"
            suggestion_list.append(f"Did you mean: {suggestion}{description}")

        suggestion_list.extend(
            [
                f"Use 'mcp-t list {config_type}s' to see all options",
                f"Use 'mcp-t create {config_type}' to create new configurations",
            ]
        )

        console.print_error(
            f"{config_type.title()} '{invalid_id}' not found", suggestion_list
        )
    else:
        console.print_error(f"{config_type.title()} '{invalid_id}' not found")
        console.print(f"[dim]Available {config_type}s:[/dim]")
        for config_id in available_ids[:5]:  # Show first 5
            console.print(f"  • [dim]{config_id}[/dim]")
        if len(available_ids) > 5:
            console.print(f"  ... and {len(available_ids) - 5} more")
        console.print_info(f"Use 'mcp-t list {config_type}s' to see all options")
        console.print_info(f"Use 'mcp-t create {config_type}' to create new configurations")

    return len(suggestions) > 0


def enhanced_error_handler(ctx, param, value, config_type: str):
    """Enhanced Click callback for configuration validation with suggestions"""
    from ..config.config_manager import ConfigManager

    config_manager = ConfigManager()

    try:
        if config_type == "server":
            config_manager.get_server_by_id(value)
            return value
        elif config_type == "suite":
            config_manager.get_suite_by_id(value)
            return value
    except (KeyError, ValueError) as e:
        console = get_console()

        # If this is a detailed ValueError with our custom message, show it directly
        if isinstance(e, ValueError):
            console.print_error(str(e))
            import sys

            sys.exit(1)

        # For other errors, show suggestions
        if config_type == "server":
            available = config_manager.list_servers()
        else:
            available = config_manager.list_suites()

        # Show suggestions and exit
        suggest_config_corrections(value, config_type, available)
        import sys

        sys.exit(1)

    return value


def validate_server_id(ctx, param, value):
    """Validation callback for server IDs"""
    return enhanced_error_handler(ctx, param, value, "server")


def validate_suite_id(ctx, param, value):
    """Validation callback for suite IDs"""
    return enhanced_error_handler(ctx, param, value, "suite")
