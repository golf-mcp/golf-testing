#!/usr/bin/env python3
"""
Create CLI commands: server, suite, and test-case creation with template selection
"""

from typing import Any

import click
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from ..config.config_manager import ConfigManager, ConfigTemplate
from ..models.conversational import ConversationalTestConfig
from ..shared.console_shared import MCPConsole, get_console
from ..shared.file_utils import ensure_directory, safe_json_dump
from .post_command_hooks import trigger_post_command_hooks


def create_create_group() -> click.Group:
    """Create the create command group"""

    @click.group(name="create")
    def mcpt_create():
        """Create new configurations with template selection

        Create servers, test suites, or individual test cases with
        interactive wizards and template selection.
        """
        pass

    # Add subcommands
    mcpt_create.add_command(create_server_command())
    mcpt_create.add_command(create_suite_command())
    mcpt_create.add_command(create_test_case_command())

    return mcpt_create


def create_server_command() -> click.Command:
    """Create the server subcommand"""

    @click.command(name="server")
    @click.option(
        "--global",
        "use_global",
        is_flag=True,
        help="Save configuration globally instead of locally",
    )
    @click.option("--id", "server_id", help="Server ID (if not provided, will prompt)")
    @click.pass_context
    def mcpt_create_server(ctx, use_global: bool, server_id: str | None):
        """Create server configuration

        Interactive wizard to create a new MCP server configuration
        with authentication and tool settings.

        Usage:
          mcp-t create server [OPTIONS]

        Options:
          --global        Save configuration globally instead of locally
          --id <SERVER-ID>  Server ID (if not provided, will prompt)

        Examples:
          mcp-t create server
          mcp-t create server --id my-production-server
          mcp-t create server --global
        """
        console = get_console()
        config_manager = ConfigManager()

        console.print_header("Server Configuration Creator")

        # Determine storage location
        if use_global:
            console.print("📍 Saving configuration globally (system-wide)\n")
            paths = config_manager.paths.get_system_paths()
            for path in [paths["servers_dir"]]:
                ensure_directory(path)
        else:
            console.print("📍 Saving configuration locally (current project)\n")
            paths = config_manager.paths.get_local_paths()
            for path in [paths["servers_dir"]]:
                ensure_directory(path)

        # Server setup with memorable ID
        if not server_id:
            server_id = Prompt.ask("Server ID (easy to remember)", default="my-server")

        server_name = Prompt.ask("Server name", default="My MCP Server")

        # Transport selection
        console.print("\n[bold]Select transport type:[/bold]")
        console.print("  1. HTTP  - Remote server via URL")
        console.print("  2. stdio - Local server via command (subprocess)\n")

        transport_choice = Prompt.ask("Transport type", choices=["1", "2"], default="1")

        if transport_choice == "1":
            # HTTP transport
            server_url = Prompt.ask("Server URL")

            # Create HTTP server config
            server_config = {
                "name": server_name,
                "transport": "http",
                "url": server_url,
            }

            # Authentication method selection (only for HTTP)
            auth_method = show_authentication_menu(console)

            if auth_method == "oauth":
                server_config["oauth"] = True
                console.print("✅ OAuth 2.1 flow will be used during testing")
                console.print(
                    "💡 The framework will handle authorization automatically"
                )
                console.print(
                    "🌐 Your browser will open for authorization when testing begins"
                )

            elif auth_method == "token":
                auth_token = Prompt.ask("Authorization token or API key", password=True)
                if auth_token:
                    server_config["authorization_token"] = auth_token
                console.print("✅ Bearer token authentication configured")

            else:  # auth_method == "none"
                console.print("✅ No authentication will be used")

        else:
            # stdio transport
            console.print("\n[dim]Examples of stdio commands:[/dim]")
            console.print("  npx -y @modelcontextprotocol/server-time")
            console.print("  npx -y @modelcontextprotocol/server-fetch")
            console.print("  uvx mcp-server-memory\n")

            command = Prompt.ask("Command to run server")

            # Create stdio server config
            server_config = {
                "name": server_name,
                "transport": "stdio",
                "command": command,
            }

            # Optional: Environment variables
            if Confirm.ask("Add environment variables?", default=False):
                console.print(
                    "[dim]Enter environment variables (leave blank to finish)[/dim]"
                )
                env_vars = {}
                while True:
                    key = Prompt.ask(
                        "Variable name (or press Enter to finish)", default=""
                    )
                    if not key:
                        break
                    value = Prompt.ask(f"Value for {key}")
                    env_vars[key] = value
                if env_vars:
                    server_config["env"] = env_vars

            # Optional: Working directory
            if Confirm.ask("Set working directory?", default=False):
                cwd = Prompt.ask("Working directory path", default=".")
                if cwd and cwd != ".":
                    server_config["cwd"] = cwd

        # Configuration confirmation
        console.print("\n[bold]Configuration Summary:[/bold]")
        console.print(f"Server ID: [cyan]{server_id}[/cyan]")
        console.print(f"Server Name: [cyan]{server_name}[/cyan]")

        if transport_choice == "1":
            # HTTP transport summary
            console.print("Transport: [blue]HTTP[/blue]")
            console.print(f"Server URL: [cyan]{server_url}[/cyan]")

            if auth_method == "oauth":
                console.print("Authentication: [green]OAuth 2.1 Flow[/green]")
            elif auth_method == "token":
                console.print("Authentication: [yellow]Bearer Token[/yellow]")
            else:
                console.print("Authentication: [dim]None[/dim]")
        else:
            # stdio transport summary
            console.print("Transport: [blue]stdio[/blue]")
            console.print(f"Command: [cyan]{server_config['command']}[/cyan]")

            if server_config.get("env"):
                console.print(
                    f"Environment: [yellow]{len(server_config['env'])} variables[/yellow]"
                )
            if server_config.get("cwd"):
                console.print(f"Working Directory: [cyan]{server_config['cwd']}[/cyan]")

        if not Confirm.ask("\nSave this configuration?", default=True):
            console.print("[yellow]Configuration cancelled.[/yellow]")
            return

        # Save to appropriate location
        if use_global:
            system_paths = config_manager.paths.get_system_paths()
            server_file = system_paths["servers_dir"] / f"{server_id}.json"
        else:
            local_paths = config_manager.paths.get_local_paths()
            server_file = local_paths["servers_dir"] / f"{server_id}.json"

        safe_json_dump(server_config, server_file, "creating server configuration")

        console.print(f"✅ Server configuration saved: {server_file}")
        console.print(f"✅ Created server config: [cyan]{server_id}[/cyan]")
        console.print(
            f"\n[bold]Test it with:[/bold] [cyan]mcp-t run <SUITE-ID> {server_id}[/cyan]"
        )

        trigger_post_command_hooks(ctx)

    return mcpt_create_server


def create_suite_command() -> click.Command:
    """Create the suite subcommand"""

    @click.command(name="suite")
    @click.option(
        "--global",
        "use_global",
        is_flag=True,
        help="Save configuration globally instead of locally",
    )
    @click.option("--id", "suite_id", help="Suite ID (if not provided, will prompt)")
    @click.pass_context
    def mcpt_create_suite(ctx, use_global: bool, suite_id: str | None):
        """Create test suite with interactive type selection

        Interactive wizard to create test suites with templates for different
        test types: Compliance, Security, or Conversational.

        Usage:
          mcp-t create suite [OPTIONS]

        Options:
          --global        Save configuration globally instead of locally
          --id <SUITE-ID>  Suite ID (if not provided, will prompt)

        Examples:
          mcp-t create suite
          mcp-t create suite --id my-security-tests
          mcp-t create suite --global
        """
        console = get_console()
        config_manager = ConfigManager()

        console.print_header("Test Suite Creator")

        # Determine storage location
        if use_global:
            console.print("📍 Saving configuration globally (system-wide)\n")
            paths = config_manager.paths.get_system_paths()
            for path in [paths["suites_dir"]]:
                ensure_directory(path)
        else:
            console.print("📍 Saving configuration locally (current project)\n")
            paths = config_manager.paths.get_local_paths()
            for path in [paths["suites_dir"]]:
                ensure_directory(path)

        # Always show interactive type selection
        test_type = show_test_type_menu(console)

        # Suite setup with memorable ID
        if not suite_id:
            default_id = f"{test_type}-tests"
            suite_id = Prompt.ask(
                "Test suite ID (easy to remember)", default=default_id
            )

        suite_name = Prompt.ask(
            "Test suite name", default=f"{test_type.title()} Test Suite"
        )

        # Create type-specific suite using new templates
        suite = create_suite_interactive(
            console, config_manager, test_type, suite_id, suite_name
        )

        # Save using type-safe method
        config_manager.save_test_suite(suite, use_global=use_global)

        console.print(f"✅ Created test suite config: [cyan]{suite_id}[/cyan]")
        console.print(f"✅ Suite type: [yellow]{type(suite).__name__}[/yellow]")
        console.print(
            f"\n[bold]Test it with:[/bold] [cyan]mcp-t run {suite_id} <SERVER-ID>[/cyan]"
        )

        trigger_post_command_hooks(ctx)

    return mcpt_create_suite


def _create_typed_suite(test_type: str, use_global: bool, suite_id: str | None):
    """Helper function to create a specific test suite type"""
    console = get_console()
    config_manager = ConfigManager()

    console.print_header(f"{test_type.title()} Test Suite Creator")

    # Determine storage location
    if use_global:
        console.print("📍 Saving configuration globally (system-wide)\n")
    else:
        console.print("📍 Saving configuration locally (current project)\n")

    # Suite setup with memorable ID
    if not suite_id:
        default_id = f"{test_type}-tests"
        suite_id = Prompt.ask("Test suite ID (easy to remember)", default=default_id)

    suite_name = Prompt.ask(
        "Test suite name", default=f"{test_type.title()} Test Suite"
    )

    # Create type-specific suite
    suite = create_suite_interactive(
        console, config_manager, test_type, suite_id, suite_name
    )

    # Save using type-safe method
    config_manager.save_test_suite(suite)

    console.print(f"✅ Created {test_type} test suite: [cyan]{suite_id}[/cyan]")
    console.print(f"✅ Suite type: [yellow]{type(suite).__name__}[/yellow]")
    console.print(
        f"\n[bold]Test it with:[/bold] [cyan]mcp-t run {suite_id} <SERVER-ID>[/cyan]"
    )


def create_test_case_command() -> click.Command:
    """Create the test-case subcommand"""

    @click.command(name="test-case")
    @click.option("--suite-id", required=True, help="Suite ID to add test case to")
    def mcpt_create_test_case(suite_id: str):
        """Add test case to existing suite

        Add a new test case to an existing test suite configuration.

        Usage:
          mcp-t create test-case --suite-id <SUITE-ID>

        Options:
          --suite-id <SUITE-ID>  Suite ID to add test case to (required)

        Examples:
          mcp-t create test-case --suite-id basic-tests
        """
        console = get_console()
        config_manager = ConfigManager()

        console.print_header(f"Add Test Case to Suite: {suite_id}")

        # Load existing suite
        try:
            suite = config_manager.get_suite_by_id(suite_id)
            suite_dict = suite.dict()
        except KeyError:
            console.print_error(
                f"Suite '{suite_id}' not found",
                [
                    "Use 'mcp-t list suites' to see available suites",
                    "Or create a new suite with 'mcp-t create suite'",
                ],
            )
            return

        console.print(
            f"📝 Current suite has {len(suite_dict['test_cases'])} test cases"
        )

        # Interactive test case creation
        console.print("\nNew test case:")
        test_id = Prompt.ask(
            "Test ID", default=f"test_{len(suite_dict['test_cases']) + 1}"
        )
        user_message = Prompt.ask("User message")
        success_criteria = Prompt.ask("Success criteria")
        timeout = IntPrompt.ask("Timeout (seconds)", default=60)

        new_test_case = {
            "test_id": test_id,
            "user_message": user_message,
            "success_criteria": success_criteria,
            "timeout_seconds": timeout,
        }

        # Add metadata if the suite has it
        existing_test = suite_dict["test_cases"][0] if suite_dict["test_cases"] else {}
        if "metadata" in existing_test:
            category = Prompt.ask("Category", default="general")
            priority = Prompt.ask("Priority", default="medium")
            new_test_case["metadata"] = {"category": category, "priority": priority}

        # Add to suite
        suite_dict["test_cases"].append(new_test_case)

        # Find and update the suite file
        paths = config_manager.paths.get_all_paths()
        suite_file = None

        for suites_dir in paths["suites_dirs"]:
            potential_file = suites_dir / f"{suite_id}.json"
            if potential_file.exists():
                suite_file = potential_file
                break

        if not suite_file:
            console.print_error("Could not locate suite file to update")
            return

        # Save updated suite
        safe_json_dump(suite_dict, suite_file, "adding test case to suite")

        console.print(f"✅ Added test case '{test_id}' to suite '{suite_id}'")
        console.print(f"✅ Suite now has {len(suite_dict['test_cases'])} test cases")

    return mcpt_create_test_case


def show_test_type_menu(console: MCPConsole) -> str:
    """Show interactive test type selection menu"""
    console.print("\n[bold]What type of test would you like to create?[/bold]\n")

    # Create table for options
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("Option", style="cyan", no_wrap=True)
    table.add_column("Type", style="green")
    table.add_column("Description", style="dim")

    options = [
        ("1", "compliance", "MCP protocol conformance testing"),
        ("2", "security", "Authentication, validation, rate limiting"),
        ("3", "conversational", "Multi-turn dialogue and workflow testing"),
    ]

    for option, test_type, description in options:
        table.add_row(option, test_type, description)

    console.console.print(table)
    console.print()

    choice = Prompt.ask("Select test type", choices=["1", "2", "3"], default="1")

    type_map = {"1": "compliance", "2": "security", "3": "conversational"}

    selected_type = type_map[choice]
    console.print(f"Selected: [cyan]{selected_type}[/cyan] tests")
    return selected_type


def show_authentication_menu(console: MCPConsole) -> str:
    """Show interactive authentication method selection menu with detailed guidance"""
    console.print("\n[bold]Authentication Configuration[/bold]")
    console.print(
        "[dim]Choose the authentication method your MCP server supports:[/dim]\n"
    )

    console.print(
        "[cyan]1.[/cyan] [green]OAuth 2.1[/green] - Full authorization flow with browser [dim](Production servers)[/dim]"
    )
    console.print(
        "[cyan]2.[/cyan] [yellow]Bearer Token[/yellow] - API key or pre-shared token [dim](Simple auth, testing)[/dim]"
    )
    console.print(
        "[cyan]3.[/cyan] [dim]No Auth[/dim] - Open access, no authentication [dim](Development, public APIs)[/dim]"
    )

    console.print(
        "\n[dim]💡 OAuth 2.1 is the MCP specification standard and recommended for production use.[/dim]"
    )
    console.print()

    choice = Prompt.ask(
        "Select authentication method", choices=["1", "2", "3"], default="1"
    )
    return {"1": "oauth", "2": "token", "3": "none"}[choice]


def get_template_for_type(test_type: str) -> dict[str, Any] | None:
    """Get template configuration for test type"""
    config_manager = ConfigManager()

    # Map test types to ConfigTemplate enums
    template_map = {
        "compliance": ConfigTemplate.SIMPLE_SUITE,  # Reuse simple as base compliance template
        "security": ConfigTemplate.SECURITY_SUITE,
        "conversational": ConfigTemplate.WORKFLOW_SUITE,  # Rename workflow to conversational
    }

    template_enum = template_map.get(test_type)
    if template_enum:
        from typing import cast

        return cast(dict[str, Any], config_manager.templates[template_enum])

    return None


def customize_template_test_cases(
    console: MCPConsole, template_test_cases: list[dict]
) -> list[dict]:
    """Allow user to customize template test cases"""
    console.print("📝 Customizing template test cases...")

    customized_cases: list = []
    for i, test_case in enumerate(template_test_cases):
        console.print(f"\n[bold]Test Case {i + 1}: {test_case['test_id']}[/bold]")
        console.print(f"Message: {test_case['user_message']}")
        console.print(f"Success: {test_case['success_criteria']}")

        if Confirm.ask("Keep this test case?", default=True):
            if Confirm.ask("Modify it?", default=False):
                # Allow editing
                test_case["user_message"] = Prompt.ask(
                    "User message", default=test_case["user_message"]
                )
                test_case["success_criteria"] = Prompt.ask(
                    "Success criteria", default=test_case["success_criteria"]
                )

            customized_cases.append(test_case)

    # Offer to add more test cases
    while Confirm.ask("Add another test case?", default=False):
        additional_case = create_single_test_case_interactively(
            console, len(customized_cases) + 1
        )
        customized_cases.append(additional_case)

    return customized_cases


def create_test_cases_interactively(console) -> list:
    """Create test cases through interactive prompts"""
    test_cases: list = []

    while True:
        case = create_single_test_case_interactively(console, len(test_cases) + 1)
        test_cases.append(case)

        if not Confirm.ask("Add another test case?", default=len(test_cases) == 0):
            break

    return test_cases


def create_single_test_case_interactively(console, case_number: int) -> dict:
    """Create a single test case interactively"""
    console.print(f"\n[bold]Test case {case_number}:[/bold]")
    test_id = Prompt.ask("Test ID", default=f"test_{case_number}")
    user_message = Prompt.ask("User message")
    success_criteria = Prompt.ask("Success criteria")
    timeout = IntPrompt.ask("Timeout (seconds)", default=60)

    test_case = {
        "test_id": test_id,
        "user_message": user_message,
        "success_criteria": success_criteria,
        "timeout_seconds": timeout,
    }

    # Ask for optional metadata
    if Confirm.ask("Add metadata (category, priority)?", default=False):
        category = Prompt.ask("Category", default="general")
        priority = Prompt.ask("Priority", default="medium")
        test_case["metadata"] = {"category": category, "priority": priority}

    return test_case


def preview_template_test_cases(console, template_suite) -> None:
    """Preview the template test cases that will be included"""
    test_cases = template_suite.test_cases
    console.print(
        f"\n[bold]📋 Template Preview: {len(test_cases)} test case{'s' if len(test_cases) != 1 else ''}[/bold]\n"
    )

    for i, test_case in enumerate(test_cases, 1):
        console.print(f"[cyan]{i}. {test_case.test_id}[/cyan]")

        # Handle different test case types
        if hasattr(test_case, "user_message"):
            # ConversationalTestConfig
            console.print(f"   Message: {test_case.user_message}")
            console.print(f"   Success: {test_case.success_criteria}")
            if hasattr(test_case, "max_turns"):
                console.print(f"   Max Turns: {test_case.max_turns}")
        elif hasattr(test_case, "check_categories"):
            # ComplianceTestConfig
            console.print(f"   Categories: {', '.join(test_case.check_categories)}")
            if hasattr(test_case, "protocol_version"):
                console.print(f"   Protocol: {test_case.protocol_version}")
        elif hasattr(test_case, "vulnerability_checks"):
            # SecurityTestConfig
            console.print(f"   Auth Method: {test_case.auth_method}")
            console.print(f"   Checks: {', '.join(test_case.vulnerability_checks)}")

        console.print()


def show_customization_menu(console) -> str:
    """Show customization options menu"""
    console.print("\n[bold]How would you like to proceed with test cases?[/bold]\n")

    table = Table(show_header=True, header_style="bold blue")
    table.add_column("Option", style="cyan", no_wrap=True)
    table.add_column("Description", style="dim")

    options = [
        ("1", "Use template as-is (quick setup)"),
        ("2", "Customize template test cases"),
        ("3", "Add additional test cases"),
        ("4", "Start with empty suite (no templates)"),
    ]

    for option, description in options:
        table.add_row(option, description)

    console.console.print(table)
    console.print()

    choice = Prompt.ask("Select option", choices=["1", "2", "3", "4"], default="1")

    option_map = {
        "1": "use_template",
        "2": "customize_template",
        "3": "add_additional",
        "4": "empty_suite",
    }

    return option_map[choice]


def dict_to_conversational_test_config(test_dict: dict) -> ConversationalTestConfig:
    """Convert dict format test case to ConversationalTestConfig"""
    return ConversationalTestConfig(
        test_id=test_dict["test_id"],
        user_message=test_dict["user_message"],
        success_criteria=test_dict["success_criteria"],
        max_turns=test_dict.get("max_turns", 10),
        context_persistence=test_dict.get("context_persistence", True),
        metadata=test_dict.get("metadata"),
    )


def conversational_test_config_to_dict(test_config: ConversationalTestConfig) -> dict:
    """Convert ConversationalTestConfig to dict format for editing"""
    result = {
        "test_id": test_config.test_id,
        "user_message": test_config.user_message,
        "success_criteria": test_config.success_criteria,
        "timeout_seconds": 60,  # Default timeout for compatibility
    }

    if test_config.metadata:
        result["metadata"] = test_config.metadata

    return result


def customize_conversational_template_test_cases(
    console, template_test_cases: list
) -> list:
    """Allow user to customize conversational template test cases"""
    console.print("📝 Customizing conversational template test cases...")

    # Convert to dict format for compatibility with existing functions
    dict_test_cases = [
        conversational_test_config_to_dict(tc) for tc in template_test_cases
    ]

    # Use existing customization function
    customized_dict_cases = customize_template_test_cases(console, dict_test_cases)

    # Convert back to ConversationalTestConfig objects
    customized_cases = [
        dict_to_conversational_test_config(tc) for tc in customized_dict_cases
    ]

    return customized_cases


def create_conversational_test_cases_interactively(console) -> list:
    """Create conversational test cases through interactive prompts"""
    # Use existing function to get dict format
    dict_test_cases = create_test_cases_interactively(console)

    # Convert to ConversationalTestConfig objects
    conversational_cases = [
        dict_to_conversational_test_config(tc) for tc in dict_test_cases
    ]

    return conversational_cases


def create_suite_interactive(
    console, config_manager, test_type: str, suite_id: str, suite_name: str
):
    """Create suite interactively using type-specific templates with customization options"""

    if test_type == "compliance":
        return create_compliance_suite_interactive(
            console, config_manager, suite_id, suite_name
        )
    elif test_type == "security":
        return create_security_suite_interactive(
            console, config_manager, suite_id, suite_name
        )
    elif test_type == "conversational":
        return create_conversational_suite_interactive(
            console, config_manager, suite_id, suite_name
        )
    else:
        raise ValueError(f"Unknown test type: {test_type}")


def create_compliance_suite_interactive(
    console, config_manager, suite_id: str, suite_name: str
):
    """Interactive creation of compliance test suite"""
    # Start with template
    template = config_manager.create_compliance_template()
    template.suite_id = suite_id
    template.name = suite_name

    # Show template preview
    preview_template_test_cases(console, template)

    # Show customization options
    customization_choice = show_customization_menu(console)

    # Handle different customization choices
    if customization_choice == "use_template":
        console.print("Using template as-is")
    elif customization_choice == "customize_template":
        console.print("Customizing template test cases...")
        # Note: customize_template_test_cases works with dict format, need to adapt for Pydantic models
        console.print(
            "⚠️  Template customization for compliance tests not yet supported"
        )
        console.print("Using template as-is for now")
    elif customization_choice == "add_additional":
        console.print("Adding additional test cases...")
        # Note: create_test_cases_interactively creates dict format, need to adapt
        console.print(
            "⚠️  Additional test case creation for compliance tests not yet supported"
        )
        console.print("Using template as-is for now")
    elif customization_choice == "empty_suite":
        console.print("Starting with empty suite")
        template.test_cases = []

    # Customize compliance-specific settings
    auth_required = Confirm.ask("Require authentication?", default=False)
    strict_mode = Confirm.ask("Enable strict protocol checking?", default=True)

    template.auth_required = auth_required
    template.strict_mode = strict_mode

    console.print(f"✅ Created compliance suite with {len(template.test_cases)} tests")
    return template


def create_security_suite_interactive(
    console, config_manager, suite_id: str, suite_name: str
):
    """Interactive creation of security test suite"""
    template = config_manager.create_security_template()
    template.suite_id = suite_id
    template.name = suite_name

    # Show template preview
    preview_template_test_cases(console, template)

    # Show customization options
    customization_choice = show_customization_menu(console)

    # Handle different customization choices
    if customization_choice == "use_template":
        console.print("Using template as-is")
    elif customization_choice == "customize_template":
        console.print("Customizing template test cases...")
        console.print("⚠️  Template customization for security tests not yet supported")
        console.print("Using template as-is for now")
    elif customization_choice == "add_additional":
        console.print("Adding additional test cases...")
        console.print(
            "⚠️  Additional test case creation for security tests not yet supported"
        )
        console.print("Using template as-is for now")
    elif customization_choice == "empty_suite":
        console.print("Starting with empty suite")
        template.test_cases = []

    # Security-specific customizations
    include_pentest = Confirm.ask("Include penetration testing?", default=False)
    template.include_penetration_tests = include_pentest

    console.print(f"✅ Created security suite with {len(template.test_cases)} tests")
    return template


def create_conversational_suite_interactive(
    console, config_manager, suite_id: str, suite_name: str
):
    """Interactive creation of conversational test suite"""
    template = config_manager.create_conversational_template()
    template.suite_id = suite_id
    template.name = suite_name

    # Show template preview
    preview_template_test_cases(console, template)

    console.print(
        "[dim]💡 Tip: For conversational test cases, use [cyan]mcp-t generate[/cyan] instead to automatically generate test cases.[/dim]\n"
    )

    # Show customization options
    customization_choice = show_customization_menu(console)

    # Handle different customization choices
    if customization_choice == "use_template":
        console.print("Using template as-is")
    elif customization_choice == "customize_template":
        customized_test_cases = customize_conversational_template_test_cases(
            console, template.test_cases
        )
        template.test_cases = customized_test_cases
    elif customization_choice == "add_additional":
        console.print("Adding additional test cases to template...")
        additional_cases = create_conversational_test_cases_interactively(console)
        template.test_cases.extend(additional_cases)
    elif customization_choice == "empty_suite":
        console.print("Starting with empty suite")
        template.test_cases = []
        # Still allow adding test cases to empty suite
        if Confirm.ask("Add test cases to the empty suite?", default=True):
            new_cases = create_conversational_test_cases_interactively(console)
            template.test_cases = new_cases

    # Conversation-specific customizations
    patience_levels = ["low", "medium", "high"]
    patience = Prompt.ask(
        "User patience level", choices=patience_levels, default="medium"
    )
    template.user_patience_level = patience

    console.print(
        f"✅ Created conversational suite with {len(template.test_cases)} tests"
    )
    return template
