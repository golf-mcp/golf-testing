from click.testing import CliRunner

from test_mcp.cli.main import mcpt_cli


class TestCLIIntegration:
    def test_no_update_notifier_flag(self):
        """Test --no-update-notifier flag with help shows overview"""
        runner = CliRunner()
        result = runner.invoke(mcpt_cli, ["--no-update-notifier", "--help"])
        assert result.exit_code == 0
        # With custom help, we show the overview instead of detailed flags
        assert "MCP Testing (mcp-t)" in result.output
        assert "Common commands:" in result.output

    def test_version_check_doesnt_break_commands(self):
        """Test that version checking doesn't break normal commands"""
        runner = CliRunner()
        result = runner.invoke(mcpt_cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
