from typer.testing import CliRunner

from kallyel import __version__
from kallyel.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_parsers_list() -> None:
    result = runner.invoke(app, ["parsers", "list"])
    assert result.exit_code == 0
    assert "nginx" in result.output
    assert "apache" in result.output
