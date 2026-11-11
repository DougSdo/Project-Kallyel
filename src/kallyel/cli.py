"""Comandos da CLI do Kallyel."""

from __future__ import annotations

import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer

from kallyel import __version__
from kallyel.rules.model import Rule
from kallyel.sanitize import neutralize

app = typer.Typer(
    name="kallyel",
    help="Kallyel: análise de logs para detecção de ataques web.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def _root() -> None:
    """Kallyel: análise de logs para detecção de ataques web."""


@app.command()
def version() -> None:
    """Mostra a versão instalada."""
    typer.echo(f"kallyel {__version__}")


parsers_app = typer.Typer(help="Parsers de log disponíveis.", no_args_is_help=True)
app.add_typer(parsers_app, name="parsers")


@parsers_app.command("list")
def parsers_list() -> None:
    """Lista os formatos de log que o Kallyel entende."""
    from kallyel.parsers import PARSERS

    for parser in PARSERS:
        typer.echo(f"{parser.name:<10} {', '.join(parser.source_types):<16} {parser.description}")


rules_app = typer.Typer(help="Consulta e validação de regras.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")

RulesDirOption = Annotated[
    Optional[Path],  # noqa: UP045 - typer 0.x precisa de Optional em tempo de execução
    typer.Option("--rules", help="Pasta com regras YAML adicionais."),
]


def _load_all_rules(extra_dir: Path | None) -> list[Rule]:
    from kallyel.rules import RuleError, load_builtin_rules, load_rules_dir
    from kallyel.rules.loader import ensure_unique

    try:
        rules = load_builtin_rules()
        if extra_dir is not None:
            rules = ensure_unique(rules + load_rules_dir(extra_dir))
    except RuleError as exc:
        typer.echo(f"erro: {neutralize(str(exc))}", err=True)
        raise typer.Exit(2) from exc
    return rules


@rules_app.command("list")
def rules_list(rules_dir: RulesDirOption = None) -> None:
    """Lista as regras carregadas."""
    for rule in _load_all_rules(rules_dir):
        typer.echo(
            f"{rule.id:<18} {rule.severity.label:<9} {rule.kind:<9} {neutralize(rule.title)}"
        )


@rules_app.command("show")
def rules_show(rule_id: str, rules_dir: RulesDirOption = None) -> None:
    """Mostra os detalhes de uma regra."""
    for rule in _load_all_rules(rules_dir):
        if rule.id == rule_id.upper():
            lines = [
                f"{rule.id}: {rule.title}",
                f"tipo: {rule.kind}  gravidade: {rule.severity.label}  fontes: {', '.join(sorted(rule.sources))}",
                f"ATT&CK: {', '.join(rule.attack) or '-'}  CWE: {', '.join(rule.cwe) or '-'}  "
                f"OWASP: {rule.owasp or '-'}",
                f"o que detecta: {rule.explain}",
                f"falsos positivos: {rule.false_positives}",
                f"mitigação: {rule.mitigation}",
                f"origem: {rule.origin}",
            ]
            typer.echo(neutralize("\n".join(lines), keep_newlines=True))
            return
    typer.echo(f"erro: regra não encontrada: {neutralize(rule_id)}", err=True)
    raise typer.Exit(2)


@rules_app.command("validate")
def rules_validate(directory: Path) -> None:
    """Valida todos os YAML de uma pasta, sem executar nada."""
    from kallyel.rules import RuleError, load_rule_file
    from kallyel.rules.loader import ensure_unique

    if not directory.is_dir():
        typer.echo(f"erro: pasta não encontrada: {directory}", err=True)
        raise typer.Exit(2)
    files = sorted(p for p in directory.iterdir() if p.suffix in {".yaml", ".yml"} and p.is_file())
    if not files:
        typer.echo(f"erro: nenhum arquivo .yaml em {directory}", err=True)
        raise typer.Exit(2)
    loaded: list[Rule] = []
    failures = 0
    for file in files:
        try:
            loaded.extend(load_rule_file(file))
        except RuleError as exc:
            failures += 1
            typer.echo(f"INVÁLIDO {neutralize(str(exc))}", err=True)
    if not failures:
        try:
            ensure_unique(loaded)
        except RuleError as exc:
            failures += 1
            typer.echo(f"INVÁLIDO {neutralize(str(exc))}", err=True)
    if failures:
        raise typer.Exit(2)
    typer.echo(f"ok: {len(loaded)} regra(s) válida(s) em {len(files)} arquivo(s)")


ConfigOption = Annotated[
    Optional[Path],  # noqa: UP045
    typer.Option("--config", help="Arquivo kallyel.toml (padrão: pasta de dados do usuário)."),
]
LogOffsetOption = Annotated[
    Optional[str],  # noqa: UP045
    typer.Option(
        "--log-utc-offset",
        help="Fuso dos logs sem fuso (auth.log tradicional, Laravel), ex.: -03:00. Padrão: UTC.",
    ),
]
SinceOption = Annotated[
    Optional[str],  # noqa: UP045
    typer.Option("--since", help="Ignora eventos antes desta data (ISO 8601, UTC se sem fuso)."),
]
UntilOption = Annotated[
    Optional[str],  # noqa: UP045
    typer.Option("--until", help="Ignora eventos depois desta data (ISO 8601, UTC se sem fuso)."),
]


def _die(message: str) -> typer.Exit:
    typer.echo(f"erro: {neutralize(message)}", err=True)
    return typer.Exit(2)


def _split_inputs(paths: list[Path]) -> tuple[list[Path], bool]:
    """Separa o argumento '-' (stdin) dos caminhos reais."""
    real = [p for p in paths if str(p) != "-"]
    return real, len(real) != len(paths)


class OutputFormat(str, Enum):
    table = "table"
    json = "json"
    jsonl = "jsonl"
    html = "html"
    md = "md"


class FailOn(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


@app.command()
def analyze(
    paths: Annotated[list[Path], typer.Argument(help="Arquivos, pastas ou '-' para stdin.")],
    fmt: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Formato da saída.")
    ] = OutputFormat.table,
    out: Annotated[
        Optional[Path],  # noqa: UP045
        typer.Option("--out", "-o", help="Grava a saída neste arquivo em vez de imprimir."),
    ] = None,
    fail_on: Annotated[
        FailOn,
        typer.Option(help="Gravidade mínima que faz o comando sair com código 1."),
    ] = FailOn.low,
    since: SinceOption = None,
    until: UntilOption = None,
    rules_dir: RulesDirOption = None,
    no_redact: Annotated[
        bool, typer.Option("--no-redact", help="Desliga o mascaramento de dados pessoais.")
    ] = False,
    show_unparsed: Annotated[
        bool, typer.Option("--show-unparsed", help="Mostra amostras de linhas não reconhecidas.")
    ] = False,
    include_private: Annotated[
        bool, typer.Option("--include-private", help="Analisa também IPs de redes privadas.")
    ] = False,
    log_utc_offset: LogOffsetOption = None,
    config_path: ConfigOption = None,
) -> None:
    """Analisa logs e produz o relatório de achados.

    Saída: 0 sem achados na gravidade de --fail-on ou acima; 1 com achados; 2 erro de uso ou entrada.
    """
    from kallyel.analysis import AnalysisOptions
    from kallyel.analysis import analyze as run_analysis
    from kallyel.config import ConfigError, load_config
    from kallyel.ingest import InputError, iter_input_files
    from kallyel.model import Severity
    from kallyel.netutil import InvalidNetworkError, parse_networks
    from kallyel.redact import Redactor
    from kallyel.report import (
        build_report,
        make_console,
        render_html,
        render_json,
        render_jsonl,
        render_markdown,
        render_table,
    )
    from kallyel.timeutil import TimeParseError, parse_user_time, parse_utc_offset

    try:
        config = load_config(config_path)
        rules = _load_all_rules(rules_dir or config.rules_dir)
        options = AnalysisOptions(
            ignore_private=config.ignore_private and not include_private,
            ignore_networks=parse_networks(config.ignore_networks),
            log_utc_offset=parse_utc_offset(log_utc_offset or config.log_utc_offset or "UTC"),
            since=parse_user_time(since) if since else None,
            until=parse_user_time(until) if until else None,
        )
    except (ConfigError, InvalidNetworkError, TimeParseError) as exc:
        raise _die(str(exc)) from exc

    real_paths, use_stdin = _split_inputs(paths)
    try:
        input_files = {p.resolve() for p in iter_input_files(real_paths)}
    except InputError as exc:
        raise _die(str(exc)) from exc
    if out is not None and out.resolve() in input_files:
        raise _die(f"--out aponta para um dos arquivos de entrada ({out}); escolha outro destino")

    try:
        result = run_analysis(real_paths, rules, options, use_stdin=use_stdin)
    except InputError as exc:
        raise _die(str(exc)) from exc

    report = build_report(
        result, redact=Redactor(enabled=not no_redact), show_unparsed=show_unparsed
    )
    try:
        if fmt is OutputFormat.table:
            if out is None:
                render_table(make_console(), report)
            else:
                with out.open("w", encoding="utf-8", newline="\n") as fh:
                    render_table(make_console(file=fh), report)
        else:
            renderers = {
                OutputFormat.json: render_json,
                OutputFormat.jsonl: render_jsonl,
                OutputFormat.html: render_html,
                OutputFormat.md: render_markdown,
            }
            text = renderers[fmt](report)
            if out is None:
                typer.echo(text, nl=False)
            else:
                out.write_text(text, encoding="utf-8", newline="\n")
    except OSError as exc:
        if out is None:  # falha ao escrever na saída padrão (ex.: pipe fechado): não é erro nosso
            raise
        raise _die(f"não foi possível gravar {neutralize(str(out))}: {exc}") from exc
    if out is not None:
        typer.echo(f"Relatório gravado em {neutralize(str(out))}", err=True)

    threshold = Severity.parse(fail_on.value)
    hits = sum(1 for f in result.findings if f.severity >= threshold)
    if hits:
        typer.echo(
            f"{hits} achado(s) com gravidade {threshold.label} ou acima (código de saída 1)",
            err=True,
        )
        raise typer.Exit(1)


@app.command()
def timeline(
    paths: Annotated[list[Path], typer.Argument(help="Arquivos, pastas ou '-' para stdin.")],
    ip: Annotated[str, typer.Option("--ip", help="Endereço IP a investigar.")],
    rules_dir: RulesDirOption = None,
    since: SinceOption = None,
    until: UntilOption = None,
    no_redact: Annotated[
        bool, typer.Option("--no-redact", help="Desliga o mascaramento de dados pessoais.")
    ] = False,
    log_utc_offset: LogOffsetOption = None,
    config_path: ConfigOption = None,
) -> None:
    """Mostra a linha do tempo de um IP: fases, regras acionadas e pontuação de risco."""
    from kallyel.analysis import AnalysisOptions, analyze
    from kallyel.config import ConfigError, load_config
    from kallyel.correlate import build_ip_report, build_timeline
    from kallyel.ingest import InputError
    from kallyel.netutil import InvalidNetworkError, parse_ip, parse_networks
    from kallyel.redact import Redactor
    from kallyel.report import make_console, render_timeline
    from kallyel.timeutil import TimeParseError, parse_user_time, parse_utc_offset

    if parse_ip(ip) is None:
        raise _die(f"IP inválido: {ip!r}")
    try:
        config = load_config(config_path)
        rules = _load_all_rules(rules_dir or config.rules_dir)
        options = AnalysisOptions(
            ignore_private=config.ignore_private,
            ignore_networks=parse_networks(config.ignore_networks),
            log_utc_offset=parse_utc_offset(log_utc_offset or config.log_utc_offset or "UTC"),
            since=parse_user_time(since) if since else None,
            until=parse_user_time(until) if until else None,
            focus_ip=ip,
        )
    except (ConfigError, InvalidNetworkError, TimeParseError) as exc:
        raise _die(str(exc)) from exc

    real_paths, use_stdin = _split_inputs(paths)
    try:
        result = analyze(real_paths, rules, options, use_stdin=use_stdin)
    except InputError as exc:
        raise _die(str(exc)) from exc

    ip_findings = [f for f in result.findings if f.client_ip == ip]
    report = build_ip_report(ip, ip_findings) if ip_findings else None
    tl = build_timeline(ip, result.focus_events, ip_findings, {r.id: r for r in rules})
    render_timeline(
        make_console(), tl, report, Redactor(enabled=not no_redact), warnings=result.warnings
    )


def main() -> None:
    # Força UTF-8 na saída: sem isso, redirecionar para arquivo/pipe no Windows (cp1252)
    # quebra ao imprimir acentos e setas.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")
    app()
