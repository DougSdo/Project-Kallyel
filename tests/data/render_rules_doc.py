"""Gera docs/rules.md a partir dos YAML das regras embutidas.

Os exemplos de log vêm dos cenários de ``generate.py`` (dados sintéticos, já verificados contra
o gabarito). Um teste confere que cada exemplo exibido dispara a regra e que o arquivo está
atualizado.

    python tests/data/render_rules_doc.py                 # imprime
    python tests/data/render_rules_doc.py --update-docs   # reescreve docs/rules.md
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from random import Random

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:  # permite rodar como script
    sys.path.insert(0, str(ROOT))

from kallyel.model import PHASE_LABELS  # noqa: E402
from kallyel.report.markdown import md_code, md_text  # noqa: E402
from kallyel.rules import load_builtin_rules  # noqa: E402
from kallyel.rules.model import PatternRule, RateRule, Rule, SequenceRule  # noqa: E402
from tests.data import generate as gen  # noqa: E402
from tests.data.evaluate import KNOWN_GAPS  # noqa: E402

DOC_PATH = ROOT / "docs" / "rules.md"
TABLE_EXAMPLE_MAX = 110

# regra -> (cenário do gerador, arquivo, trechos que identificam as linhas a mostrar, nota)
Example = tuple[str, str, tuple[str, ...], str]
EXAMPLES: dict[str, Example] = {
    "KALLYEL-WEB-001": ("sqli", "nginx", ("UNION+SELECT+null", "'1'='1"), ""),
    "KALLYEL-WEB-002": ("xss", "nginx", ("<script>", "onerror"), ""),
    "KALLYEL-WEB-003": ("traversal", "nginx", ("../../", "php://"), ""),
    "KALLYEL-WEB-004": ("scanner_sweep", "nginx", ("/.env", "/.git/config"), ""),
    "KALLYEL-WEB-005": ("scanner_sweep", "nginx", ("Nikto",), ""),
    "KALLYEL-WEB-006": ("rce", "nginx", (";id", "jndi"), ""),
    "KALLYEL-WEB-007": ("scanner_sweep", "nginx", (" 404 ",), "(30 ou mais respostas 404 do mesmo IP em 60 s)"),
    "KALLYEL-WEB-008": ("login_spray", "nginx", ("/login",), "(15 ou mais respostas 401/403 do mesmo IP em 60 s)"),
    "KALLYEL-WEB-009": ("sqli", "nginx", (" 500 ",), "(10 ou mais respostas 500 do mesmo IP em 60 s)"),
    "KALLYEL-AUTH-001": ("ssh_bruteforce_success", "auth", ("Failed password",), "(5 ou mais falhas do mesmo IP em 2 min)"),
    "KALLYEL-AUTH-002": ("ssh_bruteforce_success", "auth", ("Failed password", "Accepted password"), "(5 ou mais falhas e depois um sucesso, em 15 min)"),
    "KALLYEL-AUTH-003": ("ssh_bruteforce_success", "auth", ("COMMAND=/bin/bash", "new user:"), ""),
    "KALLYEL-APP-001": ("laravel_leak", "laravel", ("production.ERROR", "DB_PASSWORD"), "(linhas de um registro de várias linhas)"),
}  # fmt: skip

RULE_KIND_LABEL = {
    "pattern": "padrão (regex)",
    "rate": "taxa por IP",
    "sequence": "sequência por IP",
}


def example_lines(rule_id: str) -> tuple[list[str], str]:
    scenario, kind, needles, note = EXAMPLES[rule_id]
    built = gen.SCENARIOS[scenario](gen.START.timestamp(), Random("rules-doc"))
    pool = [text for _, text in getattr(built, kind)]
    lines = [ln for text in pool for ln in text.split("\n")]
    chosen: list[str] = []
    for needle in needles:
        match = next((ln for ln in lines if needle in ln and ln not in chosen), None)
        if match is None:
            raise LookupError(f"{rule_id}: nenhuma linha do cenário {scenario} contém {needle!r}")
        chosen.append(match)
    return chosen, note


def describe_kind(rule: Rule) -> str:
    if isinstance(rule, PatternRule):
        return f"padrão (regex) no campo `{rule.field}`"
    if isinstance(rule, RateRule):
        return f"taxa por IP: {rule.threshold} ou mais eventos em {rule.window_s} s"
    if isinstance(rule, SequenceRule):
        steps = " → ".join(
            f"{s.name}" + (f" (≥{s.min_count})" if s.min_count > 1 else "") for s in rule.steps
        )
        return f"sequência por IP em {rule.window_s} s: {steps}"
    return rule.kind


def attack_link(technique: str) -> str:
    path = technique.replace(".", "/")
    return f"[{technique}](https://attack.mitre.org/techniques/{path}/)"


def cwe_link(cwe: str) -> str:
    return f"[{cwe}](https://cwe.mitre.org/data/definitions/{cwe.removeprefix('CWE-')}.html)"


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def render() -> str:
    rules = load_builtin_rules()
    out: list[str] = []
    add = out.append
    add("# Regras de detecção embutidas")
    add("")
    add("Kallyel: análise de logs para detecção de ataques web")
    add("")
    add("> Este arquivo é **gerado** a partir dos YAML em `src/kallyel/rules/builtin/` por")
    add("> `python tests/data/render_rules_doc.py --update-docs`. Não edite à mão: um teste falha")
    add("> se ele ficar desatualizado. Os exemplos de log são sintéticos.")
    add("")
    add("Cada regra mapeia para MITRE ATT&CK, e quando aplicável CWE e OWASP Top 10. Todas são")
    add("**heurísticas de triagem**: geram falsos positivos e não cobrem todo ataque. As lacunas")
    add("verificadas estão em [avaliacao.md](avaliacao.md), e o formato para escrever as suas está")
    add("em [Formato das regras](#formato-das-regras-yaml).")
    add("")
    add("## Resumo")
    add("")
    add("| Regra | Gravidade | Fase | Técnica ATT&CK | Exemplo de log | Mitigação |")
    add("|---|---|---|---|---|---|")
    for r in rules:
        lines, _ = example_lines(r.id)
        first = lines[0]
        shown = first if len(first) <= TABLE_EXAMPLE_MAX else first[: TABLE_EXAMPLE_MAX - 1] + "…"
        techniques = ", ".join(attack_link(t) for t in r.attack) or "-"
        add(
            f"| [`{r.id}`](#{r.id.lower()}) | {r.severity.label} | {PHASE_LABELS[r.phase]} | "
            f"{techniques} | {_cell(md_code(shown))} | {_cell(md_text(r.mitigation))} |"
        )
    add("")
    add("## Detalhes por regra")
    for r in rules:
        lines, note = example_lines(r.id)
        add("")
        add(f"### {r.id}")
        add("")
        add(f"**{md_text(r.title)}**")
        add("")
        add(f"- **Tipo:** {describe_kind(r)}")
        add(f"- **Fontes:** {', '.join(sorted(r.sources))}")
        add(f"- **Gravidade:** {r.severity.label}; **fase do ataque:** {PHASE_LABELS[r.phase]}")
        add(f"- **MITRE ATT&CK:** {', '.join(attack_link(t) for t in r.attack) or '-'}")
        add(f"- **CWE:** {', '.join(cwe_link(c) for c in r.cwe) or '-'}")
        add(f"- **OWASP Top 10:** {r.owasp or '-'}")
        add(f"- **O que detecta:** {md_text(r.explain)}")
        add(f"- **Falsos positivos prováveis:** {md_text(r.false_positives)}")
        add(f"- **Mitigação:** {md_text(r.mitigation)}")
        gap = KNOWN_GAPS.get(r.id)
        if gap:
            add(
                f"- **Lacunas conhecidas:** {md_text(gap)} (variações testadas em [avaliacao.md](avaliacao.md))"
            )
        add("")
        add("Exemplo (sintético):" + (f" {note}" if note else ""))
        add("")
        add("```text")
        out.extend(lines)
        add("```")
    add("")
    add("## Formato das regras (YAML)")
    add("")
    add("Regras adicionais vão em uma pasta passada com `--rules DIR` (ou `rules_dir` em")
    add("`kallyel.toml`). Valide antes de usar: `kallyel rules validate DIR`. O arquivo é lido")
    add("só com `yaml.safe_load`, e qualquer erro é reportado com o arquivo e o id da regra.")
    add("")
    add("Campos comuns: `id` (`KALLYEL-<CATEGORIA>-<NNN>`), `title`, `severity` (`low`, `medium`,")
    add("`high`, `critical`), `sources` (`nginx`, `apache`, `authlog`, `laravel`), `explain`,")
    add("`false_positives`, `mitigation`; opcionais: `attack`, `cwe`, `owasp`, `phase`")
    add("(`recon`, `attempt`, `success`, `action`), `where`, `type`.")
    add("")
    add(
        "`where` filtra eventos por `action`, `http_method`, `http_status`, `source_type` ou `user`."
    )
    add("")
    add("```yaml")
    add("# type: pattern (padrão; pode ser omitido)")
    add("id: KALLYEL-WEB-001")
    add("title: Possível SQL Injection na requisição")
    add("severity: high")
    add("sources: [nginx, apache]")
    add("attack: [T1190]")
    add("cwe: [CWE-89]")
    add('owasp: "A03:2021"')
    add("match:")
    add("  field: http_path_query      # decodifica %xx (até 2 camadas) por padrão")
    add("  any_regex:")
    add("    - '(?i)union(\\s|\\+|%20)+select'")
    add('explain: "..."')
    add('false_positives: "..."')
    add('mitigation: "..."')
    add("```")
    add("")
    add("```yaml")
    add("# type: rate, por IP")
    add("type: rate")
    add("where: {http_status: [404]}")
    add("rate: {threshold: 30, window: 60s}   # unidades: s, m, h")
    add("```")
    add("")
    add("```yaml")
    add("# type: sequence, por IP, etapas em ordem dentro da janela")
    add("type: sequence")
    add("window: 15m")
    add("steps:")
    add("  - {name: falhas, where: {action: [auth.failure]}, min_count: 5}")
    add("  - {name: sucesso, where: {action: [auth.success]}}")
    add("```")
    add("")
    add("**Limites de segurança** (rejeitados ao carregar): regex com quantificador ilimitado")
    add("dentro de outro (como `(a+)+`, risco de ReDoS), regex maior que 500 caracteres, mais de")
    add(
        "50 padrões por regra, arquivo maior que 256 KB. A checagem de ReDoS é uma heurística: veja"
    )
    add("[threat-model.md](threat-model.md).")
    add("")
    return "\n".join(out)


def update_docs(path: Path = DOC_PATH) -> None:
    path.write_text(render(), encoding="utf-8", newline="\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gera docs/rules.md")
    parser.add_argument("--update-docs", action="store_true")
    args = parser.parse_args(argv)
    if args.update_docs:
        update_docs()
        print(f"atualizado: {DOC_PATH}")
    else:
        sys.stdout.buffer.write(render().encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
