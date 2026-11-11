"""docs/avaliacao.md precisa refletir a medição de verdade: o bloco gerado é conferido aqui."""

from __future__ import annotations

import pytest

from kallyel.rules import load_builtin_rules
from tests.data import evaluate as ev


@pytest.fixture(scope="module")
def evaluation(tmp_path_factory: pytest.TempPathFactory) -> ev.Evaluation:
    return ev.run_evaluation(tmp_path_factory.mktemp("avaliacao"))


def test_doc_block_is_up_to_date(evaluation: ev.Evaluation) -> None:
    text = ev.DOC_PATH.read_text(encoding="utf-8")
    start, end = text.index(ev.BEGIN), text.index(ev.END) + len(ev.END)
    assert text[start:end].strip() == ev.render_block(evaluation).strip(), (
        "docs/avaliacao.md está desatualizado: rode  python tests/data/evaluate.py --update-docs"
    )


def test_doc_mentions_every_rule_and_has_the_lab_template() -> None:
    text = ev.DOC_PATH.read_text(encoding="utf-8")
    for rule in load_builtin_rules():
        # ao menos a tabela de resultados e o modelo do laboratório (nem toda regra tem sonda)
        assert text.count(f"`{rule.id}`") >= 2, rule.id
    assert "Dados do laboratório (a preencher)" in text
    assert "não provam" in text.lower() or "não prova" in text.lower()


def test_synthetic_results_have_no_false_positives(evaluation: ev.Evaluation) -> None:
    assert evaluation.clean_findings == 0
    assert all(r.unexpected == 0 for r in evaluation.rules)
    assert all(r.detected == r.expected > 0 for r in evaluation.rules)


def test_documented_gaps_are_real_and_controls_are_detected(evaluation: ev.Evaluation) -> None:
    gaps = [p for p in evaluation.probes if not p.expect_detected]
    controls = [p for p in evaluation.probes if p.expect_detected]
    assert gaps and controls
    assert [p.title for p in gaps if p.detected] == [], (
        "uma lacuna documentada passou a ser detectada: atualize o doc"
    )
    assert [p.title for p in controls if not p.detected] == []


def test_every_rule_with_a_known_gap_text_exists() -> None:
    ids = {r.id for r in load_builtin_rules()}
    assert set(ev.KNOWN_GAPS) == ids
