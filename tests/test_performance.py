"""Desempenho: linhas por segundo e pico de memória, medidos em um processo à parte.

- Por padrão roda uma versão curta (100 mil linhas), que também mostra que a memória não
  cresce com o tamanho da entrada.
- O teste de 1 milhão de linhas (critério de aceite da v0.1) fica fora do ``pytest`` comum:

      pytest -m perf -s

Os limites são folgados de propósito (a máquina de CI pode ser bem mais lenta que a de
desenvolvimento); o que se quer pegar é regressão grosseira, como memória proporcional ao log.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.data import generate as gen

CHILD = Path(__file__).with_name("perf_child.py")
# Na máquina de desenvolvimento (notebook com Windows): ~35 mil linhas/s em rajadas de ~3 s e
# 15 a 19 mil sustentado. A queda vem do processador reduzindo o clock sob carga contínua: um
# benchmark em Python puro, sem código do Kallyel, mostra a mesma queda de ~1,75x.
MIN_LINES_PER_SECOND = 8_000
MAX_MEMORY_GROWTH_MB = 150  # pico menos a memória antes de ler o log
MAX_GROWTH_BETWEEN_SIZES_MB = 40  # 4x mais linhas não pode custar muito mais memória


def run_child(*files: Path) -> dict[str, Any]:
    done = subprocess.run(  # noqa: S603 - executa o nosso próprio script de teste
        [sys.executable, str(CHILD), *map(str, files)],
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    data: dict[str, Any] = json.loads(done.stdout)
    return data


def growth_mb(m: dict[str, Any]) -> float | None:
    if m["peak_mb"] is None or m["baseline_mb"] is None:
        return None  # plataforma sem medição de memória
    return float(m["peak_mb"] - m["baseline_mb"])


@pytest.fixture(scope="module")
def clean_100k(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    d = tmp_path_factory.mktemp("perf100k")
    gen.write_dataset(d, nginx_lines=100_000, seed=21)
    return run_child(d / "access.log")


def test_throughput_100k_lines(clean_100k: dict[str, Any]) -> None:
    m = clean_100k
    print(
        f"\n[perf 100k] {m['lines_per_second']:.0f} linhas/s, {m['seconds']:.1f} s, "
        f"memória +{growth_mb(m)} MB"
    )
    assert m["lines"] == 100_000
    assert m["unparsed"] == 0
    assert m["findings"] == []  # tráfego limpo não pode gerar achado
    assert m["lines_per_second"] >= MIN_LINES_PER_SECOND


def test_memory_does_not_grow_with_input_size(clean_100k: dict[str, Any], tmp_path: Path) -> None:
    gen.write_dataset(tmp_path, nginx_lines=25_000, seed=21)
    small = run_child(tmp_path / "access.log")
    g_small, g_big = growth_mb(small), growth_mb(clean_100k)
    if g_small is None or g_big is None:
        pytest.skip("medição de memória indisponível nesta plataforma")
    print(f"\n[perf memória] 25k linhas +{g_small:.1f} MB; 100k linhas +{g_big:.1f} MB")
    assert g_big < MAX_MEMORY_GROWTH_MB
    assert g_big - g_small < MAX_GROWTH_BETWEEN_SIZES_MB  # 4x mais linhas, quase a mesma memória


@pytest.mark.perf
def test_one_million_lines_bounded_memory_and_exact_detections(tmp_path: Path) -> None:
    manifest = gen.write_dataset(
        tmp_path,
        nginx_lines=1_000_000,
        auth_lines=50_000,
        laravel_lines=10_000,
        scenarios=list(gen.SCENARIOS),
        seed=33,
    )
    files = [tmp_path / name for name in manifest["files"]]
    m = run_child(*files)
    size_mb = sum(f.stat().st_size for f in files) / 2**20
    out = {**m, "input_mb": size_mb}
    out_dir = Path(__file__).parent / "data" / "generated"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "perf-1m.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(
        f"\n[perf 1M] {m['lines']} linhas ({size_mb:.0f} MB) em {m['seconds']:.1f} s = "
        f"{m['lines_per_second']:.0f} linhas/s; pico {m['peak_mb']:.1f} MB "
        f"(antes de ler: {m['baseline_mb']:.1f} MB)"
    )
    assert m["lines"] >= 1_000_000
    assert m["unparsed"] == 0
    # Memória limitada: ler 170+ MB de log não pode custar centenas de MB.
    growth = growth_mb(m)
    if growth is not None:
        assert growth < MAX_MEMORY_GROWTH_MB
    # E o resultado continua exato em escala: só os achados do gabarito, nenhum a mais.
    found = {(rule, ip) for rule, ip in m["findings"]}
    expected = {tuple(e) for e in manifest["expected"]}
    assert found == expected
