"""Roda a análise em um processo à parte e imprime tempo e pico de memória como JSON.

Processo separado porque o pico de memória (working set / ru_maxrss) é do processo inteiro:
dentro do pytest ele incluiria o próprio pytest e os dados dos outros testes.

    python tests/perf_child.py ARQUIVO [ARQUIVO...]
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path


def peak_rss_bytes() -> int | None:
    """Pico de memória residente do processo, em bytes (None se a plataforma não informa)."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ProcessMemoryCounters),
            wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(ProcessMemoryCounters)
        ok = psapi.GetProcessMemoryInfo(
            kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
        )
        return int(counters.PeakWorkingSetSize) if ok else None

    import resource

    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(rss) if sys.platform == "darwin" else int(rss) * 1024  # Linux informa em KiB


def main(argv: list[str]) -> int:
    from kallyel.analysis import analyze
    from kallyel.rules import load_builtin_rules

    rules = load_builtin_rules()
    baseline = peak_rss_bytes()  # depois dos imports, antes de ler qualquer log
    start = time.perf_counter()
    result = analyze([Path(a) for a in argv], rules)
    seconds = time.perf_counter() - start
    peak = peak_rss_bytes()
    print(
        json.dumps(
            {
                "lines": result.stats.lines,
                "events_analyzed": result.events_analyzed,
                "unparsed": result.stats.unparsed,
                "seconds": seconds,
                "lines_per_second": result.stats.lines / seconds if seconds else 0.0,
                "baseline_mb": None if baseline is None else baseline / 2**20,
                "peak_mb": None if peak is None else peak / 2**20,
                "findings": sorted([f.rule_id, f.client_ip or ""] for f in result.findings),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
