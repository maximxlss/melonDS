#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# SPDX-FileContributor: melonDS fuzzing harness timing

import argparse
import re
import subprocess
import sys
from pathlib import Path
from statistics import mean

TIMING_RE = re.compile(r"timing:.*cpu_ms=([0-9.]+)")
CYCLES_RE = re.compile(r"cycles=([0-9]+)")


def run_once(cmd: list[str]) -> tuple[float, int | None]:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        msg = ["Command failed:", "  " + " ".join(cmd)]
        if proc.stdout:
            msg.append("stdout:\n" + proc.stdout)
        if proc.stderr:
            msg.append("stderr:\n" + proc.stderr)
        raise RuntimeError("\n".join(msg))

    m = TIMING_RE.search(proc.stdout)
    if not m:
        msg = ["Missing timing output:", "  " + " ".join(cmd)]
        if proc.stdout:
            msg.append("stdout:\n" + proc.stdout)
        if proc.stderr:
            msg.append("stderr:\n" + proc.stderr)
        raise RuntimeError("\n".join(msg))

    cpu_ms = float(m.group(1))
    cycles = None
    m_cycles = CYCLES_RE.search(proc.stdout)
    if m_cycles:
        try:
            cycles = int(m_cycles.group(1))
        except ValueError:
            cycles = None
    return cpu_ms, cycles


def run_n(cmd: list[str], runs: int) -> list[tuple[float, int | None]]:
    return [run_once(cmd) for _ in range(runs)]


def table(rows: list[list[str]]) -> str:
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    lines = []
    for r, row in enumerate(rows):
        line = "  ".join(col.ljust(widths[i]) for i, col in enumerate(row))
        lines.append(line)
        if r == 0:
            lines.append("  ".join("-" * w for w in widths))
    return "\n".join(lines)


def seed_name_from_rom(path: Path) -> str | None:
    if path.suffix != ".nds":
        return None
    name = path.stem
    if not name.startswith("seed_"):
        return None
    return name[len("seed_"):]


def seed_name_from_blob(path: Path) -> str | None:
    if path.suffix != ".bin":
        return None
    name = path.stem
    if not name.startswith("arm9_"):
        return None
    return name[len("arm9_"):]


def main() -> int:
    root_dir = Path(__file__).resolve().parents[2]

    parser = argparse.ArgumentParser(description="Time AFL++ harnesses")
    parser.add_argument("--arm9-harness", required=True)
    parser.add_argument("--seed-rom-dir")
    parser.add_argument("--seed-blob-dir")
    parser.add_argument("--seed-filter")
    parser.add_argument("--prune-stale-blobs", action="store_true")
    parser.add_argument("--time-limit-ms", type=int, default=5)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--no-build-seeds", action="store_true")

    args = parser.parse_args()

    arm9_harness = Path(args.arm9_harness)

    if not arm9_harness.is_file():
        print(f"ARM9 harness not found: {arm9_harness}", file=sys.stderr)
        return 1

    seed_rom_dir = Path(args.seed_rom_dir) if args.seed_rom_dir else None
    seed_blob_dir = Path(args.seed_blob_dir) if args.seed_blob_dir else None

    if (seed_rom_dir is None or seed_blob_dir is None) and not args.no_build_seeds:
        seed_dir = root_dir / "tools" / "blocksds" / "jit_seeds"
        if seed_dir.is_dir():
            print("Building jit seeds (if needed)...", file=sys.stderr)
            subprocess.run(["make", "seeds"], cwd=seed_dir, check=True)

    if seed_rom_dir is None:
        seed_rom_dir = root_dir / "tools" / "blocksds" / "jit_seeds" / "build"
    if seed_blob_dir is None:
        seed_blob_dir = root_dir / "seeds"

    if not seed_rom_dir.is_dir():
        print(f"Seed ROM dir not found: {seed_rom_dir}", file=sys.stderr)
        return 1
    if not seed_blob_dir.is_dir():
        print(f"Seed blob dir not found: {seed_blob_dir}", file=sys.stderr)
        return 1

    if args.time_limit_ms <= 0 or args.time_limit_ms > 60000:
        print("--time-limit-ms must be 1..60000", file=sys.stderr)
        return 1
    if args.runs < 2:
        print("--runs must be >= 2", file=sys.stderr)
        return 1

    roms = {}
    for path in seed_rom_dir.glob("seed_*.nds"):
        seed_name = seed_name_from_rom(path)
        if seed_name:
            roms[seed_name] = path

    blobs = {}
    for path in seed_blob_dir.glob("arm9_*.bin"):
        seed_name = seed_name_from_blob(path)
        if seed_name:
            blobs[seed_name] = path

    rom_only = sorted(set(roms.keys()) - set(blobs.keys()))
    blob_only = sorted(set(blobs.keys()) - set(roms.keys()))
    seed_names = sorted(set(roms.keys()) & set(blobs.keys()))
    if args.seed_filter:
        seed_names = [s for s in seed_names if args.seed_filter in s]

    if rom_only:
        print(f"Warning: no ARM9 blob for seeds: {', '.join(rom_only)}", file=sys.stderr)
    if blob_only:
        if args.prune_stale_blobs:
            for seed in blob_only:
                stale = blobs.get(seed)
                if stale is not None:
                    stale.unlink(missing_ok=True)
            print(f"Pruned stale ARM9 blobs: {', '.join(blob_only)}", file=sys.stderr)
        else:
            print(f"Warning: no ROM for seeds: {', '.join(blob_only)}", file=sys.stderr)

    if not seed_names:
        print("No matching seeds found.", file=sys.stderr)
        return 1

    rows = [[
        "Seed",
        "Runs",
        "Avg ms",
        "Avg cycles",
        "Avg cyc/ms",
        "Min ms",
        "Max ms",
        "Max dev ms",
        "Max dev %",
    ]]

    for seed in seed_names:
        rom = roms.get(seed)
        blob = blobs.get(seed)

        if rom is None:
            print(f"Missing ROM for seed: {seed}", file=sys.stderr)
            return 1
        if blob is None:
            print(f"Missing ARM9 blob for seed: {seed}", file=sys.stderr)
            return 1

        cmd = [
            str(arm9_harness),
            str(rom),
            "--timing",
            str(blob),
            "--time-limit-ms",
            str(args.time_limit_ms),
        ]
        timings = run_n(cmd, args.runs)
        ms_vals = [t[0] for t in timings]
        avg = mean(ms_vals)
        min_t = min(ms_vals)
        max_t = max(ms_vals)
        max_dev = max(abs(t - avg) for t in ms_vals)
        max_dev_pct = (max_dev / avg * 100.0) if avg > 0 else 0.0
        cycles_vals = [t[1] for t in timings if t[1] is not None]
        avg_cycles = mean(cycles_vals) if cycles_vals else None
        cyc_per_ms_vals = []
        for ms, cycles in timings:
            if cycles is not None and ms > 0:
                cyc_per_ms_vals.append(cycles / ms)
        avg_cyc_per_ms = mean(cyc_per_ms_vals) if cyc_per_ms_vals else None

        rows.append([
            seed,
            str(args.runs),
            f"{avg:.3f}",
            f"{avg_cycles:.0f}" if avg_cycles is not None else "-",
            f"{avg_cyc_per_ms:.1f}" if avg_cyc_per_ms is not None else "-",
            f"{min_t:.3f}",
            f"{max_t:.3f}",
            f"{max_dev:.3f}",
            f"{max_dev_pct:.1f}%",
        ])

    print(table(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
