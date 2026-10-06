"""Linha de comando.

    python3 -m endpoint_investigator dataset <diretório> [-v] [-o relatorio.json]
    sudo python3 -m endpoint_investigator live [-v] [-o relatorio.json]
"""

from __future__ import annotations

import argparse
import sys

from . import engine, report
from .collectors import dataset


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="endpoint_investigator",
        description="Coleta → normalização → correlação → evidências → hipóteses → resultado.")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="store_true",
                        help="mostra informativos, linha do tempo e limitações")
    common.add_argument("-o", "--output", help="grava o resultado estruturado em JSON neste arquivo")
    common.add_argument("--no-color", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("dataset", parents=[common], help="analisa um diretório de dataset").add_argument("path")
    live = sub.add_parser("live", parents=[common], help="coleta e analisa o sistema atual (Linux)")
    live.add_argument("--log-hours", type=int, default=24, help="janela do journal (padrão: 24h)")
    args = ap.parse_args(argv)

    try:
        if args.cmd == "dataset":
            snap = dataset.collect(args.path)
        else:
            from .collectors import live as live_collector      # usa /proc, pwd e grp: só Linux
            snap = live_collector.collect(args.log_hours)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 1
    inv = engine.investigate(snap)
    report.print_text(inv, verbose=args.verbose, color=False if args.no_color else None)
    if args.output:
        report.write_json(inv, args.output)
        print(f"JSON gravado em {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
