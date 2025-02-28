import argparse

from . import commands


def main() -> None:
    parser = argparse.ArgumentParser(
        "microperf",
        description=f"A small tool using perf to provide more performance insights.",
    )
    subparsers = parser.add_subparsers(
        required=True, title="subcommands", help="available subcommands"
    )

    perf_subparser = subparsers.add_parser(
        "perf",
        help="passthrough to the perf executable",
        description="Passthrough to the perf executable.",
    )
    perf_subparser.add_argument(
        "args", nargs=argparse.REMAINDER, help="arguments forwarded to perf"
    )
    perf_subparser.set_defaults(func=commands.perf)

    process_subparser = subparsers.add_parser(
        "process",
        help="process a perf.data file into a database table",
        description="Process a perf.data file into a database table.",
    )
    process_subparser.add_argument(
        "--input",
        "-i",
        type=str,
        required=False,
        default="perf.data",
        help="input file name (default: perf.data)",
    )
    process_subparser.add_argument(
        "--output",
        "-o",
        type=str,
        required=False,
        default=None,
        help="output table name (default: random)",
    )
    process_subparser.set_defaults(func=commands.process)

    clean_subparser = subparsers.add_parser(
        "clean",
        help="delete the underlying Docker container",
        description="Delete the underlying Docker container.",
    )
    clean_subparser.add_argument(
        "--spotless",
        action="store_true",
        help="also delete the Docker image",
    )
    clean_subparser.set_defaults(func=commands.clean)

    patterns_subparser = subparsers.add_parser(
        "patterns",
        help="runs bad-pattern-idenfying queries",
        description="Runs bad-pattern-idenfying queries.",
    )
    patterns_subparser.add_argument("table", help="name of the table")
    patterns_subparser.set_defaults(func=commands.patterns)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
