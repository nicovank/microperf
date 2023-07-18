#! /usr/bin/env python3

import argparse
import prestodb

from rich.console import Console
from rich.table import Table

console = Console()


def display(data, title, total_samples):
    table = Table(title=title, row_styles=["", "dim"])
    table.add_column("Rank")
    table.add_column("Samples")
    table.add_column("Percentage")
    table.add_column("Stack")
    table.add_column("Source Line")

    for i, row in enumerate(data):
        table.add_row(
            str(i + 1),
            str(row[0]),
            "{:.2f}".format(100 * row[0] / total_samples),
            "\n".join(row[1]),
            "\n".join(row[2]),
        )

    with console.pager():
        console.print(table)


def get_total_samples(cursor, args):
    cursor.execute(
        f"""
        SELECT COUNT(*)
        FROM {args.table}
        WHERE event = 'cycles'
          AND comm LIKE '{args.comm}'"""
    )
    return cursor.fetchone()[0]


def main(args):
    connection = prestodb.dbapi.connect(
        host=args.database_host,
        port=args.database_port,
        user="perf",
        catalog="memory",
        schema="default",
    )

    cursor = connection.cursor()

    total_samples = get_total_samples(cursor, args)

    # Find copies
    cursor.execute(
        f"""
        SELECT
            COUNT(*) AS weight,
            stack,
            srclines
        FROM {args.table}
        WHERE event = 'cycles'
          AND comm LIKE '{args.comm}'
          AND (
            ANY_MATCH(stack, x -> x LIKE '%::operator=')
            OR ANY_MATCH(
                stack,
                x -> REDUCE(
                    SPLIT(x, '::'),
                    ARRAY[null, null],
                    (s, x) -> ARRAY[s[2], x],
                    s -> s[1] = s[2])
        ))
        GROUP BY stack, srclines
        ORDER BY weight DESC
        LIMIT 10
        """
    )

    display(cursor.fetchall(), "Cycles in constructors/assignments", total_samples)

    # Tree-based containers
    cursor.execute(
        f"""
        SELECT
            COUNT(*) AS weight,
            stack,
            srclines
        FROM {args.table}
        WHERE event = 'cycles'
          AND comm LIKE '{args.comm}'
          AND ANY_MATCH(stack, x -> x LIKE 'std::_Rb_tree%')
        GROUP BY stack, srclines
        ORDER BY weight DESC
        LIMIT 10
        """
    )

    display(cursor.fetchall(), "Cycles in tree-based containers", total_samples)

    cursor.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--database-host", metavar="HOST", type=str, default="localhost"
    )
    parser.add_argument("--database-port", metavar="PORT", type=int, default=8080)
    parser.add_argument("-t", "--table", required=True, help="Name of the table")
    parser.add_argument(
        "--comm",
        default="%",
        help="Filter by command. _ can be used to represent any single character, %% zero, one, or multiple characters",
    )

    main(parser.parse_args())
