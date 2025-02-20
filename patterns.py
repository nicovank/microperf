#! /usr/bin/env python3

import argparse
import prestodb
import json

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
            "\n".join(json.loads(row[1])),
            "\n".join(json.loads(row[2])),
        )

    with console.pager():
        console.print(table)


def get_total_samples(cursor, args):
    cursor.execute(
        f"""
        SELECT COUNT(*)
        FROM {args.table}
        """
    )
    return cursor.fetchone()[0]


def main(args):
    connection = prestodb.dbapi.connect(
        host=args.host,
        port=args.port,
        user="perf",
        catalog="memory",
        schema="default",
    )

    cursor = connection.cursor()

    total_samples = get_total_samples(cursor, args)

    # Tree-based containers
    cursor.execute(
        f"""
        WITH TEMPORARY1 AS (
            SELECT
                stack,
                srclines,
                FIND_FIRST_INDEX(
                    stack,
                    x -> x LIKE 'std::_Rb_tree%') AS index
            FROM {args.table}
            WHERE CARDINALITY(stack) > 0
        ), TEMPORARY2 AS (
            SELECT
                SLICE(stack, 1, index) AS stack,
                SLICE(srclines, 1, index) AS srclines
            FROM TEMPORARY1
            WHERE index IS NOT NULL
        )
        SELECT
            COUNT(*) AS weight,
            stack,
            srclines
        FROM TEMPORARY2
        GROUP BY stack, srclines
        ORDER BY weight DESC
        LIMIT 20
        """
    )

    display(cursor.fetchall(), "Cycles in tree-based containers", total_samples)

    # Copies.
    cursor.execute(
        f"""
        WITH TEMPORARY1 AS (
            SELECT
                stack,
                srclines,
                FIND_FIRST_INDEX(
                    stack,
                    x -> x LIKE '%::operator=') AS index
            FROM {args.table}
            WHERE CARDINALITY(stack) > 0
        ), TEMPORARY2 AS (
            SELECT
                SLICE(stack, 1, index) AS stack,
                SLICE(srclines, 1, index) AS srclines
            FROM TEMPORARY1
            WHERE index IS NOT NULL
        ), TEMPORARY3 AS (
            SELECT
                stack,
                srclines,
                FIND_FIRST_INDEX(
                    stack,
                    x -> ELEMENT_AT(SPLIT(x, '::'), -1) = ELEMENT_AT(SPLIT(x, '::'), -2))
                AS index
            FROM {args.table}
            WHERE CARDINALITY(stack) > 0
        ), TEMPORARY4 AS (
            SELECT
                SLICE(stack, 1, index) AS stack,
                SLICE(srclines, 1, index) AS srclines
            FROM TEMPORARY3
            WHERE index IS NOT NULL
        )
        SELECT
            COUNT(*) AS weight,
            stack,
            srclines
        FROM (
            (SELECT * FROM TEMPORARY2) UNION ALL (SELECT * FROM TEMPORARY4)
        )
        GROUP BY stack, srclines
        ORDER BY weight DESC
        LIMIT 20
        """
    )

    display(cursor.fetchall(), "Expensive copies", total_samples)

    cursor.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, default="localhost")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("-t", "--table", required=True, help="Name of the table")

    main(parser.parse_args())
