#! /usr/bin/env python3

import argparse

import prestodb


def main(args):
    connection = prestodb.dbapi.connect(
        host=args.host,
        port=args.port,
        user="perf",
        catalog="memory",
        schema="default",
    )

    cursor = connection.cursor()

    cursor.execute(
        f"""
        SELECT COUNT(*)
        FROM {args.table}
        WHERE event = 'cycles'"""
    )
    denominator = cursor.fetchone()[0]

    matchers = []
    for any in args.any:
        matchers.append(f"""ANY_MATCH(stack, x -> {" OR ".join([f"x LIKE '%{a}%'" for a in any])})""")
    for all in args.all:
        matchers.append(f"""ANY_MATCH(stack, x -> x LIKE '%{all}%')""")
    if args.none:
        matchers.append(f"""NONE_MATCH(stack, x -> {" OR ".join([f"x LIKE '%{n}%'" for n in args.none])})""")

    print(f"Total samples: {denominator}")
    if matchers:
        cursor.execute(
            f"""
            SELECT COUNT(*)
            FROM {args.table}
            WHERE event = 'cycles'
            AND {" AND ".join(matchers)}"""
        )

        nominator = cursor.fetchone()[0]
        print(f"Total matched samples: {nominator}")

        print(f"Ratio: {nominator / denominator * 100:.2f}%")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, default="localhost")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("-t", "--table", required=True, help="Name of the table")

    parser.add_argument("--any", nargs="+", default=[], action="append")
    parser.add_argument("--all", nargs="+", default=[])
    parser.add_argument("--none", nargs="+", default=[])

    main(parser.parse_args())
