import argparse
import hashlib
import os
import sys

import prestodb


# perf script -s perf-script.py -F+srcline --full-source-path --strip_cxx_templates

BATCH_SIZE = 50


def get_random_table_name():
    return "T" + hashlib.sha1(os.urandom(512)).hexdigest()


class CLI:
    def __init__(self, args):
        self.args = args

        if self.args.table is None:
            self.args.table = get_random_table_name()

    def trace_begin(self):
        connection = prestodb.dbapi.connect(
            host=self.args.database_host,
            port=self.args.database_port,
            user="perf",
            catalog="memory",
            schema="default",
        )

        self.cursor = connection.cursor()
        self.cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.args.table} (
                event VARCHAR,
                timestamp BIGINT, -- TODO: Figure out how to get real time timestamps.
                comm VARCHAR,
                stack ARRAY(VARCHAR),
                srclines ARRAY(VARCHAR)
            )
            """
        )
        if self.cursor.fetchone()[0]:
            print(f"New table created: {self.args.table}")
        else:
            print(f"Using existing table: {self.args.table}")

        self.count = 0
        self.batch = []

    def process_event(self, event):
        assert "callchain" in event

        stack = []
        srclines = []
        for frame in reversed(event["callchain"]):
            stack.append(frame.get("sym", {}).get("name", "[unknown]"))
            srcline = "[unknown]"
            if "sym_srcline" in frame:
                # There is a colon in the path, but realpath will end up ignoring it.
                srcline = os.path.realpath(frame["sym_srcline"])
            srclines.append(srcline)

        self.batch.append(
            f"""(
                '{event["ev_name"]}',
                {event.get("sample", {}).get("time", 0)},
                '{event["comm"]}',
                ARRAY{stack},
                ARRAY{srclines}
            )
            """
        )

        self.count += 1

        if self.count % BATCH_SIZE == 0:
            self.__batch()
            print(f"Processed {self.count} rows")

    def trace_end(self):
        if len(self.batch) > 0:
            self.__batch()
        self.cursor.close()
        print(f"Inserted {self.count} rows into {self.args.table}")

    def __batch(self):
        self.cursor.execute(
            f"INSERT INTO {self.args.table} VALUES {','.join(self.batch)}"
        )
        count = self.cursor.fetchone()[0]
        assert count == len(self.batch)
        self.batch.clear()


if __name__ == "__main__":
    if "PERF_EXEC_PATH" not in os.environ:
        print("This must be run with perf script, e.g. perf script -s perf-script.py")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--database-host", metavar="HOST", type=str, default="localhost"
    )
    parser.add_argument("--database-port", metavar="PORT", type=int, default=8080)
    parser.add_argument(
        "-t",
        "--table",
        type=str,
        default=None,
        help="Insert entries into a specific table",
    )

    cli = CLI(parser.parse_args())

    trace_begin = cli.trace_begin
    process_event = cli.process_event
    trace_end = cli.trace_end
