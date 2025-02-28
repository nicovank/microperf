import argparse
import importlib.metadata
import os
import shutil
import subprocess
import sys
import time

import docker
import prestodb

from . import queries


def _get_perf_executable() -> str:
    perf_executable = os.getenv("MICROPERF_PERF_EXE", shutil.which("perf"))
    if not perf_executable:
        print(
            "[ERROR] Could not find a perf executable. Is perf installed?",
            file=sys.stderr,
        )
        print(
            "[ERROR] Alternatively, set MICROPERF_PERF_EXE to the path of a perf executable.",
            file=sys.stderr,
        )
        sys.exit(1)
    return perf_executable


def perf(args: argparse.Namespace) -> None:
    process = subprocess.Popen([_get_perf_executable(), *args.args])
    try:
        process.communicate()
    except KeyboardInterrupt:
        pass
    sys.exit(process.returncode)


IMAGE_NAME = "nicovank/microperf-perf-presto"
TAGGED_IMAGE_NAME = f"{IMAGE_NAME}:v{importlib.metadata.version('microperf')}"
CONTAINER_NAME = "microperf-perf-presto"
COMMUNICATION_PORT = 13126  # Oswego.


def process(args: argparse.Namespace) -> None:
    client = docker.from_env()

    print("Checking that the container exists...")
    try:
        client.containers.get(CONTAINER_NAME)
    except docker.errors.NotFound:
        print("Container not found. Downloading and starting it...")
        client.images.pull(TAGGED_IMAGE_NAME)
        client.containers.run(
            image=TAGGED_IMAGE_NAME,
            detach=True,
            name=CONTAINER_NAME,
            ports={8080: COMMUNICATION_PORT},
        )

        # TODO: Ideally we would periodically poll and check if ready.
        print("Giving Presto 10 seconds to initialize...")
        time.sleep(10)

    print(f"Processing {args.input}...")
    subprocess.run(
        [
            _get_perf_executable(),
            "script",
            "-s",
            os.path.join(os.path.dirname(__file__), "_perf-script.py"),
            "-F+srcline",
            "--full-source-path",
            "--",
            f"--port={COMMUNICATION_PORT}",
        ]
    )


def clean(args: argparse.Namespace) -> None:
    client = docker.from_env()

    print("Stopping and deleting container...")
    try:
        container = client.containers.get(CONTAINER_NAME)
        container.stop()
        container.remove()
    except docker.errors.NotFound:
        print(f"Container {CONTAINER_NAME} not found.")

    if args.spotless:
        print("Deleting image...")
        try:
            image = client.images.get(IMAGE_NAME)
            image.remove(force=True)
        except docker.errors.NotFound:
            print(f"Image {IMAGE_NAME} not found.")

def patterns(args: argparse.Namespace) -> None:
    connection = prestodb.dbapi.connect(
        host="localhost",
        port=COMMUNICATION_PORT,
        user="perf",
        catalog="memory",
        schema="default",
    )

    cursor = connection.cursor()
    queries.run_queries(cursor, args.table)
