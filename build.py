import argparse
import os
import shutil
import subprocess

ROOT = os.path.dirname(os.path.abspath(__file__))

LINUX_URL = "https://github.com/torvalds/linux.git"
LINUX_TAG = "v6.2"


def main(args):
    if args.clean:
        shutil.rmtree(os.path.join(ROOT, "bin"), ignore_errors=True)
        shutil.rmtree(os.path.join(ROOT, "vendor"), ignore_errors=True)
        return

    LINUX_ROOT = os.path.join(ROOT, "vendor", "linux")
    PERF_ROOT = os.path.join(LINUX_ROOT, "tools", "perf")

    if not os.path.isdir(LINUX_ROOT):
        print("-- Downloading a copy of the Linux kernel for a modern perf version")
        subprocess.run(
            [
                "git",
                "clone",
                f"--branch={LINUX_TAG}",
                "--depth=1",
                LINUX_URL,
                LINUX_ROOT,
            ],
            stdout=(None if args.verbose else subprocess.DEVNULL),
            stderr=(None if args.verbose else subprocess.DEVNULL),
        ).check_returncode()

    if not os.path.isfile(os.path.join(PERF_ROOT, "perf")):
        print("-- Building perf")
        subprocess.run(
            ["make"],
            cwd=PERF_ROOT,
            stdout=(None if args.verbose else subprocess.DEVNULL),
            stderr=(None if args.verbose else subprocess.DEVNULL),
        ).check_returncode()
    else:
        print("-- Using existing perf copy")

    if not os.path.isdir(os.path.join(ROOT, "bin")):
        os.mkdir(os.path.join(ROOT, "bin"))
    shutil.copy(os.path.join(PERF_ROOT, "perf"), os.path.join(ROOT, "bin", "bp-perf"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="python3 build.py", description="Bad Patterns Build Script"
    )

    parser.add_argument("--clean", action="store_true", help="Clean up all files")
    parser.add_argument("-v", "--verbose", action="store_true")

    main(parser.parse_args())
