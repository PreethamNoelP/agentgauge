"""Ordinary project tooling with destructive calls and no agent tools at
all: nothing here is reachable by a model, so nothing should be reported."""
# expect-verdict: NOT_CRITICAL

import shutil
import subprocess


def clean_build_dir(path):
    shutil.rmtree(path)


def run_tests():
    subprocess.run(["pytest", "-q"], check=True)


def main():
    clean_build_dir("build")
    run_tests()


if __name__ == "__main__":
    main()
