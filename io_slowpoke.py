"""Dummy process that performs continuous synchronous disk I/O to simulate I/O pressure."""
import argparse
import os
import signal
import shutil
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--block-kb", type=int, default=4, help="Write block size in KB")
    args = parser.parse_args()

    pid = os.getpid()
    workdir = tempfile.mkdtemp(prefix=f"io_slowpoke_{pid}_")
    filepath = os.path.join(workdir, "iodata.bin")
    print(f"io_slowpoke started — PID {pid}, writing to {filepath}", flush=True)

    def cleanup(*_):
        shutil.rmtree(workdir, ignore_errors=True)
        sys.exit(0)

    signal.signal(signal.SIGTERM, cleanup)

    block = b"\xAA" * (args.block_kb * 1024)
    max_bytes = 100 * 1024 * 1024  # 100 MB cap before wrapping

    try:
        fd = os.open(filepath, os.O_CREAT | os.O_WRONLY | os.O_TRUNC)
        written = 0
        while True:
            os.write(fd, block)
            os.fsync(fd)
            written += len(block)
            if written >= max_bytes:
                os.lseek(fd, 0, os.SEEK_SET)
                written = 0
            time.sleep(0.01)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
