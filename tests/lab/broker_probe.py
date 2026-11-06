"""Client for the isolated Docker peer-credential lab."""

import socket
import sys


def request(frame, path="/run/hostorbit-broker/broker.sock"):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        try:
            connection.connect(path)
        except FileNotFoundError:
            return "NO_SOCKET"
        except PermissionError:
            return "DAC_DENIED"
        connection.sendall(frame)
        connection.shutdown(socket.SHUT_WR)
        with connection.makefile("rb") as reader:
            return reader.readline(64).decode("ascii").strip()


if __name__ == "__main__":
    print(request(sys.argv[1].encode("ascii") + b"\n"))
