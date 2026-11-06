"""Client for the isolated Docker peer-credential lab."""

import socket
import sys


with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.settimeout(5)
    try:
        connection.connect("/run/hostorbit-broker/broker.sock")
    except FileNotFoundError:
        print("NO_SOCKET")
    except PermissionError:
        print("DAC_DENIED")
    else:
        connection.sendall(sys.argv[1].encode("ascii") + b"\n")
        connection.shutdown(socket.SHUT_WR)
        with connection.makefile("rb") as reader:
            print(reader.readline(64).decode("ascii").strip())
