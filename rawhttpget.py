#!/usr/bin/env python3

import sys
from logger import logger
from socket import gethostbyname
import urllib.parse

from tcpsession import TCPSession


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <url>")
        sys.exit(1)
    url: str = sys.argv[1]
    logger.info("Starting...")
    parsed_url = urllib.parse.urlparse(url)
    dst_ip = gethostbyname(parsed_url.hostname)
    session = TCPSession(dst_ip, 80)
    session.do_handshake()
    res = session.do_get_request(parsed_url.netloc, parsed_url.path)
    splatted = res.split(b"\r\n\r\n")
    headers = splatted[0]
    rest = b"\r\n\r\n".join(splatted[1:])
    filename = "output"
    f = open(filename, "wb")
    f.write(rest)
    f.close()

if __name__ == "__main__":
    main()
