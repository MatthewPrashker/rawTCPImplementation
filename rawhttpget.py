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
    print(res.decode('utf-8'))


if __name__ == "__main__":
    main()
