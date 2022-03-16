#!/usr/bin/env python3

from logger import logger
from socket import gethostbyname
import urllib.parse

from tcpsession import TCPSession

REMOVEME_URL = "http://david.choffnes.com/classes/cs4700sp22/project4.php"


def main():
    logger.info("Starting...")
    parsed_url = urllib.parse.urlparse(REMOVEME_URL)
    dst_ip = gethostbyname(parsed_url.hostname)
    session = TCPSession(dst_ip, 80)
    session.do_handshake()
    session.do_get_request(parsed_url.netloc, parsed_url.path)


if __name__ == "__main__":
    main()
