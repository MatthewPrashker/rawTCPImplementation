from typing import Dict

HTTP_VERSION = "1.1"
USER_AGENT = "KyleMatthew rawHTTPget/1.0"


class HTTP:
    def __init__(self, netloc: str, path: str):
        self.netloc = netloc
        self.path = path
        self.headers: Dict[str, str] = {}
        self.headers["Host"] = self.netloc
        self.headers["User-Agent"] = USER_AGENT
        self.method = "GET"

    def length(self) -> int:
        return 0

    def construct_packet(self) -> bytes:
        ret = " "
        ret += " "
        ret += self.method
        ret += " "
        ret += self.path
        ret += " "
        ret += "HTTP/" + HTTP_VERSION
        ret += "\r\n"
        for header, value in self.headers.items():
            ret += f"{header}: {value}\r\n"
        ret += "\r\n"
        return ret.encode()
