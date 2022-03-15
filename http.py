from typing import Dict

HTTP_VERSION = "1.1"
HTTP_VERSION = "1.1"
USER_AGENT = "KyleMatthew rawHTTPget/1.0"


class HTTP:
    def __init__(self, hostname: str, port: int, path: str):
        self.hostname = hostname
        self.port = port
        self.path = path
        self.headers: Dict[str, str] = {}
        self.headers["Host"] = self.hostname
        self.headers["User-Agent"] = USER_AGENT
        self.method = "GET"

    def length(self) -> int:
        return 0

    def construct_packet(self) -> bytes:
        ret = ""
        ret += self.method
        ret += " "
        ret += self.path
        ret += " "
        ret += "HTTP/" + HTTP_VERSION
        ret += "\n"
        for header, value in self.headers.items():
            ret += f"{header}: {value}"
        ret += "\n\n"
        return ret.encode()
