import requests

class BLOCKLIST():
    def __init__(self):
        self._block_list = requests.get(url='http://10.34.134.218:8080/dart-blacklist-ip.txt')

    def check_block_status(self, ip):
        if ip in self._block_list:
            return True
        return False
