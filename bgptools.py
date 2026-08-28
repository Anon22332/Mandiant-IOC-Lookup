import requests
import re
from bs4 import BeautifulSoup

class BGPTOOLS():
    def __init__(self):
        self.headers = {"user-agent": "your company - lookup - your-name@your-mail.com"}
        pass

    def get_bgptools_data(self, ip:str):
        try:
            url = f'https://bgp.tools/search?q={ip}'
            response = requests.get(url=url, headers=self.headers)

            bgp_soup = BeautifulSoup(response.text, 'html.parser')
            network_name = bgp_soup.find(attrs={'id':'network-name'})
            network_number = bgp_soup.find(attrs={'id':'network-number'})
            whois = bgp_soup.find(attrs={'id':'whois-page'})

            country = re.findall('(c|C)ountry\:\s+(?P<country>\w+)', whois.get_text())
            
            IP_NET = 'ip_error'
            try:
                IP_NET = network_name.get_text()
            except:
                pass

            OWNER = 'UNKNOWN'
            
            try:
                pattern_network_number = 'AS Name\: (?P<owner>.*)'
                o = re.findall(pattern_network_number, network_number.get_text())
                OWNER = o[0]
                
            except:
                pass

            ASN = 'UNKNOWN'
            try:
                pattern_asn = '(?P<AS>AS\d+)'
                asn = re.findall(pattern_asn, network_number.get_text())
                ASN = asn[0]
            except:
                pass

            COUNTRY = 'UNKNOWN'
            try:
                COUNTRY = country[0][1]
            except:
                pass
        except:
            OWNER = 'UNKNOWN'
            IP_NET = 'UNKNOWN'
            COUNTRY = 'UNKNOWN'
        
        return (OWNER, IP_NET, COUNTRY)