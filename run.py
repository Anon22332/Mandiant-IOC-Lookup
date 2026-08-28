import os
import time
import datetime
import logging
from mail import MAIL
from elastic import MANDIANT, SIEM
from bgptools import BGPTOOLS
from blocklist import BLOCKLIST

logging.basicConfig(
    filename=os.path.join(os.path.dirname(__file__), 'app.log'),
        filemode="a",
        encoding="utf8",
        format='%(asctime)s - %(name)s - %(levelname)s - "%(message)s"',
)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

    

def main():
    mandiant = MANDIANT()
    siem = SIEM()
    bgptools = BGPTOOLS()
    blocklist = BLOCKLIST()

    mandiant_data = mandiant.get_mandiant_ioc_information()
    IOC_COUNTER = 0
    MAIL_BODY = ''
    MAIL_BODY += f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br><br>'
    MAIL_BODY += "The following ip adresses has made succesful connections to our datacenter:<br><br>"
    for data in mandiant_data:
        if data['ThreatConfidence']['buckets'][0]['key'] > 90:
            logger.info('Checking ip: %s' % data['key'])
            COUNT = siem.get_network_connection_information(ip=data['key'])
            if COUNT:
                if COUNT > 0:
                    bgptools_data = bgptools.get_bgptools_data(ip=data['key'])
                    last_seen = siem.get_last_seen(ip=data['key'])
    
                    if blocklist.check_block_status(ip=data['key']):
                        logger.info("IP: %s already on blocklist")
                        continue
                    logger.info('IP: %s - Score: %s - Country: %s - Last Seen: %s' % (data['key'], data['ThreatConfidence']['buckets'][0]['key'], bgptools_data[2], last_seen))

                    # Get the actors from Mandiant, if any
                    ACTORS = []
                    if data['Actors']['buckets']:
                        for a in data['Actors']['buckets']:
                            ACTORS.append(a['key'])

                    MAIL_BODY += f"# Mandiant Score: {data['ThreatConfidence']['buckets'][0]['key']} - Last seen: {last_seen} - Actors: {ACTORS} - Owner: {bgptools_data[0]} - Country: {bgptools_data[2]} - Successful connections: {COUNT}<br>"
                    MAIL_BODY += f"{data['key']}<br>"
                    IOC_COUNTER += 1
        
        # for the sake of exhaustion in bgp tools website.
        time.sleep(1.5)
    if IOC_COUNTER > 0:
        MAIL().send(send_to='SOC@your-mail.com', body=MAIL_BODY, subject='Mandiant IOC Checker')
        MAIL().send(send_to='your-name@your-mail.com', body=MAIL_BODY, subject='Mandiant IOC Checker')

if __name__ == '__main__':
    main()

