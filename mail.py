# -*- coding: iso-8859-15 -*-
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

class MAIL:
    def __init__(self) -> None:
        pass

    def send(self, send_to=None, subject=None, body=""):
        msg = MIMEMultipart()
        msg['From'] = "siem-alert-noreply@your-mail.com"
        msg['To'] = send_to

        try:
            msg['Subject'] = subject
            t = body
            msg.attach(MIMEText(t, 'html'))
            smtp = smtplib.SMTP(
                "smtp.your-mail.com", timeout=10)
            smtp.sendmail("siem-alert-noreply@your-mail.com",
                          send_to, msg.as_string())
            smtp.close()
            logger.info('Mail send to: %s', send_to)
        except Exception as error:
            logger.error('Failed sending mail. Error: %s', error)
            raise Exception(f'Failed sending mail. Error: {error}')
