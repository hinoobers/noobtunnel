"""Check authenticated submission and IMAP against the standalone mail ports."""

import imaplib
import smtplib
import ssl
import time
import uuid
from email.message import EmailMessage
from pathlib import Path


host = 'mail.byenoob.com'
address = 'noreply@byenoob.com'
password = Path('/root/mailu-noreply-password').read_text().strip()
subject = 'Mailu setup check ' + uuid.uuid4().hex[:10]

message = EmailMessage()
message['From'] = address
message['To'] = address
message['Subject'] = subject
message.set_content('The standalone mail submission and mailbox path work.')

with smtplib.SMTP_SSL(host, 465, context=ssl.create_default_context(), timeout=15) as smtp:
    smtp.login(address, password)
    smtp.send_message(message)

for attempt in range(12):
    with imaplib.IMAP4_SSL(host, 993, ssl_context=ssl.create_default_context()) as imap:
        imap.login(address, password)
        imap.select('INBOX')
        status, matches = imap.search(None, 'SUBJECT', '"' + subject + '"')
        if status == 'OK' and matches[0]:
            print('Authenticated SMTP submission and IMAP delivery passed')
            break
    time.sleep(2)
else:
    raise RuntimeError('Message did not reach the noreply inbox')
