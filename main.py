import datetime
import json
import pytz
import socket
import ssl

import slackweb
from dotenv import load_dotenv

load_dotenv('./.env')

SLACK_WEBHOOK_TOKEN = os.getenv('SLACK_WEBHOOK_TOKEN')

slack = slackweb.Slack(url=SLACK_WEBHOOK_TOKEN)

STATUS = {
    "FAILED": "failed",
    "WARN": "warning",
    "PASS": "pass",
}

STATUS_COLOR = {
    "FAILED": "#DC3535",
    "WARN": "#F49D1A",
    "PASS": "#2eb886",
}


def ssl_valid_time_remaining(domain):
    try:
        expires = ssl_expiry_datetime(domain)
    except:
        return False

    return expires - datetime.datetime.utcnow()


def ssl_expires_in(domain, buffer_days=14):
    remaining = ssl_valid_time_remaining(domain)

    if not remaining:
        return STATUS['FAILED']
    elif remaining < datetime.timedelta(days=buffer_days):
        return STATUS['WARN']
    else:
        return STATUS['PASS']


def ssl_expiry_datetime(domain):
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
    context = ssl.create_default_context()

    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=domain,
    )

    conn.settimeout(3.0)
    conn.connect((domain, 443))
    ssl_info = conn.getpeercert()
    return datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)


def is_pass(status):
    if status == STATUS['PASS']:
        return True
    else:
        return False


def status_color(status):
    if status == STATUS['PASS']:
        return STATUS_COLOR['PASS']
    elif status == STATUS['WARN']:
        return STATUS_COLOR['WARN']
    else:
        return STATUS_COLOR['FAILED']


def status_detail(status, domain):
    if status == STATUS['PASS']:
        return f'このドメインは {ssl_expiry_datetime(domain)} に有効期限がきます'
    elif status == STATUS['WARN']:
        return f'<!channel> 有効期限が近づいてきています ({ssl_expiry_datetime(domain)})'
    else:
        return '<!channel> 有効期限が切れているか不具合が起きている可能性があります'


def check():
    domains = json.load(open('domains.json', 'r'))

    attachments = []

    for domain in domains:
        status = ssl_expires_in(domain)

        if not is_pass(status):
            attachments.append({
                "title": f'{domain} is {status}',
                "fallback": "Plain-text summary of the attachment.",
                "color": status_color(status),
                "text": status_detail(status, domain),
            })

    if attachments:
        checked_at = datetime.datetime.now(pytz.timezone('Asia/Tokyo')).strftime('%Y/%m/%d')

        message = f'⚠️ SSL証明書の設定を見直してください (checked: {checked_at})'

        slack.notify(text=message, attachments=attachments)


if __name__ == '__main__':
    check()
