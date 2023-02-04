import smtplib
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from logger import init_logging, logger

init_logging()


def send_mail(mail_srv_add,
              mail_user,
              mail_from,
              mail_to,
              mail_password,
              mail_srv_port="587",
              mail_subject="Notification",
              mail_body="Automated Notification Email",
              mail_srv_typ="tls"):
    try:
        logger.info(f"Email: Check for Server {mail_srv_add}:{mail_srv_port}")
        mail_server = smtplib.SMTP(mail_srv_add, mail_srv_port)
    except Exception as e:
        logger.error(
            f"Email: Server Connection Error, {mail_srv_add}:{mail_srv_port} Unreachable or other error occurred.")
        logger.error(str(e))
        logger.error(f"Email: Skip Sending Email to {mail_to}")
        return False
    else:
        logger.info(f"Email: Server {mail_srv_add}:{mail_srv_port} Found")
    if mail_srv_typ == "tls":
        logger.info(f"Email: TLS/SMTP Email Option Selected")
        try:
            logger.info(
                f"Email: Request TLS/SSL Connection with Server {mail_srv_add}:{mail_srv_port}")
            mail_server.starttls()
        except Exception as e:
            logger.error(
                f"Email: TLS/SSL Connection Error, Server {mail_srv_add} Untrusted Certificate")
            logger.error(f"Email: Skip Sending Email to {mail_to}")
            return False
        else:
            logger.info(
                f"Email: TLS/SSL Connection Established with Mail {mail_srv_add}:{mail_srv_port}")
    elif mail_srv_typ == "cleartext":
        logger.info(f"Email: Clear-Text SMTP  Email Option Selected")
    if mail_password and len(mail_password.strip()):
        try:
            logger.info(
                f"Email: Request Account Login for {mail_user} on Server {mail_srv_add}")
            mail_server.login(mail_user, base64.b64decode(
                mail_password.encode('utf-8')).decode('utf-8'))
        except Exception as e:
            logger.error(
                f"Email: Account Login Failure for {mail_from}, Credentials Error")
            logger.debug(
                f"Password: {base64.b64decode(mail_password.encode('utf-8')).decode('utf-8').strip()}")
            logger.debug(f"Error: {str(e)}")
            logger.error(f"Email: Skip Sending Email to {mail_to}")
            return False
        else:
            logger.info(
                f"Email: Account Login Success for {mail_from} on Server {mail_srv_add}")
    try:
        email = MIMEMultipart('alternative')
        email['Subject'] = mail_subject
        email['From'] = mail_from
        if type(mail_to) is not list:
            email['To'] = mail_to
        else:
            email['To'] = ', '.join(mail_to)
        email.attach(MIMEText(mail_body, "html"))
        email_str = email.as_string()
        mail_server.sendmail(mail_from, mail_to, email_str)
    except Exception as e:
        logger.error(f"Email: Email sending failed with error {str(e)}")
        logger.error(f"Email: Skip Sending Email to {mail_to}")
        return False
    else:
        logger.info(f"Email: Email Sent Successfully")
        mail_server.quit()
        return True


def mail_html_body(data):
    body = f"""
<html>
  <head>
    <meta charset="UTF-8">
    <style>
      body {{
        font-family: 'Trebuchet MS', 'Open Sans', Tahoma, sans-serif;
        background-color: #F8F0E3;
      }}

      h1 {{
        text-align: center;
        font-size: 18px;
      }}

      .notification {{
        background-color: #f5f5f5;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
        margin: 20px;
        font-size: 13px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      }}

      table {{
        border-collapse: separate;
        border: solid black 1px;
        border-radius: 6px;
        margin: 0 auto;
      }}
      th {{
        border: none;
        padding-left: 10px;
        padding-right: 10px;
      }}
      td {{
        padding-left: 10px;
        padding-right: 10px;
        border-top:  solid black 1px;
      }}
    </style>
  </head>

  <body>
    <h1>GP Duplicate session login attempt detected</h1>
    <div class="notification">
      <p>
      A duplicate login attempt has been detected for username {data['username']}
      </p>
      <h4>
      Original (Connected) Session Details
      </h4>
      <table>
        <thead>
          <tr>
            <th>Client Hostname</th>
            <th>Client OS</th>
            <th>Client IP</th>
            <th>Client IP Region/Country</th>
          </tr>
        </thead>
        <tr>
          <td>{data['oldsession']['PaloAlto-Client-Hostname']}</td>
          <td>{data['oldsession']['PaloAlto-Client-OS']}</td>
          <td>{data['oldsession']['PaloAlto-Client-Source-IP']}</td>
          <td>{data['oldsession']['PaloAlto-Client-Region']}</td>
        </tr>
      </table>
            <h4>
      Denied Login Attempt Details
      </h4>
      <table>
        <thead>
          <tr>
            <th>Client Hostname</th>
            <th>Client OS</th>
            <th>Client IP</th>
            <th>Client IP Region/Country</th>
          </tr>
        </thead>
        <tr>
          <td>{data['newsession']['PaloAlto-Client-Hostname']}</td>
          <td>{data['newsession']['PaloAlto-Client-OS']}</td>
          <td>{data['newsession']['PaloAlto-Client-Source-IP']}</td>
          <td>{data['newsession']['PaloAlto-Client-Region']}</td>
        </tr>
      </table>
    </div>
  </body>
</html>"""
    return body
