import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

class MailjetSMTP:
    server = None
    address = None
    username = None
    password = None

    @staticmethod
    def updateConfig(config: dict) -> None:
        MailjetSMTP.server = config.get('server')
        MailjetSMTP.address = config.get('address')
        MailjetSMTP.username = config.get('username')
        MailjetSMTP.password = config.get('password')

    def sendAuthKey(self, toEmail: str, key: str, expire: int = 5):
        '''
        Given a user's email, send a key.
        '''
        try:
            msg = MIMEMultipart()
            msg['From'] = self.address
            msg['To'] = toEmail
            msg['Subject'] = "PhaseII Password Reset Request"
            email_body = f"Your password reset key is:\n\n{key}\n\nThis key will expire in {expire} minutes.\n\nDo not share this key with anybody."
            msg.attach(MIMEText(email_body, 'plain'))

            with smtplib.SMTP(self.server, 587) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.address, toEmail, msg.as_string())

            return None
        except Exception as e:
            return str(e)
        
    def passwordChanged(self, toEmail: str):
        '''
        Given a user's email, send a warning.
        '''
        now = datetime.now()
        string_format = now.strftime("%Y-%m-%d %H:%M:%S")

        try:
            msg = MIMEMultipart()
            msg['From'] = self.address
            msg['To'] = toEmail
            msg['Subject'] = "Your PhaseII password has been reset"
            email_body = f"Your password was successfully reset on {string_format}\n\nIf this was not you, please contact a staff member."
            msg.attach(MIMEText(email_body, 'plain'))

            with smtplib.SMTP(self.server, 587) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.address, toEmail, msg.as_string())

            return None
        except Exception as e:
            return str(e)
        
    def oAuthUsed(self, toEmail: str, application_name: str):
        '''
        Given a user's email, send a warning.
        '''
        now = datetime.now()
        string_format = now.strftime("%Y-%m-%d %H:%M:%S")

        try:
            msg = MIMEMultipart()
            msg['From'] = self.address
            msg['To'] = toEmail
            msg['Subject'] = "Your PhaseII account was used for oAuth"
            email_body = f"You successfully signed into {application_name} via oAuth using your PhaseII account on {string_format}.\n\nIf this was not you, please contact a staff member IMMEDIATELY."
            msg.attach(MIMEText(email_body, 'plain'))

            with smtplib.SMTP(self.server, 587) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.address, toEmail, msg.as_string())

            return None
        except Exception as e:
            return str(e)