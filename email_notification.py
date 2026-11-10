#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A module for sending email notifications with attachments.
   Author: Mike Cao <bcao@redhat.com>
   
"""

import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr


class EmailNotifier:
    """
    A class to configure and send emails via an SMTP server.

    Attributes:
        to_list (list): A list of recipient email addresses.
        cc_list (list): A list of CC recipient email addresses.
        mail_host (str): The SMTP server hostname or IP address.
        mail_user (str): The sender's email address.
        sender_name (str): The sender's display name.
    """

    def __init__(self, mail_host="smtp.corp.redhat.com",
                 mail_user="nitthaku@redhat.com", sender_name="Nitesh Thakur"):
        """
        Initialize the EmailNotifier with server and sender details.

        Args:
            mail_host (str): The SMTP server hostname.
            mail_user (str): The sender's email address.
            sender_name (str): The sender's display name.
        """
        self.to_list = ["nitthaku@redhat.com"]
        self.cc_list = []
        self.mail_host = mail_host
        self.mail_user = mail_user
        self.sender_name = sender_name

    def set_recipients(self, to_list):
        """Set the primary recipient list."""
        if not isinstance(to_list, list):
            raise TypeError("Recipients must be provided as a list.")
        self.to_list = to_list

    def set_cc_recipients(self, cc_list):
        """Set the CC recipient list."""
        if not isinstance(cc_list, list):
            raise TypeError("CC recipients must be provided as a list.")
        self.cc_list = cc_list

    def send_email(self, subject, content, attachment_path):
        """
        Compose and send an email with an attachment.

        Args:
            subject (str): The subject line of the email.
            content (str): The HTML body content of the email.
            attachment_path (str): The file path to the attachment.

        Returns:
            bool: True if the email was sent successfully, False otherwise.
        """
        if not self.to_list:
            print("Error: Recipient list is empty.")
            return False

        from_header = formataddr((self.sender_name, self.mail_user))

        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = from_header
        msg['To'] = ", ".join(self.to_list)
        if self.cc_list:
            msg['Cc'] = ", ".join(self.cc_list)

        msg.attach(MIMEText(content, 'html'))

        try:
            with open(attachment_path, 'rb') as f:
                attachment = MIMEApplication(f.read())
                filename = attachment_path.split('/')[-1].split('\\')[-1]
                attachment.add_header(
                    'Content-Disposition', 'attachment', filename=filename
                )
                msg.attach(attachment)
        except FileNotFoundError:
            print(f"Error: Attachment not found at '{attachment_path}'")
            return False
        except IOError as e:
            print(f"Error reading attachment file: {e}")
            return False

        all_recipients = self.to_list + self.cc_list
        try:
            with smtplib.SMTP(self.mail_host, 25) as server:
                # server.set_debuglevel(1)  # Uncomment for verbose debug output
                server.ehlo()
                server.sendmail(from_header, all_recipients, msg.as_string())
            return True
        except smtplib.SMTPException as e:
            print(f"An SMTP error occurred: {e}")
            return False
        except Exception as e:
            print(f"A general error occurred: {e}")
            return False


def test_email_sending():
    """Demonstrate the usage of the EmailNotifier class."""
    try:
        with open("test.txt", "w", encoding="utf-8") as f:
            f.write("This is a test attachment file.")
    except IOError:
        print("Could not create a dummy test file. Aborting test.")
        return

    email_client = EmailNotifier()
    email_client.set_recipients(['nitthaku@redhat.com', 'nitesh.thakur@redhat.com'])

    subject = "Test Subject from Python 3 Script"
    html_content = """
    <html><body>
      <h1>Hello!</h1>
      <p>This is a test email from an optimized Python 3 script.</p>
    </body></html>
    """

    if email_client.send_email(subject, html_content, 'test.txt'):
        print("Email sent successfully!")
    else:
        print("Failed to send email.")


if __name__ == '__main__':
    test_email_sending()
