from django.core.mail import EmailMessage


class Utils:
    @staticmethod
    def send_email(data):
        email = EmailMessage(subject=data['email_subject'], body=data['email_body'], to=(data['to_user'],),
                             from_email='noreply@mail.denisy.com')
        email.send()
