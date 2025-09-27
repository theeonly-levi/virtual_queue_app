from twilio.rest import Client
import os

account_sid = os.getenv('TWILIO_SID')
auth_token = os.getenv('TWILIO_AUTH_TOKEN')
twilio_number = os.getenv('TWILIO_NUMBER')
client = Client(account_sid, auth_token)

def send_sms(to_number, message):
    message = client.messages.create(
        body=message,
        from_=twilio_number,
        to=to_number
    )
    return message.sid
