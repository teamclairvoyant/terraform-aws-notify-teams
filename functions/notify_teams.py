# https://medium.com/@sebastian.phelps/aws-cloudwatch-alarms-on-microsoft-teams-9b5239e23b64
import json
import logging
import os
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen

HOOK_URL = os.environ['TEAMS_WEBHOOK_URL']

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info("Event: " + str(event))
    message = event['Records'][0]['Sns']['Message']
    data = ""
    if is_cloudwatch_alarm(message):
        message_json = json.loads(event['Records'][0]['Sns']['Message'])
        alarm_name = message_json['AlarmName']
        old_state = message_json['OldStateValue']
        new_state = message_json['NewStateValue']
        reason = message_json['NewStateReason']
        logger.info("Message: " + str(message_json))

        base_data = {
          "colour": "64a837",
          "title": "**%s** is resolved" % alarm_name,
          "text": "**%s** has changed from %s to %s - %s" % (
            alarm_name, old_state, new_state, reason)
        }
        if new_state.lower() == 'alarm':
            base_data = {
              "colour": "d63333",
              "title": "Red Alert - There is an issue %s" % alarm_name,
              "text": "**%s** has changed from %s to %s - %s" % (
                alarm_name, old_state, new_state, reason)
            }

        messages = {
          ('ALARM', 'my-alarm-name'): {
            "colour": "d63333",
            "title": "Red Alert - A bad thing happened.",
            "text": "These are the specific details of the bad thing."
          },
          ('OK', 'my-alarm-name'): {
            "colour": "64a837",
            "title": "The bad thing stopped happening",
            "text": "These are the specific details of how we know the bad "
                    "thing stopped happening "
          }
        }
        data = messages.get((new_state, alarm_name), base_data)
    else:
        data = {
          "colour": "d63333",
          "title": "Alert - There is an issue: %s" % event['Records'][0]['Sns']
          ['Subject'],
          "text": {
            "Subject": event['Records'][0]['Sns']['Subject'],
            "Type": event['Records'][0]['Sns']['Type'],
            "MessageId": event['Records'][0]['Sns']['MessageId'],
            "TopicArn": event['Records'][0]['Sns']['TopicArn'],
            "Message": event['Records'][0]['Sns']['Message'],
            "Timestamp": event['Records'][0]['Sns']['Timestamp']
          }
        }

    message = {
      "@context": "https://schema.org/extensions",
      "@type": "MessageCard",
      "themeColor": data["colour"],
      "title": data["title"],
      "text": data["text"]
    }

    req = Request(HOOK_URL, json.dumps(message).encode('utf-8'))
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted")
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)


def is_cloudwatch_alarm(message):
    try:
        message_json = json.loads(message)
        if message_json['AlarmName']:
            return True
        else:
            return False
    except ValueError as e:
        return False
