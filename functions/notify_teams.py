# https://medium.com/@sebastian.phelps/aws-cloudwatch-alarms-on-microsoft-teams-9b5239e23b64
import json
import logging
import os
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen

HOOK_URL = os.environ['TEAMS_WEBHOOK_URL']

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def parse_cloudtrail_event(message_json_detail):
  logger.info("message_json_detail: %s", json.dumps(message_json_detail))

  alarm_name = message_json_detail['eventName']
  
  reason = message_json_detail['errorMessage']

  data = {
    "colour": "d63333",
    "title": "Alert - %s - There is an issue: %s" % (reason.split(":")[6].split(" ")[0], alarm_name),
    "text": json.dumps({
      "Subject": alarm_name,
      "Type": message_json_detail['eventType'],
      "MessageId": message_json_detail['eventID'],
      "Message": reason,
      "Timestamp": message_json_detail['eventTime']
    })
  }
  # return data from the function
  return data



def lambda_handler(event, context):
    logger.info("Event: %s", json.dumps(event))
    message = event['Records'][0]['Sns']['Message']

    message_json = json.loads(message)

    if 'AlarmName' in message_json:
      data = ""
      if is_cloudwatch_alarm(message):
        message_json = json.loads(event['Records'][0]['Sns']['Message'])
        alarm_name = message_json['AlarmName']
        old_state = message_json['OldStateValue']
        new_state = message_json['NewStateValue']
        reason = message_json['NewStateReason']
        logger.info("Message: %s", json.dumps(message_json))

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
          "title": "Alert - There is an issue: %s" % event['Records'][0]['Sns']['Subject'],
          "text": json.dumps({
            "Subject": event['Records'][0]['Sns']['Subject'],
            "Type": event['Records'][0]['Sns']['Type'],
            "MessageId": event['Records'][0]['Sns']['MessageId'],
            "TopicArn": event['Records'][0]['Sns']['TopicArn'],
            "Message": event['Records'][0]['Sns']['Message'],
            "Timestamp": event['Records'][0]['Sns']['Timestamp']
          })
        }
    elif 'detail-type' in message_json and message_json['detail-type'] == 'AWS Service Event via CloudTrail':
      logger.info("Parsing cloudtrail message json !!")
      data = parse_cloudtrail_event(message_json['detail'])
    else:
      logger.info("None of the properties are present!!")

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
