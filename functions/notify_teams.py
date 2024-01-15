# https://medium.com/@sebastian.phelps/aws-cloudwatch-alarms-on-microsoft-teams-9b5239e23b64
import json
import logging
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

HOOK_URL = os.environ["TEAMS_WEBHOOK_URL"]

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info("Event: " + str(event))
    message = event["Records"][0]["Sns"]["Message"]

    message_json = json.loads(event["Records"][0]["Sns"]["Message"])
    alarm_description = message_json["AlarmDescription"]
    subject = message_json["Subject"]
    logger.info("Message: " + str(message_json))

    data = {
        "color": "d63333",
        "title": f"{subject}",
        "text": json.dumps(
            {
                "Type": event["Records"][0]["Sns"]["Type"],
                "MessageId": event["Records"][0]["Sns"]["MessageId"],
                "TopicArn": event["Records"][0]["Sns"]["TopicArn"],
                "Message": event["Records"][0]["Sns"]["Message"],
                "Timestamp": event["Records"][0]["Sns"]["Timestamp"],
            }
        ),
    }

    message = {
        "@context": "https://schema.org/extensions",
        "@type": "MessageCard",
        "themeColor": data["colour"],
        "title": data["title"],
        "text": alarm_description + "\n" + data["text"],
    }

    req = Request(HOOK_URL, json.dumps(message).encode("utf-8"))
    # add content-type json header
    req.add_header("Content-Type", "application/json; charset=utf-8")

    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted")
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)
