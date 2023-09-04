import argparse
import os
import textwrap
import time
import logging
from datetime import datetime

import telegram
from dotenv import load_dotenv
from instagrapi import Client


def check_new_notifications(cl: Client, last_check_timestamp: float) -> dict:
    """Check for new Insta notifications.

    Args:
        cl (Client): The Instagrapi client.
        last_check_timestamp (float): The timestamp of the last check.

    Returns:
        list: A list of notifications.
    """
    notifications = {}
    threads = cl.direct_threads(selected_filter='unread')
    if threads:
        for thread in threads:
            notifications[thread.thread_title] = []
            messages = thread.messages
            for message in messages:
                message_timestamp = message.timestamp.astimezone(current_timezone).timestamp()
                if message_timestamp >= last_check_timestamp and not message.is_sent_by_viewer:
                    message_type = message.item_type
                    if message_type == 'xma_story_share':
                        notifications[thread.thread_title].append('Stories')
                    elif message_type == 'xma_media_share':
                        notifications[thread.thread_title].append(message.xma_share.preview_url.__str__())
                    else:
                        message_content = message.__getattribute__(message_type)
                        if message_type == 'clip':
                            notifications[thread.thread_title].append(message_content.video_url.__str__())
                        elif message_type == 'text':
                            notifications[thread.thread_title].append(message_content)
            cl.direct_send_seen(int(thread.id))
    return notifications


def send_notifications(bot: telegram.Bot, notifications: dict, telegram_chat_id: str):
    """Send a message to Telegram.

    Args:
        bot (telegram.Bot): The Telegram bot.
        notifications (dict): A dictionary of notifications.
        telegram_chat_id (str): The chat ID to send the message to.
    """
    for sender, notification in notifications.items():
        for content in notification:
            message = f'{sender}: {content}'
            bot.send_message(text=textwrap.dedent(message), chat_id=telegram_chat_id)


def main():
    """Start checking Insta notifications."""
    load_dotenv()
    parser = argparse.ArgumentParser(description='Start checking insta notifications.')
    parser.add_argument('-v', '--verif_code', type=int, help='Verification code')
    parser.add_argument('--check_interval', type=int, default=3600, help='Interval for checking. 1 hour by default.')
    verif_code = str(parser.parse_args().verif_code)
    check_interval = parser.parse_args().check_interval

    cl = Client()
    cl.login(os.environ['INST_USER'], os.environ['INST_PASS'], verification_code=verif_code)

    bot = telegram.Bot(token=os.environ["TELEGRM_BOT_API_TOKEN"])
    telegram_chat_id = os.environ["CHAT_ID"]
    bot.send_message(text='Start checking..', chat_id=telegram_chat_id)
    while True:
        current_timestamp = datetime.now().timestamp()
        last_check_timestamp = current_timestamp - check_interval
        notifications = check_new_notifications(cl, last_check_timestamp)
        if notifications:
            send_notifications(bot, notifications, telegram_chat_id)
        time.sleep(check_interval)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, filename="insta_checker_log.log", filemode="w",
                        format="%(asctime)s %(levelname)s %(message)s")
    current_timezone = datetime.now().astimezone().tzinfo
    main()
