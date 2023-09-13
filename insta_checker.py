import argparse
import asyncio
import logging
import os
import textwrap
from datetime import datetime

from aiogram import Bot, Dispatcher, types
from dotenv import load_dotenv
from instagrapi import Client
from instagrapi.exceptions import LoginRequired


async def send_notifications(notifications: dict):
    """Send a message to Telegram.

    Args:
        notifications (dict): A dictionary of notifications.
    """
    for sender, notification in notifications.items():
        for content in notification:
            message = f'{sender}: {content}'
            if 'Сергей' in sender:
                await bot.send_message(chat_id=telegram_chat_id,
                                       text=textwrap.dedent(message))
            else:
                await bot.send_message(chat_id=privat_tg_id,
                                       text=textwrap.dedent(message))


async def manual_check(message: types.Message):
    current_timestamp = datetime.now().timestamp() - check_interval
    notifications = await check_new_notifications(current_timestamp)
    if notifications:
        return await send_notifications(notifications)
    return await bot.send_message(chat_id=privat_tg_id, text='No new..')


async def check_new_notifications(last_check_timestamp: float) -> dict:
    """Check for new Insta notifications.

    Args:
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
                # message_timestamp = message.timestamp.astimezone(current_timezone).timestamp()
                message_timestamp = message.timestamp.timestamp()
                print(datetime.fromtimestamp(message_timestamp))
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


async def start_checking():
    while True:
        current_timestamp = datetime.now().timestamp()
        last_check_timestamp = current_timestamp - check_interval
        notifications = await check_new_notifications(last_check_timestamp)
        if notifications:
            await send_notifications(notifications)
        await asyncio.sleep(check_interval)


async def start_bot():
    dp.register_message_handler(manual_check, commands=['manual_check'])
    await dp.start_polling()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, filename="insta_checker_log.log", filemode="w",
                        format="%(asctime)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description='Start checking insta notifications.')
    parser.add_argument('-v', '--verif_code', type=int, help='Verification code')
    parser.add_argument('--check_interval', type=int, default=3600, help='Interval for checking. 1 hour by default.')
    verif_code = str(parser.parse_args().verif_code)
    check_interval = parser.parse_args().check_interval

    current_timezone = datetime.now().astimezone().tzinfo

    load_dotenv()
    privat_tg_id = os.environ['PRIVAT_CHAT_ID']
    telegram_chat_id = os.environ['CHAT_ID']

    cl = Client()

   # try:
      #  cl.load_settings('insta_checker_dump.json')
      #  cl.get_timeline_feed()
   # except (LoginRequired, FileNotFoundError):
      #  logging.warning('failure to login via login_settings.json')
      #  cl = Client()
        # cl.login(os.environ['INST_USER_MEA'], os.environ['INST_PASS_MEA'])
    cl.login(os.environ['INST_USER'], os.environ['INST_PASS'], relogin=True, verification_code=cl.totp_generate_code(os.environ['SEED']))
    # cl.dump_settings('insta_checker_dump.json')

    # cl.set_timezone_offset(3 * 3600)

    bot = Bot(os.environ['TELEGRAM_BOT_API_TOKEN'])
    dp = Dispatcher(bot)

    loop = asyncio.get_event_loop()
    insta_checker_task = loop.create_task(start_checking())
    tg_bot_task = loop.create_task(start_bot())

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()
        # insta_checker_task.cancel()
        # tg_bot_task.cancel()
        # dp.stop_polling()
        # dp.wait_closed()
        # bot.close()
        # loop.close()

    # cl.login(os.environ['INST_USER'], os.environ['INST_PASS'], verification_code='012027')
    # cl.login(os.environ['INST_USER_MEA'], os.environ['INST_PASS_MEA'])
    # cl.login_by_sessionid("61745534520%3ACVGL5mm4Ng4ctZ%3A16%3AAYf765cVrB3VRPiFGYbzbSzztW_ZyB0fi6S8ovGXZg") # Mea
    # cl.dump_settings('dump.json')
