import argparse
import asyncio
import logging
import os
import textwrap
import time
from datetime import datetime
from pathlib import Path

from aiogram import Dispatcher, types, Bot
from dotenv import load_dotenv
from instagrapi import Client
from instagrapi.exceptions import LoginRequired, PleaseWaitFewMinutes
from requests.exceptions import RetryError


class LoginUserException(Exception):
    pass


async def send_notifications(notifications: dict):
    """Send a message to Telegram.

    Args:
        notifications (dict): A dictionary of notifications.
    """
    for sender, notification in notifications.items():
        for content in notification:
            message = f'{sender}: {content}'
            if 'Сергей' in sender and content != 'Stories':
                await bot.send_message(chat_id=telegram_chat_id,
                                       text=textwrap.dedent(message))
            else:
                await bot.send_message(chat_id=private_tg_id,
                                       text=textwrap.dedent(message))


async def manual_check(message: types.Message):
    logger.info('Manual-check started')
    current_timestamp = datetime.now().timestamp() - check_interval
    try:
        notifications = await check_new_notifications(current_timestamp)
    except TimeoutError:
        return await bot.send_message(chat_id=private_tg_id, text='Login troubles')
    else:
        if notifications:
            return await send_notifications(notifications)
        return await bot.send_message(chat_id=private_tg_id, text='No new..')


async def check_new_notifications(last_check_timestamp: float) -> dict:
    """Check for new Insta notifications.

    Args:
        last_check_timestamp (float): The timestamp of the last check.

    Returns:
        list: A list of notifications.
    """
    notifications = {}

    if not check_session():
        while True:
            logger.info('Re-login started')
            if login_user():
                break

    threads = cl.direct_threads(selected_filter='unread')
    if threads:
        for thread in threads:
            notifications[thread.thread_title] = []
            messages = thread.messages
            for message in messages:
                # message_timestamp = message.timestamp.astimezone(current_timezone).timestamp()
                message_timestamp = message.timestamp.timestamp()
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
        logger.info('Auto-check started')
        current_timestamp = datetime.now().timestamp()
        last_check_timestamp = current_timestamp - check_interval
        try:
            notifications = await check_new_notifications(last_check_timestamp)
        except TimeoutError:
            await bot.send_message(chat_id=private_tg_id, text='Login troubles')
        else:
            if notifications:
                await send_notifications(notifications)
        await asyncio.sleep(check_interval)


async def start_bot():
    dp = Dispatcher(bot)
    dp.register_message_handler(manual_check, commands=['manual_check'])
    await dp.start_polling()


def check_session():
    try:
        cl.get_timeline_feed()
    except LoginRequired:
        logger.info('Session is invalid, need to login via username and password')
    except PleaseWaitFewMinutes:
        logger.info('sleeping')
        time.sleep(300)
    except Exception as e:
        logger.info('Couldn\'t check session: %s' % e)
    else:
        return True


def login_user():
    """
    Attempts to login to Instagram using either the provided session information
    or the provided username and password.
    """
    logger.info('start login user')
    global cl
    cl = Client()
    cl.delay_range = [1, 3]

    session = cl.load_settings(Path('session.json'))

    login_via_session = False
    login_via_pw = False

    if session:
        try:
            cl.set_settings(session)
            cl.login(username, password)
            if not check_session():
                old_session = cl.get_settings()

                # use the same device uuids across logins
                cl.set_settings({})
                cl.set_uuids(old_session['uuids'])

                cl.login(username, password,
                         verification_code=cl.totp_generate_code(seed))

            else:
                login_via_session = True

        except RetryError as e:
            logger.info(e)
            return False
        except Exception as e:
            logger.info('Couldn\'t login user using session information: %s' % e)

    if not login_via_session:
        try:
            logger.info('Attempting to login via username and password. username: %s' % username)
            if cl.login(username, password,
                        verification_code=cl.totp_generate_code(seed)):
                if check_session():
                    login_via_pw = True
                    cl.dump_settings(Path('session.json'))
        except Exception as e:
            logger.info('Couldn\'t login user using username and password: %s' % e)

    if not login_via_pw and not login_via_session:
        raise LoginUserException('Couldn\'t login user with either password or session')

    return cl


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, filename='insta_checker_log.log', filemode='w',
                        format='%(asctime)s %(levelname)s %(message)s')
    logger = logging.getLogger()
    parser = argparse.ArgumentParser(description='Start checking insta notifications.')
    parser.add_argument('-v', '--verif_code', type=int, help='Verification code')
    parser.add_argument('--check_interval', type=int, default=3600, help='Interval for checking. 1 hour by default.')
    verif_code = str(parser.parse_args().verif_code)
    check_interval = parser.parse_args().check_interval

    current_timezone = datetime.now().astimezone().tzinfo

    load_dotenv()
    tg_bot_token = os.environ['TELEGRAM_BOT_API_TOKEN']
    private_tg_id = os.environ['PRIVATE_CHAT_ID']
    telegram_chat_id = os.environ['CHAT_ID']
    username, password = os.environ['INST_USER'], os.environ['INST_PASS']  # instagram user
    seed = os.environ['SEED']  # 2FA seed

    # username, password = os.environ['INST_USER_MEA'], os.environ['INST_PASS_MEA']
    # cl.login(username, password)

    # cl = Client()
    # cl.login(username, password,
    #          verification_code=cl.totp_generate_code(seed))
    #
    # if check_session():
    #     cl.dump_settings('session.json')

    cl = login_user()

    if cl:
        cl.delay_range = [1, 3]
        bot = Bot(tg_bot_token)

        loop = asyncio.get_event_loop()
        loop.create_task(start_bot())
        loop.create_task(start_checking())

        try:
            logger.info('starting loop')
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            loop.close()
