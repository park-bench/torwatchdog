#!/usr/bin/python3

# Copyright 2015-2026 Joel Allen Luellwitz and Emily Frost
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Verifies a website is running over Tor and sends an encrypted e-mail notification when
the site's availability changes. Uses urllib to fetch the site using Socks for Tor over
the SOCKS_PORT.
"""

# TODO: Eventually consider running in a chroot or jail. (gpgmailer issue 17)
# TODO: Eventually check to see if the network/internet connection is down. (issue 4)

__author__ = 'Joel Luellwitz and Emily Frost'
__version__ = '0.9'

from collections import deque
import datetime
from itertools import islice
import logging
import os
import pwd
import random
import sdnotify
import signal
import socket
import stat
import time
import traceback
import urllib.request

import configparser
import socks
from parkbenchcommon import confighelper
import gpgmailmessage

# Constants
PROGRAM_NAME = 'torwatchdog'
CONFIGURATION_PATHNAME = f'/etc/{PROGRAM_NAME}/{PROGRAM_NAME}.conf'
PROCESS_USERNAME = PROGRAM_NAME


class InitializationException(Exception):
    """Indicates an expected fatal error occurred during program initialization.
    Initialization is implied to mean, before daemonization.
    """


class ShutdownException(BaseException):
    """Raised when SIGTERM is received."""


def read_configuration():
    """Reads and validates the configuration file. Supported configuration options are
    returned as a dictonary.

    Return (dict): The read system configuration.
    """
    logger = logging.getLogger(__name__)

    logger.info(f'Reading {CONFIGURATION_PATHNAME}...')
    config_parser = configparser.ConfigParser()
    config_parser.read(CONFIGURATION_PATHNAME)

    config = {}
    config_helper = confighelper.ConfigHelper()
    config['log_level'] = config_helper.verify_log_level(config_parser)

    logger.info('Verifying non-logging configuration.')

    config['url'] = config_helper.verify_string_exists(config_parser, 'url')
    config['tor_socks_port'] = config_helper.verify_integer_within_range(
        config_parser, 'tor_socks_port', lower_bound=1, upper_bound=65536)
    config['max_poll_delay'] = config_helper.verify_number_within_range(
        config_parser, 'max_poll_delay', lower_bound=0.000001, upper_bound=900.000001)
    config['min_failed_polls'] = config_helper.verify_integer_within_range(
        config_parser, 'min_failed_polls', lower_bound=1)
    config['email_subject'] = config_helper.get_string_if_exists(
        config_parser, 'email_subject')

    return config


def sig_term_handler(_signal, _stack_frame):
    """Signal handler for SIGTERM. Quits when SIGTERM is received.

    _signal (int): The signal number that was thrown.
    _stack_frame (frame): Represents the stack frame.
    """
    raise ShutdownException('Received SIGTERM.')


def get_user_id():
    """Return (int): The user ID that the program runs as."""

    try:
        program_user = pwd.getpwnam(PROCESS_USERNAME)
    except KeyError as key_error:
        message = f'User {PROCESS_USERNAME} does not exist.'
        raise InitializationException(message) from key_error

    return program_user.pw_uid


# TODO: Consider checking ACLs. (gpgmailer issue 22)
def verify_safe_file_permissions():
    """Crashes the application if unsafe file permissions exist on application configuration
    files.
    """
    if not os.path.isfile(CONFIGURATION_PATHNAME):
        raise InitializationException(
            f'Configuration file {CONFIGURATION_PATHNAME} does not exist. Quitting.')

    # The configuration file should be owned by torwatchdog.
    config_file_stat = os.stat(CONFIGURATION_PATHNAME)
    if config_file_stat.st_uid != get_user_id():
        raise InitializationException(
            f'File {CONFIGURATION_PATHNAME} must be owned by torwatchdog.')
    if bool(config_file_stat.st_mode & stat.S_IWGRP):
        raise InitializationException(f'File {CONFIGURATION_PATHNAME} cannot be writable '
                                      'via the group access permission.')
    if bool(config_file_stat.st_mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)):
        raise InitializationException(
            f"File {CONFIGURATION_PATHNAME} cannot have 'other user' access permissions set."
            )


ORIGINAL_SOCKET = socket.socket


def socket_factory(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, fileno=None):
    """Creates a socket where all data is routed through a Tor SOCKS5 proxy, except in the
    case of Unix domain sockets which behave normally.

    family (socket.AddressFamily): The address family of the socket to be created. All
      address families except AF_UNIX are routed through a Tor SOCKS5 proxy. See the official
      socket.socket documentation for details.
    type (socket.SocketKind): Typically one of SOCK_STREAM, SOCK_DGRAM, or SOCK_RAW. See the
      official socket.socket documentation for details.
    proto (int): Typically 0 and only relevant for AF_CAN address families. See the official
      Linux or official socket.socket documentation for details.
    fileno (int): A file descriptor indentifier of an existing socket to associate with the
      returned socket object.
    Return (socket.socket): The new (likely proxied) socket object.
    """
    # Don't proxy Unix-domain sockets.
    if family == socket.AF_UNIX:
        return ORIGINAL_SOCKET(family, type, proto, fileno=fileno)

    # PySocks handles everything else.
    return socks.socksocket(family, type, proto, fileno=fileno)


def configure_tor_proxy(config):
    """Configures the Tor proxy settings.

    config (dict): The program configuration object, mostly based on the configuration file.
    """
    # Set socks proxy and wrap the urllib module
    # TODO: Eventually consider choosing a randomly available TCP port. (issue 8)
    socks.setdefaultproxy(
        socks.PROXY_TYPE_SOCKS5, '127.0.0.1', config['tor_socks_port'])
    socket.socket = socket_factory
    # Perform DNS resolution through the socket.
    socket.getaddrinfo = lambda *args: [(
        socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]


def get_url_availability(url):
    """Checks if the specified website is available over Tor.

    url (str): The website to check for availability.
    Return (boolean): True if the url is available. False otherwise.
    """
    logger = logging.getLogger(__name__)
    logger.debug(f'Checking url {url}.')

    try:
        # 30 second timeout.
        urllib.request.urlopen(url, None, 30).read
        logger.debug(f'{url} is up.')
        return True
    except Exception as exception:
        logger.warning(f'Unable to reach {url}. {type(exception).__name__}: {exception}')
        logger.trace(f'Exception: {traceback.format_exc()}')
        return False


def log_and_send_message(config, message, email_error_message):
    """Logs and sends an e-mail of a message.

    config (dict): The program configuration object, mostly based on the configuration file.
    message (str): The e-mail message body.
    email_error_message (str): A message to log in the event of an error while sending the
      e-mail.
    """
    logger = logging.getLogger(__name__)
    logger.warning(message)

    # Prevent the program from quitting if sending an e-mail fails for whatever reason.
    try:
        mail_message = gpgmailmessage.GpgMailMessage()
        mail_message.set_subject(config['email_subject'])
        mail_message.set_body(message)
        mail_message.queue_for_sending()
    except Exception as exception:
        logger.error(f'{email_error_message} {type(exception).__name__}: {exception}\n'
                     f'{traceback.format_exc()}')


def check_availability_and_send_notification(config, prior_availability):
    """Checks if the website is available and sends a notification if the website has not
    been available for a user specified number of attempts.

    config (dict): The program configuration object, mostly based on the configuration file.
    prior_availability (deque<boolean>): The availability status of the prior website access
      attempts. The current attempt will be appended to this deque.
    """
    prior_availability.append(get_url_availability(config['url']))

    # Send an e-mail if the site is consistently down.
    if (not any(islice(prior_availability, 1, len(prior_availability) + 1))
        and prior_availability[0]):
        message = f"Down notification for {config['url']} at {datetime.datetime.now()}."
        email_error_message = 'Could not send down notification.'
        log_and_send_message(config, message, email_error_message)

    # Send e-mail if the site just came back up.
    if (prior_availability[-1] and not prior_availability[-2]):
        message = f"Up notification for {config['url']} at {datetime.datetime.now()}."
        email_error_message = 'Could not send up notification.'
        log_and_send_message(config, message, email_error_message)


def main_loop(config):
    """The main program loop.

    config (dict): The program configuration object, mostly based on the configuration file.
    """
    # Uses /dev/urandom, for determining how long to sleep the main loop.
    random.SystemRandom()

    # Start the program assuming the website has been up.
    prior_availability = deque([True] * (config['min_failed_polls'] + 1),
                               maxlen=(config['min_failed_polls'] + 1))

    logger = logging.getLogger(__name__)
    logger.trace('Starting main loop.')
    while True:
        try:
            # Let's not be too obvious about what this program does. Ramdomize the time
            #   between availability checks.
            sleep_seconds = random.uniform(0, float(config['max_poll_delay']))
            logger.trace(f'Sleeping for {sleep_seconds} seconds.')
            time.sleep(sleep_seconds)

            check_availability_and_send_notification(config, prior_availability)

            sdnotify.SystemdNotifier().notify('WATCHDOG=1')
        except Exception as exception:
            logger.error(f'Unexpected exception {type(exception).__name__}: {exception}.\n'
                         f'{traceback.format_exc()}')
            time.sleep(1)  # Sleep so we don't tax the CPU.


def start():
    """The parent function for the entire program. It loads and verifies configuration and
    starts the main program loop.
    """
    confighelper.ConfigHelper.configure_logger()
    logger = logging.getLogger(__name__)

    signal.signal(signal.SIGTERM, sig_term_handler)

    try:
        verify_safe_file_permissions()
        config = read_configuration()

        configure_tor_proxy(config)

        sdnotify.SystemdNotifier().notify('READY=1')
        main_loop(config)

    except ShutdownException:
        logger.info('Quiting due to SIGTERM.')
    except (Exception, KeyboardInterrupt) as exception:
        logger.critical(f'Fatal {type(exception).__name__}: {exception}\n'
                        f'{traceback.format_exc()}')
        raise exception


if __name__ == '__main__':
    start()
