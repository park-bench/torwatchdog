#!/usr/bin/env python2

# Copyright 2015-2018 Joel Allen Luellwitz and Andrew Klapp
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
the site's availability changes.  Uses urllib to fetch the site using Socks for Tor over
the SOCKS_PORT.
"""

# TODO: Eventually consider running in a chroot or jail. (gpgmailer issue 17)
# TODO: Eventually check to see if the network/internet connection is down. (issue 4)

__author__ = 'Joel Luellwitz and Andrew Klapp'
__version__ = '0.8'

import ConfigParser
import datetime
import grp
import logging
import os
import pwd
import random
import signal
import socket
import stat
import sys
import time
import traceback
import urllib
import confighelper
import daemon
from lockfile import pidlockfile
import socks
import stem.process
import gpgmailmessage

# Constants
PROGRAM_NAME = 'torwatchdog'
CONFIGURATION_PATHNAME = os.path.join('/etc', PROGRAM_NAME, '%s.conf' % PROGRAM_NAME)
SYSTEM_PID_DIR = '/run'
PROGRAM_PID_DIRS = PROGRAM_NAME
PID_FILE = '%s.pid' % PROGRAM_NAME
LOG_DIR = os.path.join('/var/log', PROGRAM_NAME)
LOG_FILE = '%s.log' % PROGRAM_NAME
SYSTEM_DATA_DIR = '/var/cache'
TOR_DATA_DIRS = os.path.join(PROGRAM_NAME, 'tor')
PROCESS_USERNAME = PROGRAM_NAME
PROCESS_GROUP_NAME = PROGRAM_NAME
PROGRAM_UMASK = 0o027  # -rw-r----- and drwxr-x---


class InitializationException(Exception):
    """Indicates an expected fatal error occurred during program initialization.
    Initialization is implied to mean, before daemonization.
    """


def get_user_and_group_ids():
    """Get user and group information for dropping privileges.

    Returns the user and group IDs that the program should eventually run as.
    """
    try:
        program_user = pwd.getpwnam(PROCESS_USERNAME)
    except KeyError as key_error:
        # TODO: When moving to Python 3, change to chained exception. (gpgmailer issue 15)
        print('User %s does not exist.', PROCESS_USERNAME)
        raise key_error
    try:
        program_group = grp.getgrnam(PROCESS_GROUP_NAME)
    except KeyError as key_error:
        # TODO: When moving to Python 3, change to chained exception. (gpgmailer issue 15)
        print('Group %s does not exist.', PROCESS_GROUP_NAME)
        raise key_error

    return program_user.pw_uid, program_group.gr_gid


def read_configuration_and_create_logger(program_uid, program_gid):
    """Reads the configuration file and creates the application logger. This is done in the
    same function because part of the logger creation is dependent upon reading the
    configuration file.

    program_uid: The system user ID this program should drop to before daemonization.
    program_gid: The system group ID this program should drop to before daemonization.
    Returns the read system config, a confighelper instance, and a logger instance.
    """
    config_parser = ConfigParser.SafeConfigParser()
    config_parser.read(CONFIGURATION_PATHNAME)

    # Logging config goes first.
    config = {}
    config_helper = confighelper.ConfigHelper()
    config['log_level'] = config_helper.verify_string_exists(config_parser, 'log_level')

    # Create logging directory.  drwxr-x---
    log_mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP
    # TODO: Look into defaulting the logging to the console until the program gets more
    #   bootstrapped. (gpgmailer issue 18)
    print('Creating logging directory %s.' % LOG_DIR)
    if not os.path.isdir(LOG_DIR):
        # Will throw exception if file cannot be created.
        os.makedirs(LOG_DIR, log_mode)
    os.chown(LOG_DIR, program_uid, program_gid)
    os.chmod(LOG_DIR, log_mode)

    # Temporarily drop permissions and create the handle to the logger.
    os.setegid(program_gid)
    os.seteuid(program_uid)
    config_helper.configure_logger(os.path.join(LOG_DIR, LOG_FILE), config['log_level'])

    logger = logging.getLogger(__name__)

    logger.info('Verifying non-logging config')
    config['url'] = config_helper.verify_string_exists(config_parser, 'url')
    config['tor_socks_port'] = config_helper.verify_integer_exists(
        config_parser, 'tor_socks_port')
    config['average_delay'] = config_helper.verify_number_exists(
        config_parser, 'average_delay')
    config['email_subject'] = config_helper.verify_string_exists(
        config_parser, 'email_subject')

    return (config, config_helper, logger)


# TODO: Consider checking ACLs. (gpgmailer issue 22)
def verify_safe_file_permissions():
    """Crashes the application if unsafe file permissions exist on application configuration
    files.
    """
    # The configuration file should be owned by root.
    config_file_stat = os.stat(CONFIGURATION_PATHNAME)
    if config_file_stat.st_uid != 0:
        raise InitializationException(
            'File %s must be owned by root.' % CONFIGURATION_PATHNAME)
    if bool(config_file_stat.st_mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)):
        raise InitializationException(
            "File %s cannot have 'other user' access permissions set."
            % CONFIGURATION_PATHNAME)


def create_directory(system_path, program_dirs, uid, gid, mode):
    """Creates directories if they do not exist and sets the specified ownership and
    permissions.

    system_path: The system path that the directories should be created under. These are
      assumed to already exist. The ownership and permissions on these directories are not
      modified.
    program_dirs: A string representing additional directories that should be created under
      the system path that should take on the following ownership and permissions.
    uid: The system user ID that should own the directory.
    gid: The system group ID that should be associated with the directory.
    mode: The umask of the directory access permissions.
    """
    logger.info('Creating directory %s.', os.path.join(system_path, program_dirs))

    path = system_path
    for directory in program_dirs.strip('/').split('/'):
        path = os.path.join(path, directory)
        if not os.path.isdir(path):
            # Will throw exception if file cannot be created.
            os.makedirs(path, mode)
        os.chown(path, uid, gid)
        os.chmod(path, mode)


def drop_permissions_forever(uid, gid):
    """Drops escalated permissions forever to the specified user and group.

    uid: The system user ID to drop to.
    gid: The system group ID to drop to.
    """
    logger.info('Dropping permissions for user %s.', PROCESS_USERNAME)
    os.initgroups(PROCESS_USERNAME, gid)
    os.setgid(gid)
    os.setuid(uid)


def configure_tor_proxy(config):
    """Configures the tor proxy settings.

    config: The program configuration object, mostly based on the configuration file.
    """
    # Set socks proxy and wrap the urllib module
    # TODO: Eventually consider choosing a randomly available TCP port. (issue 8)
    socks.setdefaultproxy(
        socks.PROXY_TYPE_SOCKS5, '127.0.0.1', config['tor_socks_port'])
    socket.socket = socks.socksocket
    # Perform DNS resolution through the socket.
    socket.getaddrinfo = lambda *args: [(
        socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]


def sig_term_handler(signal, stack_frame):
    """Signal handler for SIGTERM. Kills Tor and quits when SIGTERM is received.

    signal: Object representing the signal thrown.
    stack_frame: Represents the stack frame.
    """
    logger.info('SIGTERM received. Quitting.')
    if tor_process is not None:
        logger.info('Stopping tor.')
        tor_process.kill()
    sys.exit(0)


def setup_daemon_context(log_file_handle, program_uid, program_gid):
    """Creates the daemon context. Specifies daemon permissions, PID file information, and
    signal handler.

    log_file_handle: The file handle to the log file.
    program_uid: The system user ID the daemon should run as.
    program_gid: The system group ID the daemon should run as.
    Returns the daemon context.
    """
    daemon_context = daemon.DaemonContext(
        working_directory='/',
        pidfile=pidlockfile.PIDLockFile(
            os.path.join(SYSTEM_PID_DIR, PROGRAM_PID_DIRS, PID_FILE)),
        umask=PROGRAM_UMASK,
        )

    daemon_context.signal_map = {
        signal.SIGTERM: sig_term_handler,
        }

    daemon_context.files_preserve = [log_file_handle]

    # Set the UID and PID to 'torwatchdog' user and group.
    daemon_context.uid = program_uid
    daemon_context.gid = program_gid

    return daemon_context


def print_bootstrap_lines(line):
    """Callback to log only Tor's bootstrap lines.

    line: A Tor log line.
    """
    if 'Bootstrapped ' in line:
        logger.info(line)


def start_tor(config):
    """Starts the tor process.

    config: The program configuration object, mostly based on the configuration file.
    Returns a handle to the tor process.
    """
    # Note that the 'take_ownership' option does not work correctly after forking.
    tor_config = {
        'SocksPort': str(config['tor_socks_port']),
        'DataDirectory': os.path.join(SYSTEM_DATA_DIR, TOR_DATA_DIRS),
    }

    logger.info('Starting Tor on port %s.', config['tor_socks_port'])
    tor_process = stem.process.launch_tor_with_config(
        tor_config, init_msg_handler=print_bootstrap_lines)

    return tor_process


def start_tor_before_daemonize(config):
    """Starts the tor process prior to daemonization. If the tor process fails too quickly,
    we assume tor is configured incorrectly and the program quits. Else, the program will
    keep trying to connect to Tor even after daemonization.

    config: The program configuration object, mostly based on the configuration file.
    Returns a handle to the tor process.
    """
    tor_process = None
    start_time = datetime.datetime.now()
    try:
        tor_process = start_tor(config)
    except OSError as os_error:
        end_time = datetime.datetime.now()
        fail_time = end_time - start_time

        logger.error('Failed start Tor. %s: %s', type(os_error).__name__, str(os_error))
        logger.error(traceback.format_exc())

        # If tor quit in less than 30 seconds, assume something is misconfigured.
        if fail_time >= datetime.timedelta(seconds=30):
            logger.error('Will try again after daemonize.')
        else:
            # TODO: When moving to Python 3, convert to checked exception. (gpgmailer issue
            #   15)
            raise Exception(
                'Tor failed to start in only %d seconds. Assuming the program is '
                'misconfigured. Quitting.' % fail_time.total_seconds())

    return tor_process


def is_site_up(url):
    """Checks if the specified website is available over Tor.

    url: The website to check for availability.
    Returns True if the url is available. False otherwise.
    """
    logger.debug('Checking url %s.', url)

    try:
        urllib.urlopen(url).read()
        logger.debug('%s is up.', url)
        return True
    except Exception as exception:
        logger.warn('Unable to reach %s. %s: %s',
                    url, type(exception).__name__, str(exception))
        logger.trace('Exception: %s' % traceback.format_exc())
        return False


def log_and_send_message(config, message, email_error_message):
    """Logs and sends an e-mail of a message.

    config: The program configuration object, mostly based on the configuration file.
    message: The e-mail message body.
    email_error_message: A message to log in the event of an error while sending the e-mail.
    """
    logger.warn(message)

    # Prevent the program from quitting if sending an e-mail fails for whatever reason.
    try:
        mail_message = gpgmailmessage.GpgMailMessage()
        mail_message.set_subject(config['email_subject'])
        mail_message.set_body(message)
        mail_message.queue_for_sending()
    except Exception as exception:
        logger.error('%s %s: %s', email_error_message, type(exception).__name__,
                     str(exception))
        logger.error(traceback.format_exc())


def main_loop(config, tor_process):
    """The main program loop.

    config: The program configuration object, mostly based on the configuration file.
    tor_process: A handle to the tor process.
    """
    # If tor hasn't started, keep trying.
    while tor_process is None:
        try:
            tor_process = start_tor(config)
        except Exception as exception:
            logger.error('Failed to start Tor. %s: %s', type(exception).__name__,
                         str(exception))
            logger.error(traceback.format_exc())
            logger.error('Will try to connect again in 1 second.')
            time.sleep(1)

    # Uses /dev/urandom, for determining how long to sleep the main loop.
    random.SystemRandom()

    prior_status = True  # Start the program assuming the website is up.

    logger.trace('Starting loop.')
    while True:
        # Let's not be too obvious about what this program does. Ramdomize the time between
        #   status checks.
        sleep_seconds = random.uniform(0, int(config['average_delay']))
        logger.trace('Sleeping for %d seconds.' % sleep_seconds)
        time.sleep(sleep_seconds)

        current_status = is_site_up(config['url'])

        # Send e-mail if the site just went down
        if (not current_status and prior_status):
            message = 'Down notification for %s at %s.' % (
                config['url'], datetime.datetime.now())
            email_error_message = 'Could not send down notification.'
            log_and_send_message(config, message, email_error_message)

        # Send e-mail if the site just came back up
        if (current_status and not prior_status):
            message = 'Up notification for %s at %s.' % (
                config['url'], datetime.datetime.now())
            email_error_message = 'Could not send up notification.'
            log_and_send_message(config, message, email_error_message)

        prior_status = current_status


os.umask(PROGRAM_UMASK)
program_uid, program_gid = get_user_and_group_ids()
config, config_helper, logger = read_configuration_and_create_logger(
    program_uid, program_gid)

tor_process = None
try:
    verify_safe_file_permissions()

    # Re-establish root permissions to create required directories.
    os.seteuid(os.getuid())
    os.setegid(os.getgid())

    # Non-root users cannot create files in /run, so create a directory that can be written
    #   to. Full access to user only.  drwx------
    create_directory(
        SYSTEM_PID_DIR, PROGRAM_PID_DIRS, program_uid, program_gid,
        stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    # Make the Tor data directory. Full access to user only.  drwx------
    create_directory(
        SYSTEM_DATA_DIR, TOR_DATA_DIRS, program_uid, program_gid,
        stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    # Configuration has been read and directories setup. Now drop permissions forever.
    drop_permissions_forever(program_uid, program_gid)

    configure_tor_proxy(config)

    daemon_context = setup_daemon_context(
        config_helper.get_log_file_handle(), program_uid, program_gid)

    tor_process = start_tor_before_daemonize(config)

    with daemon_context:
        main_loop(config, tor_process)

except Exception as exception:
    logger.critical('Fatal %s: %s\n%s', type(exception).__name__, str(exception),
                    traceback.format_exc())
    if tor_process is not None:
        logger.info('Stopping tor.')
        tor_process.kill()
    raise exception
