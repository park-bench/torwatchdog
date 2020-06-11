#!/usr/bin/python3

# Copyright 2015-2020 Joel Allen Luellwitz and Emily Frost
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
__version__ = '0.8'

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
import urllib.request
import configparser
import daemon
from lockfile import pidlockfile
import socks
import stem.process
from parkbenchcommon import confighelper
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
        message = 'User %s does not exist.' % PROCESS_USERNAME
        raise InitializationException(message) from key_error
    try:
        program_group = grp.getgrnam(PROCESS_GROUP_NAME)
    except KeyError as key_error:
        message = 'Group %s does not exist.' % PROCESS_GROUP_NAME
        raise InitializationException(message) from key_error

    return program_user.pw_uid, program_group.gr_gid


def read_configuration_and_create_logger(program_uid, program_gid):
    """Reads the configuration file and creates the application logger. This is done in the
    same function because part of the logger creation is dependent upon reading the
    configuration file.

    program_uid: The system user ID this program should drop to before daemonization.
    program_gid: The system group ID this program should drop to before daemonization.
    Returns the read system config, a confighelper instance, and a logger instance.
    """
    print('Reading %s...' % CONFIGURATION_PATHNAME)

    if not os.path.isfile(CONFIGURATION_PATHNAME):
        raise InitializationException(
            'Configuration file %s does not exist. Quitting.' % CONFIGURATION_PATHNAME)

    config_file = configparser.SafeConfigParser()
    config_file.read(CONFIGURATION_PATHNAME)

    config = {}
    config_helper = confighelper.ConfigHelper()
    # Figure out the logging options so that can start before anything else.
    # TODO: Eventually add a verify_string_list method. (gpgmailer issue 20)
    config['log_level'] = config_helper.verify_string_exists(config_file, 'log_level')

    # Create logging directory.  drwxr-x--- torwatchdog torwatchdog
    log_mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP
    # TODO: Look into defaulting the logging to the console until the program gets more
    #   bootstrapped. (gpgmailer issue 18)
    print('Creating logging directory %s.' % LOG_DIR)
    if not os.path.isdir(LOG_DIR):
        # Will throw exception if directory cannot be created.
        os.makedirs(LOG_DIR, log_mode)
    os.chown(LOG_DIR, program_uid, program_gid)
    os.chmod(LOG_DIR, log_mode)

    # Temporarily drop permissions and create the handle to the logger.
    print('Configuring logger.')
    os.setegid(program_gid)
    os.seteuid(program_uid)
    config_helper.configure_logger(os.path.join(LOG_DIR, LOG_FILE), config['log_level'])

    logger = logging.getLogger(__name__)

    logger.info('Verifying non-logging configuration.')

    config['url'] = config_helper.verify_string_exists(config_file, 'url')
    config['tor_socks_port'] = config_helper.verify_integer_within_range(
        config_file, 'tor_socks_port', lower_bound=1, upper_bound=65536)
    config['max_poll_delay'] = config_helper.verify_number_within_range(
        config_file, 'max_poll_delay', lower_bound=0.000001)
    config['email_subject'] = config_helper.get_string_if_exists(
        config_file, 'email_subject')

    return config, config_helper, logger


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
    mode: The unix standard 'mode bits' that should be associated with the directory.
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
    """Configures the Tor proxy settings.

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


def is_tor_wrapper_process_running(wrapper_process):
    """Checks if the Tor wrapper process is still running. Popen.poll() does not work when a
    subprocess is started before Daemonize, so this method uses an alternate algorithm to
    determine is if the subprocess is still running. This method sends USR1 to the
    subprocess. If a ProcessLookupError is raised, the subprocess is no longer running.

    wrapper_process: A handle to the Tor wrapper process.
    Returns True if the subprocess is still running. False otherwise.
    """
    running = True
    try:
        wrapper_process.send_signal(signal.SIGUSR1)
    except ProcessLookupError:
        running = False

    return running


def stop_tor_before_exit(wrapper_process):
    """Stops the Tor wrapper, first by being nice and using SIGTERM and then SIGKILL.

    tor_wrapper_process: A handle to the Tor wrapper process.
    """
    if wrapper_process is not None:
        logger.info('Waiting for one second for Tor to terminate.')
        wrapper_process.terminate()
        time.sleep(1)
        if not is_tor_wrapper_process_running(wrapper_process):
            logger.info('Tor stopped successfully.')
        else:
            logger.error('Tor process did not terminate. Attempting to kill tor.')
            # Since Tor is linked to the wrapper process, Tor should quickly self terminate.
            wrapper_process.kill()
            # To handle the case where the daemon is restarting, make sure the Tor process
            #   has had enough time to realize the Tor wrapper process has died. Tor polls
            #   every 15 seconds to determine if its owning contoller process has died. If
            #   we don't wait, the Tor port might still be in use.
            logger.error('Waiting for 16 seconds for the Tor process to realize that the '
                'wrapper process has died.')
            time.sleep(16)


def sig_term_handler(signal, stack_frame):  #pylint: disable=unused-argument
    """Signal handler for SIGTERM. When SIGTERM is received, stops the Tor wrapper and
    quits.

    signal: Object representing the signal thrown.
    stack_frame: Represents the stack frame.
    """
    logger.info('SIGTERM received. Quitting.')
    stop_tor_before_exit(tor_wrapper_process)
    sys.exit(0)


def setup_daemon_context(log_file_handle, program_uid, program_gid):
    """Creates the daemon context. Specifies daemon permissions, PID file information, and
    the signal handler.

    log_file_handle: The file handle to the log file.
    program_uid: The system user ID that should own the daemon process.
    program_gid: The system group ID that should be assigned to the daemon process.
    Returns the daemon context.
    """
    daemon_context = daemon.DaemonContext(
        # This next line prevents a Python 3 related hang. This should evalute to True
        #   anyway.
        detach_process=True,
        working_directory='/',
        pidfile=pidlockfile.PIDLockFile(
            os.path.join(SYSTEM_PID_DIR, PROGRAM_PID_DIRS, PID_FILE)),
        umask=PROGRAM_UMASK,
    )

    daemon_context.signal_map = {
        signal.SIGTERM: sig_term_handler,
    }

    daemon_context.files_preserve = [log_file_handle]

    # Set the UID and GID to 'torwatchdog' user and group.
    daemon_context.uid = program_uid
    daemon_context.gid = program_gid

    return daemon_context


def print_bootstrap_lines(line):
    """Callback to log only Tor's bootstrap lines.

    line: A Tor log line.
    """
    logger.info("Tor: %s" % line)


def start_tor(config):
    """Starts the Tor process.

    config: The program configuration object, mostly based on the configuration file.
    Returns a handle to the Tor wrapper process.
    """
    # Note that the 'take_ownership' option does not work correctly after forking.
    tor_config = {
        'SocksPort': str(config['tor_socks_port']),
        'DataDirectory': os.path.join(SYSTEM_DATA_DIR, TOR_DATA_DIRS),
    }

    logger.info('Starting Tor on port %s.', config['tor_socks_port'])
    wrapper_process = stem.process.launch_tor_with_config(
        tor_config,
        tor_cmd=os.path.join('/usr/share', PROGRAM_NAME, 'tor-stdout-fix.py'),
        init_msg_handler=print_bootstrap_lines)

    return wrapper_process


def start_tor_before_daemonize(config):
    """Starts the Tor process prior to daemonization. If the Tor process fails too quickly,
    we assume Tor is configured incorrectly and the program quits. Else, the program will
    keep trying to connect to Tor even after daemonization.

    config: The program configuration object, mostly based on the configuration file.
    Returns a handle to the Tor wrapper process.
    """
    wrapper_process = None
    start_time = datetime.datetime.now()
    try:
        wrapper_process = start_tor(config)
    except OSError as os_error:
        end_time = datetime.datetime.now()
        fail_time = end_time - start_time

        logger.error(
            'Failed start Tor. %s: %s\n%s', type(os_error).__name__, str(os_error),
            traceback.format_exc())

        # If Tor quit in less than 30 seconds, assume something is misconfigured.
        if fail_time >= datetime.timedelta(seconds=30):
            logger.error('Will try again after daemonize.')
        else:
            raise InitializationException(
                'Tor failed to start in only %d seconds. Assuming the program is '
                'misconfigured. Quitting.' % fail_time.total_seconds()) from os_error

    return wrapper_process


def restart_tor_if_needed(config, wrapper_process):
    """If Tor hasn't started or has stopped running, try to connect.

    config: The program configuration object, mostly based on the configuration file.
    wrapper_process: A handle to the Tor wrapper process.
    Returns a handle to the current Tor wrapper process. Might be a different handle than
      the parameter above.
    """
    while wrapper_process is None or not is_tor_wrapper_process_running(
            wrapper_process):
        if wrapper_process is not None:
            logger.error(
                'Tor process unexpectantly exited with exit code %d. Attempting to restart '
                'Tor.', wrapper_process.returncode)
        try:
            wrapper_process = start_tor(config)
        except Exception as exception:
            wrapper_process = None
            logger.error(
                'Failed to start Tor. %s: %s\n%s\nWill try to connect again in 1 second.',
                type(exception).__name__, str(exception),
                traceback.format_exc())
            time.sleep(1)

    return wrapper_process


def get_url_availability(url):
    """Checks if the specified website is available over Tor.

    url: The website to check for availability.
    Returns True if the url is available. False otherwise.
    """
    logger.debug('Checking url %s.', url)

    try:
        urllib.request.urlopen(url).read
        logger.debug('%s is up.', url)
        return True
    except Exception as exception:
        logger.warning('Unable to reach %s. %s: %s',
                       url, type(exception).__name__, str(exception))
        logger.trace('Exception: %s' % traceback.format_exc())
        return False


def log_and_send_message(config, message, email_error_message):
    """Logs and sends an e-mail of a message.

    config: The program configuration object, mostly based on the configuration file.
    message: The e-mail message body.
    email_error_message: A message to log in the event of an error while sending the e-mail.
    """
    logger.warning(message)

    # Prevent the program from quitting if sending an e-mail fails for whatever reason.
    try:
        mail_message = gpgmailmessage.GpgMailMessage()
        mail_message.set_subject(config['email_subject'])
        mail_message.set_body(message)
        mail_message.queue_for_sending()
    except Exception as exception:
        logger.error('%s %s: %s\n%s', email_error_message, type(exception).__name__,
                     str(exception), traceback.format_exc())


def check_availability_and_send_notification(config, prior_availability):
    """Checks if the website is available and sends a notification if the availability
    status changes.

    config: The program configuration object, mostly based on the configuration file.
    prior_availability: The availability status of the prior website access attempt.
    Returns True if the url is available. False otherwise.
    """
    current_availability = get_url_availability(config['url'])

    # Send e-mail if the site just went down
    if (not current_availability and prior_availability):
        message = 'Down notification for %s at %s.' % (
            config['url'], datetime.datetime.now())
        email_error_message = 'Could not send down notification.'
        log_and_send_message(config, message, email_error_message)

    # Send e-mail if the site just came back up
    if (current_availability and not prior_availability):
        message = 'Up notification for %s at %s.' % (
            config['url'], datetime.datetime.now())
        email_error_message = 'Could not send up notification.'
        log_and_send_message(config, message, email_error_message)

    return current_availability


def main_loop(config):
    """The main program loop.

    config: The program configuration object, mostly based on the configuration file.
    """
    # Uses /dev/urandom, for determining how long to sleep the main loop.
    random.SystemRandom()

    global tor_wrapper_process
    prior_availability = True  # Start the program assuming the website is up.

    logger.trace('Starting main loop.')
    while True:
        try:
            tor_wrapper_process = restart_tor_if_needed(config, tor_wrapper_process)

            # Let's not be too obvious about what this program does. Ramdomize the time
            #   between availability checks.
            sleep_seconds = random.uniform(0, float(config['max_poll_delay']))
            logger.trace('Sleeping for %d seconds.' % sleep_seconds)
            time.sleep(sleep_seconds)

            prior_availability = check_availability_and_send_notification(
                config, prior_availability)
        except Exception as exception:
            logger.error('Unexpected exception %s: %s.\n%s', type(exception).__name__,
                         str(exception), traceback.format_exc())
            time.sleep(1)  # Sleep so we don't tax the CPU.


def main():
    """The parent function for the entire program. It loads and verifies configuration,
    daemonizes, and starts the main program loop.
    """
    os.umask(PROGRAM_UMASK)
    program_uid, program_gid = get_user_and_group_ids()
    global logger
    config, config_helper, logger = read_configuration_and_create_logger(
        program_uid, program_gid)

    global tor_wrapper_process
    tor_wrapper_process = None
    try:
        verify_safe_file_permissions()

        # Re-establish root permissions to create required directories.
        os.seteuid(os.getuid())
        os.setegid(os.getgid())

        # Non-root users cannot create files in /run, so create a directory that can be
        #   written to. Full access to user only.  drwx------ torwatchdog torwatchdog
        create_directory(SYSTEM_PID_DIR, PROGRAM_PID_DIRS, program_uid, program_gid,
                         stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        # Make the Tor data directory. Full access to user only.
        #   drwx------ torwatchdog torwatchdog
        create_directory(SYSTEM_DATA_DIR, TOR_DATA_DIRS, program_uid, program_gid,
                         stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        # Configuration has been read and directories setup. Now drop permissions forever.
        drop_permissions_forever(program_uid, program_gid)

        configure_tor_proxy(config)

        daemon_context = setup_daemon_context(
            config_helper.get_log_file_handle(), program_uid, program_gid)

        tor_wrapper_process = start_tor_before_daemonize(config)

        logger.info('Daemonizing...')
        with daemon_context:
            main_loop(config)

    except (Exception, KeyboardInterrupt) as exception:
        logger.critical('Fatal %s: %s\n%s', type(exception).__name__, str(exception),
                        traceback.format_exc())
        stop_tor_before_exit(tor_wrapper_process)

        raise exception


if __name__ == '__main__':
    main()
