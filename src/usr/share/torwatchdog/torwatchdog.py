#!/usr/bin/env python2

# Copyright 2015-2016 Joel Allen Luellwitz and Andrew Klapp
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

# Verifies a website is running over Tor and sends an encrypted e-mail
#   notification when the site's availability changes. Uses urllib to
#   fetch the site using SocksiPy for Tor over the SOCKS_PORT.

# TODO: Consider running in a chroot or jail.
# TODO: Check if network/internet connection is down

import confighelper
import ConfigParser
import daemon
import datetime
import gpgmailmessage
import grp
import logging
import os
from daemon import pidlockfile
import pwd
import random
import signal
import socket
import socks  # SocksiPy module
import stat
import stem.process
import sys
import time
import traceback
import urllib

# Constants
program_name = 'torwatchdog'
pid_file = '%s.pid' % program_name
pid_dir = '/run/%s' % program_name
log_file = '%s.log' % program_name
process_username = program_name
process_group_name = program_name
configuration_pathname = os.join('/etc', program_name, '%s.conf' % program_name)
tor_data_dir = os.join('/var/cache', program_name, 'tor')


# Get user and group information for dropping privileges.
def get_user_and_group_ids():
    try:
        program_user = pwd.getpwnam(process_username)
    except KeyError as key_error:
        raise Exception('User %s does not exist.' % process_username, key_error)
    try:
        program_group = grp.getgrnam(process_group_name)
    except KeyError as key_error:
        raise Exception('Group %s does not exist.' % process_group_name, key_error)

    return (program_user.pw_uid, program_group.gr_gid)


# Reads the configuration file and creates the application logger. This is done in the
#   same function because part of the logger creation is dependent upon reading the
#   configuration file.
#
# program_uid The system user ID this program should drop to before daemonization.
# program_gid The system group ID this program should drop to before daemonization.
def read_configuration_and_create_logger(program_uid, program_gid):
    config_parser = ConfigParser.SafeConfigParser()
    config_parser.read(configuration_pathname)

    # Logging config goes first
    config = {}
    config_helper = confighelper.ConfigHelper()
    config['log_level'] = config_helper.verify_string_exists_prelogging(config_parser, 'log_level')

    # Temporarily drop permission and create the handle to the logger.
    os.setegid(program_gid)
    os.seteuid(program_uid)
    config_helper.configure_logger(os.join(log_dir, log_file), config['log_level'])
    os.seteuid(os.getuid())
    os.setegid(os.getgid())

    logger = logging.getLogger('%s-daemon' % program_name)

    logger.info('Verifying non-logging config')
    config['url'] = config_helper.verify_string_exists(config_file, 'url')
    config['tor_socks_port'] = config_helper.verify_integer_exists(config_file, 'tor_socks_port')
    config['average_delay'] = config_helper.verify_number_exists(config_file, 'average_delay')
    config['email_subject'] = config_helper.verify_string_exists(config_file, 'email_subject')

    return (config, config_helper, logger)


# Creates a directory if it does not exist and sets the specified ownership and permissions.
#
# path: The pathname of the directory to create. Will create intermediate directories.
# uid: The system user ID that should own the directory.
# gid: The system group ID that should own be associated with the directory.
# mode: The umask of the directory access permissions.
def create_directory(path, uid, gid, mode):
    logger.info('Creating directory %s.' % path)
    if not os.path.isdir(path):
        # Will throw exception if file cannot be created.
        os.makedirs(path, mode)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


# Drops escalated permissions forever to the specified user and group.
#
# uid: The system user ID to drop to.
# gid: The system group ID to drop to.
def drop_permissions_forever(uid, gid):
    logger.info('Dropping permissions for user %s.' % process_username)
    os.initgroups(process_username, gid)
    os.setgid(gid)
    os.setuid(uid)


# Configures the tor proxy settings.
#
# config: The program configuration object, mostly based on the configuration file.
def configure_tor_proxy(config):
    # Set socks proxy and wrap the urllib module
    # TODO: Consider choosing a randomly available TCP port.
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', int(config['tor_socks_port']))
    socket.socket = socks.socksocket
    socket.getaddrinfo = lamdba *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]


# Perform DNS resolution through the socket
# TODO: Consider inlining.
#def get_address_info(*args):
#    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]


# Creates the daemon context. Currently specifies daemon permissions, PID file information, and
#   signal handler.
#
# log_file_handle: The file handle to the log file.
def setup_daemon_context(log_file_handle):

    daemon_context = daemon.DaemonContext(
        working_directory = '/',
        pidfile = pidlockfile.PIDLockFile(os.path.join(pid_dir, pid_file)),
        umask = 0o117,  # Read/write by user and group.
        )

    daemon_context.signal_map = {
        signal.SIGTERM : sig_term_handler,
        }

    daemon_context.files_preserve = []

    # Set the UID and PID to parkbench-torwatchdog user and group.
    daemon_context.uid = linuxUser.pw_uid
    daemon_context.gid = linuxGroup.gr_gid

    return daemon_context


# Starts the tor process.
#
# config: The program configuration object, mostly based on the configuration file.
def start_tor(config):

    # Note that the 'take_ownership' option does not work correctly after forking.
    tor_config = {
        'SocksPort': str(config['socks_port']),
        'DataDirectory': config['tor_data_dir'],
    }
     
    logger.info("Starting Tor on port %s." % config['socks_port'])
    tor_process = stem.process.launch_tor_with_config(
        tor_config, 
        init_msg_handler = if "Bootstrapped " in line: logger.info("%s" % line))

    return tor_process


# Start an instance of Tor. This prints Tor's bootstrap information as it starts.
# TODO: Consider inlining.
#def print_bootstrap_lines(line):
#    if "Bootstrapped " in line:
#        logger.info("%s" % line)


# The main program loop.
#
# config: The program configuration object, mostly based on the configuration file.
def main_loop(config):

    random.SystemRandom()  # Uses /dev/urandom, for determining how long to sleep the main loop.

    prior_status = True  # Start the program assuming the website is up.
    
    logger.trace('Starting loop.')

    while(True):
        
        # Let's not be too obvious about what this program does. Ramdomize the time between
        #   status checks.
        sleep_seconds = random.uniform(0, int(config['avg_delay']))
        logger.trace('Sleeping for %d seconds.' % sleep_seconds)
        time.sleep(sleep_seconds)

        current_status = is_site_up(config['url'])

        # Send e-mail if the site just went down
        if (not current_status and prior_status):
            logger.warn("Send down notification")

            message = gpgmailmessage.GpgMailMessage()
            message.set_subject(config['email_subject'])
            message.set_body('Down notification for %s at %s.' % (config['url'], datetime.datetime.now()))
            message.queue_for_sending()
      
        # Send e-mail if the site just came back up
        if (current_status and not prior_status):
            logger.info("Send up notification")

            message = gpgmailmessage.GpgMailMessage()
            message.set_subject(config['email_subject'])
            message.set_body('Up notification for %s at %s.' % (config['url'], datetime.datetime.now()))
            message.queue_for_sending()
        prior_status = current_status


# Checks if the specified website is available over Tor.
#
# url: The website to check for availability.
def is_site_up(url):

    logger.debug('Checkin url %s.' % url)

    try:
        urllib.urlopen(url).read()
        logger.debug("%s is up." % url)
        return True
    except Exception as detail:
        logger.warn("Unable to reach %s." % url)
        # TODO: Print a one line reason about why the site was not resolved.
        logger.debug("Full reason for lookup failure: %s" % traceback.format_exc())
        return False
        
    logger.trace('Done checking url %s.' % url)


# Signal handler for SIGTERM. Kills Tor and quits when SIGTERM is received.
def sig_term_handler(signal, stack_frame):
    if tor_process != None:
        logger.info("Stopping tor.")
        tor_process.kill()
    sys.exit(0)


(program_uid, program_gid) = get_user_and_group_ids()

(config, config_helper, logger) = read_configuration_and_create_logger(program_uid, program_gid)

try:
    # Read gpgmailer watch directory from the gpgmailer config file
    gpgmailmessage.GpgMailMessage.configure()

    # Create the logging directory
    #   Full access to user, others can read and traverse.
    create_directory(log_dir, program_uid, program_gid, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

    # Non-root users cannot create files in /run, so create a directory that can be written to.
    #   Full access to user only.
    create_directory(pid_dir, program_uid, program_gid, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    # Make the Tor data directory.
    #   Full access to user only.
    create_directory(tor_data_dir, program_uid, program_gid, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
     
    # Configuration has been read and directories setup. Now drop permissions forever.
    drop_permissions_forever(program_uid, program_gid)

    configure_tor_proxy(config)

    daemon_context = setup_daemon_context(config_helper.get_log_file_handle())

    tor_process = None
    tor_process = start_tor(config)

    with daemon_context:
        main_loop(config)
 
except Exception as e:
    logger.critical("Fatal %s: %s\n" % (type(e).__name__, e.message))
    logger.critical(traceback.format_exc())
    if tor_process != None:
        logger.info("Stopping tor.")
        tor_process.kill()
    sys.exit(1)
