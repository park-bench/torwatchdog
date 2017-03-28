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

pid_file = 'torwatchdog.pid'
pid_dir = '/run/torwatchdog'
log_file = 'torwatchdog.log'
process_username = 'torwatchdog'
process_group_name = 'torwatchdog'

# TODO: Consider running in a chroot or jail.
# TODO: Check if network/internet connection is down
# TODO: We need to do more to make sure the tor process gets shutdown if something wrong occurs during init.

# Get user and group information for dropping privileges.
try:
    linuxUser = pwd.getpwnam(process_username)
except KeyError as key_error:
    raise Exception('User %s does not exist.' % process_username, key_error)
try:
    linuxGroup = grp.getgrnam(process_group_name)
except KeyError as key_error:
    raise Exception('Group %s does not exist.' % process_group_name, key_error)
escalated_uid = os.getuid()
escalated_gid = os.getgid()

config_file = ConfigParser.SafeConfigParser()
config_file.read('/etc/torwatchdog/torwatchdog.conf')

# Logging config goes first
config_helper = confighelper.ConfigHelper()
log_dir = config_helper.verify_string_exists_prelogging(config_file, 'log_dir')
log_level = config_helper.verify_string_exists_prelogging(config_file, 'log_level')

# Create the logging directory
# Full access to user, others can read and traverse.
log_mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH
if not os.path.isdir(log_dir):
    print('Creating the logging directory %s.', log_dir)
    os.makedirs(log_dir, log_mode)
os.chown(log_dir, linuxUser.pw_uid, linuxGroup.gr_gid)
os.chmod(log_dir, log_mode)

# Temporarily drop permission and create the handle to the logger.
os.setegid(linuxGroup.gr_gid)
os.seteuid(linuxUser.pw_uid)
config_helper.configure_logger(os.join(log_dir, log_file), log_level)

logger = logging.getLogger()

logger.info('Verifying non-logging config')
config = {}

config['url'] = config_helper.verify_string_exists(config_file, 'url')
config['tor_data_dir'] = config_helper.verify_string_exists(config_file, 'tor_data_dir')
config['tor_socks_port'] = config_helper.verify_integer_exists(config_file, 'tor_socks_port')
config['avg_delay'] = config_helper.verify_number_exists(config_file, 'avg_delay')
config['email_subject'] = config_helper.verify_string_exists(config_file, 'email_subject')

# Read gpgmailer watch directory from the gpgmailer config file
os.seteuid(escalated_uid)
os.setegid(escalated_gid)
gpgmailmessage.GpgMailMessage.configure()

# Non-root users cannot create files in /run, so create a directory that can be written to.
pid_mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR;  # Full access to user only.
if not os.path.isdir(pid_dir):
    os.makedirs(pid_dir, pid_mode)
os.chown(pid_dir, linuxUser.pw_uid, linuxGroup.gr_gid)
os.chmod(pid_dir, pid_mode)

# Configuration has been read. Now drop permissions forever.
os.initgroups(process_username, linuxGroup.gr_gid)
os.setgid(linuxGroup.gr_gid)
os.setuid(linuxUser.pw_uid)

# Make the Tor data directory
tor_dir_mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR;  # Full access to user only.
if not os.path.isdir(config['tor_data_dir']):
    logger.info('Creating Tor data directory.')
    os.makedirs(config['tor_data_dir'])
    os.makedirs(pid_dir, tor_dir_mode)
os.chown(config['tor_data_dir'], linuxUser.pw_uid, linuxGroup.gr_gid)
os.chmod(config['tor_data_dir'], tor_dir_mode)

prior_status = True # Start the program assuming the website is up.

# Set socks proxy and wrap the urllib module
# TODO: Consider choosing a randomly available TCP port.
socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', int(config['tor_socks_port']))
socket.socket = socks.socksocket

# Perform DNS resolution through the socket
def getaddrinfo(*args):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]

socket.getaddrinfo = getaddrinfo


def is_site_up(url):
    # Uses urllib to fetch a site using SocksiPy for Tor over the SOCKS_PORT.

    logger.debug("Checking our endpoint: ")
    try:
        urllib.urlopen(url).read()
        logger.debug("%s is up." % url)
        return True
    except Exception as detail:
        logger.warn("Unable to reach %s." % url)
        logger.warn("Exception: %s" % traceback.format_exc())
        return False

# Start an instance of Tor. This prints
# Tor's bootstrap information as it starts. Note that this will not
# work if you have another Tor instance running.
# TODO: Make it deal with another instance of Tor properly.
def print_bootstrap_lines(line):
    if "Bootstrapped " in line:
        logger.info("%s" % line);

logger.info("Starting Tor on port %s." % config['socks_port'])

tor_process = stem.process.launch_tor_with_config(
    config = {
        'SocksPort': str(config['socks_port']),
        'DataDirectory': config['tor_data_dir'],
#        'User': process_username,
    },
    init_msg_handler = print_bootstrap_lines,
    # TODO: The following doesn't work right with forking:
    #take_ownership = True
)

# Quit when SIGTERM is received
def sig_term_handler(signal, stack_frame):
    logger.info("Stopping tor.")
    tor_process.kill()
    sys.exit(0)

daemon_context = daemon.DaemonContext(
    working_directory = '/',
    pidfile = pidlockfile.PIDLockFile(os.path.join(pid_dir, pid_file)),
    umask = 0o117  # Read/write by user and group.
    )

daemon_context.signal_map = {
    signal.SIGTERM : sig_term_handler
    }

daemon_context.files_preserve = [config_helper.get_log_file_handle()]

# Set the UID and PID to parkbench-torwatchdog user and group.
daemon_context.uid = linuxUser.pw_uid
daemon_context.gid = linuxGroup.gr_gid

with daemon_context:
    try:
        # Init the secure random number generator
        randomGenerator = random.SystemRandom()  # Uses /dev/urandom
        logger.trace('Starting loop.')

        while(True):
            logger.trace('Sleeping!')

            # Let's not be too obvious here. Ramdomize the requests.
            time.sleep(random.uniform(0, int(config['avg_delay'])))

            logger.trace('Start checking url')
        
            current_status = is_site_up(config['url'])
            logger.trace('Done checking url.')

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

    except Exception as e:
        logger.critical("Fatal %s: %s\n" % (type(e).__name__, e.message))
        logger.error(traceback.format_exc())
        logger.info("Stopping tor.")
        tor_process.kill()
        sys.exit(1)
