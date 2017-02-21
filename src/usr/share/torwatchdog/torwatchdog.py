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
import stem.process
import sys
import time
import traceback
import urllib

pid_file = '/run/torwatchdog.pid'

# TODO: Consider running in a chroot or jail.
# TODO: Check if network/internet connection is down

config_file = ConfigParser.SafeConfigParser()
config_file.read('/etc/torwatchdog/torwatchdog.conf')

# Logging config goes first
config_helper = confighelper.ConfigHelper()
log_file = config_helper.verify_string_exists_prelogging(config_file, 'log_file')
log_level = config_helper.verify_string_exists_prelogging(config_file, 'log_level')

config_helper.configure_logger(log_file, log_level)

logger = logging.getLogger()

logger.info('Verifying non-logging config')
config = {}

config['url'] = config_helper.verify_string_exists(config_file, 'url')
config['socks_port'] = config_helper.verify_integer_exists(config_file, 'socks_port')
config['avg_delay'] = config_helper.verify_number_exists(config_file, 'avg_delay')
config['subject'] = config_helper.verify_string_exists(config_file, 'subject')
config['cache_dir'] = config_helper.verify_string_exists(config_file, 'cache_dir')

# Make the Tor cache directory
if not os.path.exists(config['cache_dir']):
    logger.info('Creating Tor cache directory.')
    os.makedirs(config['cache_dir'])

prior_status = True # Start the program assuming the website is up.

# Set socks proxy and wrap the urllib module
socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', int(config['socks_port']))
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
        'DataDirectory': config['cache_dir'],
    },
    init_msg_handler = print_bootstrap_lines,
)

# Quit when SIGTERM is received
# TODO: Delete the cache directory on exit
def sig_term_handler(signal, stack_frame):
    logger.info("Stopping tor.")
    tor_process.kill()
    sys.exit(0)

# TODO: Work out a permissions setup for this program so that it doesn't run as root.
daemon_context = daemon.DaemonContext(
    working_directory = '/',
    pidfile = pidlockfile.PIDLockFile(pid_file),
    umask = 0o033
    )

daemon_context.signal_map = {
    signal.SIGTERM : sig_term_handler
    }

daemon_context.files_preserve = [config_helper.get_log_file_handle()]

# Set the UID and PID to parkbench-torwatchdog user and group.
try:
    linuxUser = pwd.getpwnam('parkbench-torwatchdog')
except KeyError as key_error:
    raise Exception('User parkbench-torwatchdog does not exist.', key_error)
daemon_context.uid = linuxUser.pw_uid
try:
    linuxGroup = grp.getgrnam('parkbench-torwatchdog')
except KeyError as key_error:
    raise Exception('Group parkbench-torwatchdog does not exist.', key_error)
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
                message.set_subject(config['subject'])
                message.set_body('Down notification for %s at %s.' % (config['url'], datetime.datetime.now()))
                message.queue_for_sending()
          
            # Send e-mail if the site just came back up
            if (current_status and not prior_status):
                logger.info("Send up notification")

                message = gpgmailmessage.GpgMailMessage()
                message.set_subject(config['subject'])
                message.set_body('Up notification for %s at %s.' % (config['url'], datetime.datetime.now()))
                message.queue_for_sending()
            prior_status = current_status

    except Exception as e:
        logger.critical("Fatal %s: %s\n" % (type(e).__name__, e.message))
        logger.error(traceback.format_exc())
        logger.info("Stopping tor.")
        tor_process.kill()
        sys.exit(1)
