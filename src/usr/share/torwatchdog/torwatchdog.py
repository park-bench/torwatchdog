#!/usr/bin/env python2

# Copyright 2015-2017 Joel Allen Luellwitz and Andrew Klapp
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

__author__ = 'Joel Luellwitz and Andrew Klapp'
__version__ = '0.8'

import confighelper
import ConfigParser
import datetime
import gpgmailmessage
import logging
import os
import random
import signal
import socket
import socks  # SocksiPy module
import stem.process
import sys
import time
import traceback
import urllib

PID_FILE = '/run/torwatchdog.pid'

# TODO: Eventually check to see if the network/internet connection is down.


def daemonize():

    # Fork the first time to make init our parent.
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write('Failed to make parent process init: %d (%s)' %
                         (e.errno, e.strerror))
        sys.exit(1)

    os.chdir('/')  # Change the working directory.
    os.setsid()  # Create a new process session.
    os.umask(0)

    # Fork the second time to make sure the process is not a session leader.
    #   This apparently prevents us from taking control of a TTY.
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write('Failed to give up session leadership: %d (%s)' %
                         (e.errno, e.strerror))
        sys.exit(1)

    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, sys.stdin.fileno())
    os.dup2(devnull, sys.stdout.fileno())
    os.dup2(devnull, sys.stderr.fileno())
    os.close(devnull)

    pid = str(os.getpid())
    pidFile = file(PID_FILE, 'w')
    pidFile.write('%s\n' % pid)
    pidFile.close()


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

# Read gpgmailer watch directory from the gpgmailer config file
gpgmailmessage.GpgMailMessage.configure()

# Make the Tor cache directory
if not os.path.exists(config['cache_dir']):
    logger.info('Creating Tor cache directory.')
    os.makedirs(config['cache_dir'])

prior_status = True  # Start the program assuming the website is up.

# Set socks proxy and wrap the urllib module
socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', int(config['socks_port']))
socket.socket = socks.socksocket


def getaddrinfo(*args):
    """Perform DNS resolution through the socket."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]

socket.getaddrinfo = getaddrinfo


def is_site_up(url):
    # Uses urllib to fetch a site using SocksiPy for Tor over the SOCKS_PORT.

    logger.debug('Checking our endpoint: ')
    try:
        urllib.urlopen(url).read()
        logger.debug('%s is up.' % url)
        return True
    except Exception:
        logger.warn('Unable to reach %s.' % url)
        # The current version of socksipy contains a bug that causes this
        #   message to raise the wrong kind of exception and print an unhelpful
        #   message. It has been fixed in Ubuntu 16.04.
        logger.trace('Exception: %s' % traceback.format_exc())
        return False


# TODO: Make this deal with another instance of Tor properly.
def print_bootstrap_lines(line):
    """Start an instance of Tor. This prints Tor's bootstrap information as it starts. Note
    that this will not work if you have another Tor instance running.
    """
    if 'Bootstrapped ' in line:
        logger.info('%s' % line)

logger.info('Starting Tor on port %s.' % config['socks_port'])

tor_process = stem.process.launch_tor_with_config(
    config={
        'SocksPort': str(config['socks_port']),
        'DataDirectory': config['cache_dir'],
    },
    init_msg_handler=print_bootstrap_lines,
)


# TODO: Delete the cache directory on exit.
def sig_term_handler(signal, stack_frame):
    """Quit when SIGTERM is received."""
    logger.info('SIGTERM received. Quitting.')
    logger.info('Stopping tor.')
    tor_process.kill()
    sys.exit(0)

signal.signal(signal.SIGTERM, sig_term_handler)

daemonize()
try:

    # Init the secure random number generator.
    randomGenerator = random.SystemRandom()  # Uses /dev/urandom.
    logger.trace('Starting loop.')

    while(True):
        logger.trace('Sleeping!')

        # Let's not be too obvious here. Ramdomize the requests.
        time.sleep(random.uniform(0, int(config['avg_delay'])))

        logger.trace('Start checking url')

        current_status = is_site_up(config['url'])
        logger.trace('Done checking url.')

        # Send e-mail if the site just went down.
        if not current_status and prior_status:
            logger.warn('Send down notification.')

            message = gpgmailmessage.GpgMailMessage()
            message.set_subject(config['subject'])
            message.set_body('Down notification for %s at %s.' % (config['url'],
                             datetime.datetime.now()))
            message.queue_for_sending()

        # Send e-mail if the site just came back up.
        if current_status and not prior_status:
            logger.info('Send up notification')

            message = gpgmailmessage.GpgMailMessage()
            message.set_subject(config['subject'])
            message.set_body('Up notification for %s at %s.' % (config['url'],
                             datetime.datetime.now()))
            message.queue_for_sending()
        prior_status = current_status

except Exception as exception:
    logger.critical('Fatal %s: %s\n%s' % (type(exception).__name__, exception.message,
                    traceback.format_exc()))
    logger.info('Stopping tor.')
    tor_process.kill()
    sys.exit(1)
