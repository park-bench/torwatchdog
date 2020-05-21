#!/usr/bin/python3

# Copyright 2015-2020 Joel Allen Luellwitz
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

# Do this first to make race conditions less likely. Allows the parent process to kill by
#   process group ID.
# TODO: Determine if this is necessary.
import os
#os.setsid()

import re
import signal
import subprocess
import sys


def sig_term_handler(signal, stack_frame):  #pylint: disable=unused-argument
    """Signal handler for SIGTERM. Kills Tor and quits when SIGTERM is received.

    signal: Object representing the signal thrown.
    stack_frame: Represents the stack frame.
    """
    if tor_process is not None:
        tor_process.kill()
    sys.exit(0)


def write_line(output_line):
    """Writes a line to stdout but handles the case where the stdout pipe is closed. If a
    BrokenPipeError is raised, stdout is redirected to /dev/null.

    output_line: The line to write to stdout.
    """
    try:
        sys.stdout.write(output_line)
        sys.stdout.flush()
    except BrokenPipeError:
        # Python flushes standard streams on exit; redirect remaining output
        #   to devnull to avoid another BrokenPipeError at shutdown.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())


global tor_process

signal.signal(signal.SIGTERM, sig_term_handler)

command_and_arguments = sys.argv[1:].insert(0, 'tor')
tor_process = None
bootstrap_finished_regex = re.compile('(.*Bootstrapped 100%)(.*)')
try:
    tor_process = subprocess.Popen(
        command_and_arguments, stdout=subprocess.PIPE, stderr=sys.stderr, stdin=sys.stdin)
    while tor_process.poll() is None:
        output_line = tor_process.stdout.readline().decode('utf-8', 'replace').strip()
        bootstrap_finished_match = bootstrap_finished_regex.search(output_line)
        if not bootstrap_finished_match:
            write_line(output_line)
        else:
            # Alter the Tor output to the format that Ubuntu's python3-stem expects.
            write_line('%s: %s' % (
                bootstrap_finished_match.group(1), bootstrap_finished_match.group(2)))
    exit(tor_process.returncode)
finally:
    if tor_process:
        tor_process.kill()
