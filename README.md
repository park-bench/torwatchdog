# Torwatchdog

Torwatchdog is a daemon that checks availability of an arbitrary URL through
Tor and sends encrypted notification emails using our gpgmailer daemon.

**NOTICE:** Some distributions do not maintain secure and updated version of
Tor. Please manually add the Tor Project's Apt repository. Instructions are
here: https://www.torproject.org/docs/debian.html.en

At the time of this writing, the Tor Project's signing key for Apt packages
is: A3C4 F0F9 79CA A22C DBA8  F512 EE8C BC9E 886D DD89

Torwatchdog is licensed under the GNU GPLv3.

Bug fixes are welcome.

This software is currently only supported on Ubuntu 14.04 and may not be ready
for use in a production environment.

The only current method of installation for our software is building and
installing your own package. We make the following assumptions:

*    You are already familiar with using a Linux terminal.
*    You already know how to use GnuPG.
*    You are already somewhat familiar with using debuild.

Clone the latest release tag, not the master branch, as master may not be
stable. Build the package with debuild from the project directory and install
with dpkg -i. Resolve any missing dependencies with apt-get -f install. The
daemon will attempt to start and fail.

Updates may change configuration file options, so if you have a configuration
file already, check that it has all of the required options in the current
example file.

## Post-install

Copy the example configuration file at
/etc/torwatchdog/torwatchdog.conf.example to /etc/torwatchdog/torwatchdog.conf
and make any necessary changes to it, then restart the daemon.
