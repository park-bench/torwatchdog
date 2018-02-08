# torwatchdog

_torwatchdog_ is a daemon that checks availability of an arbitrary URL through
Tor and sends encrypted notification emails using our gpgmailer daemon when the availability changes.

torwatchdog is licensed under the GNU GPLv3.

Bug fixes are welcome!

## Prerequisites

The only current method of installation for our software is building and installing your own debian package. We make the following assumptions:

*    You are already familiar with using a Linux terminal.
*    You already know how to use GnuPG.
*    You are already somewhat familiar with using debuild.

**NOTICE:** Some distributions do not maintain secure and updated version of
Tor. Please manually add the Tor Project's Apt repository. Instructions are
here: https://www.torproject.org/docs/debian.html.en

At the time of this writing, the Tor Project's signing key for Apt packages
is: A3C4 F0F9 79CA A22C DBA8  F512 EE8C BC9E 886D DD89

## Parkbench Dependencies
_torwatchdog_ depends on two other pieces of the Parkbench project, which must be installed first:

1. [_confighelper_](https://github.com/park-bench/confighelper)
2. [_gpgmailer_](https://github.com/park-bench/gpgmailer)

## Steps to Build and Install

1.   Manually add the Tor Project's Apt repository to ensure you have a secure and updated version of Tor. Instructions located here: https://www.torproject.org/docs/debian.html.en
2.   Clone the latest release tag. (Do not clone the master branch. `master` may not be stable.)
3.   Use `debuild` in the project root directory to build the package.
4.   Use `dpkg -i` to install the package.
5.   Use `apt-get -f install` to resolve any missing dependencies. The daemon will attempt to start and fail. (This is expected.)
6.   Locate the example configuration file at `/etc/torwatchdog/torwatchdog.conf.example`. Copy or rename this file to `torwatchdog.conf` in the same directory. Edit this file to enter the Tor URL you want to monitor or to modify other settings.
7.   Restart the daemon with `service torwatchdog restart`. If the configuration file is valid and named correctly, the service will now start successfully.

## Updates

Updates may change configuration file options, so if you have a configuration file already, check that it has all of the required options in the current example file.

## Known Errors and Limitations

* If no Internet is available while daemonizing, the program will eventually fail to start.
