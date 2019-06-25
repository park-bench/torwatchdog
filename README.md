# torwatchdog

_torwatchdog_ is a daemon that checks the availability of an arbitrary URL through Tor and
sends encrypted notification emails using our gpgmailer daemon when the availability changes.

torwatchdog is licensed under the GNU GPLv3.

This is software is still in _beta_ and may not be ready for use in a production environment.

Bug fixes are welcome!

## Prerequisites

Currently, the only supported method for installation of this project is building and
installing a Debian package. The rest of these instructions make the following assumptions:

*   Your server is running Ubuntu 18.04 LTS. (Other operating systems may work, but are not
    supported.)
*   `build-essential` is installed on your build server.
*   `devscripts` is installed on your build server.
*   You are already familiar with using a Linux terminal.
*   You are familiar with using `git` and GitHub.
*   You already know how to use GnuPG.
*   You are already somewhat familiar with using `debuild`.

**NOTICE:** Some distributions, including Ubuntu, do not maintain a secure and updated
version of Tor. Please manually add the Tor Project's Apt repository. Instructions are
here: https://www.torproject.org/docs/debian.html.en

At the time of this writing, the Tor Project's signing key for Apt packages
is: A3C4 F0F9 79CA A22C DBA8  F512 EE8C BC9E 886D DD89

## Parkbench Dependencies

_torwatchdog_ depends on two other Parkbench projects which must be installed first:

1.  [_parkbench-common_](https://github.com/park-bench/parkbench-common)
2.  [_gpgmailer_](https://github.com/park-bench/gpgmailer)

## Steps to Build and Install

1.  Manually add the Tor Project's Apt repository to ensure you have a secure and updated
    version of Tor. Instructions located here:
    https://www.torproject.org/docs/debian.html.en
2.  Clone the repository and checkout the lastest release tag. (Do not build against the
    `master` branch. The `master` branch might not be stable.)
3.  Use `debuild` in the project root directory to build the package.
4.  Use `dpkg -i` to install the package.
5.  Run `apt-get -f install` to resolve any missing dependencies. The daemon will attempt to
    start and fail. (This is expected.)
6.  Copy or rename the example configuration file
    `/etc/torwatchdog/torwatchdog.conf.example` to `/etc/torwatchdog/torwatchdog.conf`. Edit
    this file to enter the Tor URL you want to monitor. Other settings can also be modified.
7.  Use `chmod` to clear the _other user_ permissions bits of `watchman.conf`. Namely, remove
    read, write, and execute permissions for _other_.
8.  To ease system maintenance, add `torwatchdog` as a supplemental group to administrative
    users. Doing this will allow these users to view torwatchdog log files.
9.  Restart the daemon with `systemctl restart torwatchdog`. If the configuration file is
    valid, named correctly, and has the correct file permissions, the service will start
    successfully.

## Updates

Updates may change configuration file options. So if you have a configuration file already,
check the current example file to make sure it has all the required options.
