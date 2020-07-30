# torwatchdog

_torwatchdog_ is a daemon that checks the availability of an arbitrary URL through Tor and
sends encrypted notification emails using our gpgmailer daemon when the URL availability
changes.

_torwatchdog_ is licensed under the GNU GPLv3.

This is software is still in _beta_ and may not be ready for use in a production environment.

Bug fixes are welcome!

## Prerequisites
This software is currently only suported in Ubuntu 18.04.

Currently, the only supported method for installation of this project is building and
installing a Debian package. The rest of these instructions make the following assumptions:

*   You are familiar with using a Linux terminal.
*   You are somewhat familiar with using `debuild`.
*   `debhelper` is installed.

## Parkbench Dependencies

_torwatchdog_ depends on two other Parkbench projects which must be installed first:

*  [_parkbench-common_](https://github.com/park-bench/parkbench-common)
*  [_gpgmailer_](https://github.com/park-bench/gpgmailer)

## Steps to Build and Install

1.  Install 'tor' and the 'deb.torproject.org-keyring' by following the Tor Project's
    instructions located here: https://www.torproject.org/docs/debian.html.en At the time of
    this writing, the Tor Project's signing key for Apt packages is:
    A3C4 F0F9 79CA A22C DBA8  F512 EE8C BC9E 886D DD89
2.  Clone the repository and checkout the lastest release tag. (Do not build against the
    `master` branch. The `master` branch might not be stable.)
3.  Run `debuild` in the project root directory to build the package.
5.  Run `apt install /path/to/package.deb` to install the package. The daemon will attempt to
    start and fail. (This is expected.)
6.  Copy or rename the example configuration file
    `/etc/torwatchdog/torwatchdog.conf.example` to `/etc/torwatchdog/torwatchdog.conf`. Edit
    this file to enter the URL that should be monitored. Other settings can also be modified.
7.  Change the ownership and permissions of the configuration file:
```
chown root:torwatchdog /etc/torwatchdog/torwatchdog.conf
chmod u=rw,g=r,o= /etc/torwatchdog/torwatchdog.conf
```
8.  To ease system maintenance, add `torwatchdog` as a supplemental group to administrative
    users. Doing this will allow these users to view torwatchdog log files.
9.  Restart the daemon with `systemctl restart torwatchdog`. If the configuration file is
    valid, named correctly, and has the correct file permissions, the service will start
    successfully.

If the default TCP port of 6613 is in use, alter the port specified in
`/etc/torwatchdog/torwatchdog.conf` and `/etc/tor/instances/torwatchdogtor/torrc`.

## Updates

Updates may change configuration file options. So if you have a configuration file already,
check the current example file to make sure it has all the required options.
