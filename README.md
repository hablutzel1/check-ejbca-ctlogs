# About

**IMPORTANT: The current quality of this project is just prototype level!**

This project connects to an EJBCA database and verifies that the CT Logs configuration is up to date with the intersection of the usable CT Logs lists published by Google and Apple in https://www.gstatic.com/ct/log_list/v3/log_list.json and https://valid.apple.com/ct/log_list/current_log_list.json respectively.

The exit status of this program is 0 (OK) if the configuration is up to date, 1 (WARNING) if the configuration is outdated and 2 (CRITICAL) if the configuration is invalid, which makes it appropriate to be used as a Nagios check.

# Installation

```
./gradlew installDist
```

# Usage

## Create a dedicated limited user

```
CREATE USER 'nagios'@'monitoringhost.example.org' IDENTIFIED BY 'secret';
GRANT SELECT ON ejbca.GlobalConfigurationData TO 'nagios'@'monitoringhost.example.org';
```

## Nagios configuration

It is suggested to make this a daily check. More frequency is not really needed.

In a dedicated server with NRPE server installed, add the following to `/etc/nagios/nrpe_local.cfg`:

```
command[check_ejbca_ctlogs]=/opt/check-ejbca-ctlogs/build/install/check-ejbca-ctlogs/bin/check-ejbca-ctlogs ejbcadbhost.example.org ejbca nagios 'secret'
```

Then, in the Nagios server, add the following to `/etc/nagios/nrpe.cfg`:
```
define service{
use                             daily-check-service
host_name                       monitoringhost.example.org
service_description             EJBCA CT Logs
check_command                   check_nrpe!check_ejbca_ctlogs
}
```

Here you can see output of the check for the OK status (exit status 0):

```
All logs common to Google and Apple are correctly configured in EJBCA.
```

And the WARNING status (exit status 1):

```
Missing in EJBCA CT logs: wjF+V0UZo0XufzjespBB68fCIVoiv3/Vta12mtkOUs0=, https://wyvern.ct.digicert.com/2026h2/, MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEenPbSvLeT+zhFBu+pqk8IbhFEs16iCaRIFb1STLDdWzL6XwTdTWcbOzxMTzB3puME5K3rT0PoZyPSM50JxgjmQ==, interval: 2026-07-01T00:00Z - 2027-01-01T00:00Z
```

And the CRITICAL status (exit status 2):

```
The temporal interval of the log with ID pELFBklgYVSPD9TqnPt6LSZFTYepfy/fRVn2J086hFQ= is different in EJBCA. Actual: 2025-07-01T00:00Z - 2026-01-06T00:00Z, Expected: 2025-07-01T00:00Z - 2026-01-07T00:00Z
```

# TODOS

- Support checking that all CT Logs of each operator are in the same EJBCA group.
