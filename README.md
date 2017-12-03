# LogAnalyzer


A log analyzer for the logfile of **pgbouncer**

You just have to set the path of the logfile in the **LogAnalyzer.json** file and run the **LogAnalyzer.py** script for collecting stats lines and all the logins stats.

You should collect informations on logins and stats and receive one by day an Information Report Email on the usage of the pgbouncer pools. 

One of the main goal of this script is to ensure that a user connect to a database during a service window.
If during this service windows the user doesn't connect during a time laps of X minutes configured in the **usersToWatchAndThresholdInMinutes** parameter, then an alert is issued depending of the parameter **alertingToUse** (print to the screen or sending an email)

## Configuration file

```json
{
    "configuration": {
        "dateTimeFormat": "%Y-%m-%d %H:%M:%S",        
        "windowDateTimeFormat": "%H:%M:%S",
        "windowOpenServiceDateTime": "08:00:00",
        "windowCloseServiceDateTime": "19:00:00",
        "timeToSendEmailInformation": "19:00:00",
        "trailingDelay": 1.0,
        "alertingEmail":
        {
            "emailFrom": "eric@example.org",
            "emailTo": "eric@example.org",
            "emailServer": "localhost"
        }
    },
    "file" :
    {
        "fileName": "/var/log/postgresql/pgbouncer.log",
        "logFileDateTimeFormat": "%Y-%m-%d %H:%M:%S.%f",
        "regexp":
        {
            "iterLines": "^(?P<lineLogTime>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3}) (?P<linePid>\\d+) LOG (?P<lineType>Stats|C-0x[0-9a-fA-F]+): (?P<lineDetail>.*)$",
            "iterLinesDetailStats": "^(?P<lineReqBySec>\\d+) req/s, in (?P<lineBytesInBySec>\\d+) b/s, out (?P<lineBytesOutBySec>\\d+) b/s,query (?P<lineReqMicroSec>\\d+) us$",
            "iterLinesDetailLogin": "^(?P<lineDatabase>\\w+)/(?P<lineUser>\\w+)@(?P<lineIpFrom>\\d{0,3}\\.\\d{0,3}\\.\\d{0,3}\\.\\d{0,3}):(?P<linePortFrom>\\d+) (?P<lineActionType>closing|login) (?:because|attempt): (?:db=(?P<lineDbCx>\\w+) user=(?P<lineUserCx>\\w+) tls=(?P<lineTls>\\w+)|).*$"
        },
        "usersToWatchAndThresholdInMinutes": "postgres:1,poc:5",
        "alertingType": "print|email",        
        "alertingToUse": "print"
    }
}
```
### Parameter you should change for your needs
- windowOpenServiceDateTime   : window open edge for alerting
- windowCloseServiceDateTime  : window close edge for alerting
- timeToSendEmailInformation  : time for sending the Report Information Email
- alertingEmail : email configuration to match your configuration
- fileName  : complete path to your pgbouncer.log file
- usersToWatchAndThresholdInMinutes : list of users to watch and there threshold maximum limit in minutes between 2 connections 
- alertingToUse : type of alerting to use, *print* to screen or send an *email*


## Usage

```shell
usage: LogAnalyzer [-h] [-v] [-V]

Log analyzer for pgbouncer logfile

optional arguments:
  -h, --help     show this help message and exit
  -v, --version  print the version
  -V, --verbose  verbose mode
```

## Stopping the program

When you stop the programm, by hitting **CTRL-C**, a report is print like this one and an email is send to the email adrress in the configuration file:

```
Stats for running periode from 2017-12-03 19:15:39 to 2017-12-03 19:16:53 : 
Average requests by second : 41
Average bytes IN by second : 17628
Average bytes OUT by second : 7835
Average request duration by second : 0.0696525

Stats for logins, periode from 2017-12-03 19:15:39 to 2017-12-03 19:16:53 : 
Account : postgres
First login time : 2017-12-03 19:15:42
Last login time : 2017-12-03 19:16:17
Number of logins : 55
Number of logins from 192.168.1.16 : 55

End date : 2017-12-03 19:16:53

```
## Generating an Information Report Email during execution

when starting the programm print eh start date and the **PID**, for receiving an Information Report Email you just have to send a **SIGUSR1** signal to the process using its **PID** for receiving the email.

```shell
# ./LogAnalyzer.py --verbose
Start date : 2017-12-03 18:53:14 with pid : 7298

# kill -s SIGUSR1  7298
```