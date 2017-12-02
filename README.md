# LogAnalyzer


A log analyzer for the logfile of pgbouncer

You just have to set the path of the logfile in the *LogAnalyzer.json* file and run the *LogAnalyzer.py* script for collecting stats lines and all the logins stats.
When you stop the programm a report is print like this one :

```
Stats for running periode from 2017-12-02 23:22:13 to 2017-12-02 23:22:38 : 
Average requests by second : 0
Average bytes IN by second : 0
Average bytes OUT by second : 0
Average request duration by second : 0.0

Stats for logins, periode from 2017-12-02 23:22:13 to 2017-12-02 23:22:38 : 

Account : postgres
First login time : 2017-12-02 23:22:16
Last login time : 2017-12-02 23:22:27
Number of logins : 22
Number of logins from 192.168.1.16 : 22

End date : 2017-12-02 23:22:38

```
