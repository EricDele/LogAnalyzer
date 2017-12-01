#! /usr/bin/env python
import os
import re
from datetime import datetime
import time


DEFAULT = '\033[39m'
BLACK = '\033[30m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
BACK_RED = '\033[41m'
BACK_GREEN = '\033[42m'
BACK_YELLOW = '\033[43m'
BACK_BLUE = '\033[44m'
BACK_CYAN = '\033[46m'
BACK_GRAY = '\033[47m'
BACK_DEFAULT = '\033[49m'
dateTimeFormat = '%Y-%m-%d %H:%M:%S.%f'
thresholdLoginMinutes = 1
lastTime = actualTime = datetime.now()


# 2017-11-30 18:48:39.607 26538 LOG Stats: 209 req/s, in 560744 b/s, out 660303 b/s,query 11209 us
# 2017-11-30 17:38:23.156 26538 LOG C-0x12311d0: hue/hue@192.246.33.6:33224 login attempt: db=hue user=hue tls=no
# 2017-11-30 18:48:39.732 26538 LOG C-0x1242970: hue/hue@192.246.33.7:44679 closing because: client close request (age=12)

iter_lines = re.compile(r"^(?P<logTime>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) (?P<pid>\d+) LOG (?P<lineType>Stats|C-0x[0-9a-fA-F]+): (?P<lineDetail>.*)$", re.M).finditer
iter_line_detail_Stats = re.compile(r"^(?P<logReqBySec>\d+) req/s, in (?P<logBytesInBySec>\d+) b/s, out (?P<logBytesOutBySec>\d+) b/s,query (?P<logReqMicroSec>\d+) us$",re.M).finditer
iter_line_detail_Login = re.compile(r"^(?P<logUser>\w+)/(?P<logDatabase>\w+)@(?P<logIpFrom>\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3}):(?P<logPortFrom>\d+) (?P<logActionType>closing|login) (?:because|attempt): (?:db=(?P<db>\w+) user=(?P<user>\w+) tls=(?P<tls>\w+)|).*$",re.M).finditer

def followingFile(file, delay = 1.0):
    line_terminators = ('\r\n', '\n', '\r')
    trailing = True
    while 1:
        whereWeAre = file.tell()
        line = file.readline()
        if line:
            if trailing and line in line_terminators:
                # This is just the line terminator added to the end of the file
                # before a new line, ignore.
                trailing = False
                continue

            if line[-1] in line_terminators:
                line = line[:-1]
                if line[-1:] == '\r\n' and '\r\n' in line_terminators:
                    # found crlf
                    line = line[:-1]

            trailing = False
            yield line
        else:
            trailing = True
            file.seek(whereWeAre)
            time.sleep(delay)


def analyzeLog(lastTime, logTime, logUser, logDatabase, logIpFrom, logPortFrom, logActionType, db, user, tls):
    logDateTime = datetime.strptime(logTime,dateTimeFormat)
    timeDiff = logDateTime - lastTime
    if(((timeDiff.days * 24 * 60) + (timeDiff.seconds/60)) > thresholdLoginMinutes ):
        print(RED + "User " + user + " no new connection since " + str(thresholdLoginMinutes) + " minutes : " + str(lastTime)) 
    lastTime = logDateTime

if __name__ == '__main__':
    print(BLUE + "Start date : " + DEFAULT + str(actualTime))

    with open("/var/log/pgbouncer/pgbouncer.log", "rb") as f:
        f.seek(0,os.SEEK_END)
        for line  in followingFile(f):
#            print(line)
            for match in iter_lines(line):
                logTime, pid, lineType, lineDetail = match.groups()
                if(lineType == 'Stats'):
                    for matchDetail in iter_line_detail_Stats(lineDetail):
                        logReqBySec, logBytesInBySec, logBytesOutBySec, logReqMicroSec = matchDetail.groups()
                        print(BLUE + "Stats for the last minute : \n" + 
                                    CYAN + "Average requests by second : " + YELLOW + logReqBySec + 
                                    CYAN + " Average bytes IN by second : " + YELLOW + logBytesInBySec + 
                                    CYAN + " Average bytes OUT by second : "  + YELLOW + logBytesOutBySec + 
                                    CYAN + " Average request duration by second : "  + YELLOW + str(float(logReqMicroSec)/1000000) + DEFAULT)
                elif(lineType[:4] == 'C-0x'):
                    for matchDetail in iter_line_detail_Login(lineDetail):
                        logUser, logDatabase, logIpFrom, logPortFrom, logActionType, db, user, tls = matchDetail.groups()
                        if(logActionType == 'login'):
                            print(GREEN + logActionType + " : " + DEFAULT + db + "/" + user + CYAN + " from : " + DEFAULT + logIpFrom)
                            if(db == 'ranger'):
                                analyzeLog(lastTime, logTime,logUser, logDatabase, logIpFrom, logPortFrom, logActionType, db, user, tls)
                        # elif(logActionType == 'closing'):
                        #     print(logActionType + " : " + logDatabase + "/" + logUser)
                else:
                    print("Unknow line type : " + line)
