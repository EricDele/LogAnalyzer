#! /usr/bin/python
# coding: utf-8

# ===================================================================#
# -------------------------------------------------------------------#
#                             LogAnalyzer                            #
# -------------------------------------------------------------------#
# *******************************************************************#
#                   Eric Deleforterie - 2017/12/01                   #
# -------------------------------------------------------------------#
#                          Notes/Comments                            #
#                                                                    #
# -------------------------------------------------------------------#
#                             HISTORY                                #
#    V0.0.1    Eric Deleforterie - 2017/12/01                        #
#              Creation and first features                           #
# ===================================================================#


# --------------------------------------------#
#             Packages Importation            #
# --------------------------------------------#
from __future__ import print_function
import os
import sys
import re
from datetime import datetime
import time
import json
from collections import defaultdict
from pprint import pprint

# --------------------------------------------#
#              Variables declaration          #
# --------------------------------------------#

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

global vg_configuration


class LogAnalyzer():

    def __init__(self, jsonConfiguration):
        self.configuration = jsonConfiguration['configuration']
        self.dateTimeFormat = self.configuration['dateTimeFormat']
        self.tresholdAlertingInMinutes = self.configuration['tresholdAlertingInMinutes']
        self.windowDateTimeFormat = self.configuration['windowDateTimeFormat']
        self.windowOpenServiceDateTime = datetime.time(datetime.strptime(self.configuration['windowOpenServiceDateTime'], self.configuration['windowDateTimeFormat']))
        self.windowCloseServiceDateTime = datetime.time(datetime.strptime(self.configuration['windowCloseServiceDateTime'], self.configuration['windowDateTimeFormat']))
        self.trailingDelay = float(self.configuration['trailingDelay'])
        self.logins = defaultdict(dict)
        self.stats = defaultdict(dict)
        self.file = jsonConfiguration['file']
        self.logFileDateTimeFormat = self.file['logFileDateTimeFormat']
        self.iterLines = re.compile(r"{}".format(self.file['regexp']['iterLines']), re.M).finditer
        self.iterLinesDetailStats = re.compile(r"{}".format(self.file['regexp']['iterLinesDetailStats']), re.M).finditer
        self.iterLinesDetailLogin = re.compile(r"{}".format(self.file['regexp']['iterLinesDetailLogin']), re.M).finditer

    def followingFile(self, file):
        line_terminators = ('\r\n', '\n', '\r')
        trailing = True
        while True:
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
                time.sleep(self.trailingDelay)

    def updateStats(self, lineReqBySec, lineBytesInBySec, lineBytesOutBySec, lineReqMicroSec):
        if('requestsBySeconds' not in self.stats):
            self.stats['requestsBySeconds'] = []
            self.stats['bytesInBySeconds'] = []
            self.stats['bytesOutBySeconds'] = []
            self.stats['requestDurationInSeconds'] = []
        self.stats['requestsBySeconds'].append(int(lineReqBySec))
        self.stats['bytesInBySeconds'].append(int(lineBytesInBySec))
        self.stats['bytesOutBySeconds'].append(int(lineBytesOutBySec))
        self.stats['requestDurationInSeconds'].append(float(lineReqMicroSec) / 1000000)

    def printStats(self):
        if('requestsBySeconds' in self.stats):
            print(BLUE + "\nStats for running periode from " + DEFAULT + self.startTime + BLUE +
                  " to " + DEFAULT + datetime.now().strftime(self.dateTimeFormat) + BLUE + " : \n" +
                  CYAN + "Average requests by second : " + YELLOW + str(reduce(lambda x, y: x + y, self.stats['requestsBySeconds']) / len(self.stats['requestsBySeconds'])) + "\n" +
                  CYAN + "Average bytes IN by second : " + YELLOW + str(reduce(lambda x, y: x + y, self.stats['bytesInBySeconds']) / len(self.stats['bytesInBySeconds'])) + "\n" +
                  CYAN + "Average bytes OUT by second : " + YELLOW + str(reduce(lambda x, y: x + y, self.stats['bytesOutBySeconds']) / len(self.stats['bytesOutBySeconds'])) + "\n" +
                  CYAN + "Average request duration by second : " + YELLOW + str(reduce(lambda x, y: x + y, self.stats['requestDurationInSeconds']) / len(self.stats['requestDurationInSeconds'])) +
                  DEFAULT)

    def updateLogin(self, lineLogTime, lineDatabase, lineUser, lineIpFrom, linePortFrom, lineActionType, lineDbCx, lineUserCx, lineTls):
        if(lineUserCx not in self.logins):
            self.logins[lineUserCx]['firstLoginTime'] = datetime.strptime(lineLogTime, self.file['logFileDateTimeFormat'])
            self.logins[lineUserCx]['numberOfLogins'] = 0
        if('ipFrom' not in self.logins[lineUserCx]):
            self.logins[lineUserCx]['ipFrom'] = defaultdict(dict)
        if(lineIpFrom not in self.logins[lineUserCx]['ipFrom']):
            self.logins[lineUserCx]['ipFrom'][lineIpFrom] = 0
        self.logins[lineUserCx]['lastLoginTime'] = datetime.strptime(lineLogTime, self.file['logFileDateTimeFormat'])
        self.logins[lineUserCx]['numberOfLogins'] += 1
        self.logins[lineUserCx]['ipFrom'][lineIpFrom] += 1

    def printLogins(self):
        print(BLUE + "\nStats for logins, periode from " + DEFAULT + self.startTime + BLUE +
              " to " + DEFAULT + datetime.now().strftime(self.dateTimeFormat) + BLUE + " : \n")
        for account in self.logins:
            print(BLUE + "Account : " + GREEN + account)
            print(CYAN + "First login time : " + YELLOW + self.logins[account]['firstLoginTime'].strftime(self.dateTimeFormat) + "\n" +
                  CYAN + "Last login time : " + YELLOW + self.logins[account]['lastLoginTime'].strftime(self.dateTimeFormat) + "\n" +
                  CYAN + "Number of logins : " + YELLOW + str(self.logins[account]['numberOfLogins']))
            for ipFrom in self.logins[account]['ipFrom']:
                print(CYAN + "Number of logins from " + YELLOW + ipFrom + CYAN + " : " + YELLOW + str(self.logins[account]['ipFrom'][ipFrom]) + DEFAULT)

    # def analyzeLog(self,lastTime, logTime, logUser, logDatabase, logIpFrom, logPortFrom, logActionType, db, user, tls):
    #     logDateTime = datetime.strptime(logTime, dateTimeFormat)
    #     timeDiff = logDateTime - lastTime
    #     if(((timeDiff.days * 24 * 60) + (timeDiff.seconds/60)) > thresholdLoginMinutes ):
    #         print(RED + "User " + user + " no new connection since " + str(thresholdLoginMinutes) + " minutes : " + str(lastTime))
    #     lastTime = logDateTime

    def start(self):
        self.startTime = datetime.now().strftime(self.dateTimeFormat)
        print(BLUE + "Start date : " + DEFAULT + self.startTime)
        with open(self.file['fileName'], "rb") as f:
            # Go to the END
            f.seek(0, os.SEEK_END)
            for line in self.followingFile(f):
                for match in self.iterLines(line):
                    lineLogTime, linePid, lineType, lineDetail = match.groups()
                    print(lineLogTime + "," + linePid + "," + lineType + "," + lineDetail)
                    if(lineType == 'Stats'):
                        for matchDetail in self.iterLinesDetailStats(lineDetail):
                            lineReqBySec, lineBytesInBySec, lineBytesOutBySec, lineReqMicroSec = matchDetail.groups()
                            print(BLUE + "Stats for the last minute : \n" +
                                  CYAN + "Average requests by second : " + YELLOW + lineReqBySec +
                                  CYAN + " Average bytes IN by second : " + YELLOW + lineBytesInBySec +
                                  CYAN + " Average bytes OUT by second : " + YELLOW + lineBytesOutBySec +
                                  CYAN + " Average request duration by second : " + YELLOW + str(float(lineReqMicroSec) / 1000000) + DEFAULT)
                            self.updateStats(lineReqBySec, lineBytesInBySec, lineBytesOutBySec, lineReqMicroSec)
                    elif(lineType[:4] == 'C-0x'):
                        for matchDetail in self.iterLinesDetailLogin(lineDetail):
                            lineDatabase, lineUser, lineIpFrom, linePortFrom, lineActionType, lineDbCx, lineUserCx, lineTls = matchDetail.groups()
                            if(lineActionType == 'login'):
                                print(GREEN + lineActionType + " : " + YELLOW + lineDbCx + CYAN + "/" + YELLOW + lineUserCx + CYAN + " from : " + YELLOW + lineIpFrom + DEFAULT)
                                self.updateLogin(lineLogTime, lineDatabase, lineUser, lineIpFrom, linePortFrom, lineActionType, lineDbCx, lineUserCx, lineTls)
                                # if(lineDb == 'ranger'):
                                # analyzeLog(lastTime, logTime,logUser, logDatabase, logIpFrom, logPortFrom, logActionType, db, user, tls)
                            # elif(logActionType == 'closing'):
                            #     print(logActionType + " : " + logDatabase + "/" + logUser)
                    else:
                        print("Unknow line type : " + line)

    def stop(self):
        print(BLUE + "\nEnd date : " + DEFAULT + str(datetime.now().strftime(self.dateTimeFormat)))


if __name__ == '__main__':
    reload(sys)
    sys.setdefaultencoding('utf8')
    # Get the configuration file
    with open('conf/LogAnalyzer.json') as jsonFile:
        jsonData = json.load(jsonFile)
    vg_configuration = jsonData
    # Initiate the object
    logAnalyzer = LogAnalyzer(vg_configuration)
    try:
        logAnalyzer.start()
    except KeyboardInterrupt:
        logAnalyzer.printStats()
        logAnalyzer.printLogins()
    finally:
        logAnalyzer.stop()
