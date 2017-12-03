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
import signal
import re
import argparse
from datetime import datetime
import time
import json
from collections import defaultdict
from pprint import pprint
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

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

global vg_arguments


class LogAnalyzer():
    """ Class for analyzing the pgbounce logfile
    """

    def __init__(self, configurationFile, verboseMode):
        """ Init methode
            :param arg1: configurationFile: path to the json configuration file 
            :param arg2: verboseMode: set the verbose mode or not
        """
        # Get the configuration file
        with open(configurationFile) as jsonFile:
            jsonConfiguration = json.load(jsonFile)
        self.configuration = jsonConfiguration['configuration']
        self.dateTimeFormat = self.configuration['dateTimeFormat']
        self.windowDateTimeFormat = self.configuration['windowDateTimeFormat']
        self.windowOpenServiceDateTime = datetime.time(datetime.strptime(self.configuration['windowOpenServiceDateTime'], self.windowDateTimeFormat))
        self.windowCloseServiceDateTime = datetime.time(datetime.strptime(self.configuration['windowCloseServiceDateTime'], self.windowDateTimeFormat))
        self.timeToSendEmailInformation = datetime.time(datetime.strptime(self.configuration['timeToSendEmailInformation'], self.windowDateTimeFormat))
        self.trailingDelay = float(self.configuration['trailingDelay'])
        self.logins = defaultdict(dict)
        self.stats = defaultdict(dict)
        self.file = jsonConfiguration['file']
        self.logFileDateTimeFormat = self.file['logFileDateTimeFormat']
        self.iterLines = re.compile(r"{}".format(self.file['regexp']['iterLines']), re.M).finditer
        self.iterLinesDetailStats = re.compile(r"{}".format(self.file['regexp']['iterLinesDetailStats']), re.M).finditer
        self.iterLinesDetailLogin = re.compile(r"{}".format(self.file['regexp']['iterLinesDetailLogin']), re.M).finditer
        self.usersToWatch = defaultdict(dict)
        for token in self.file['usersToWatchAndThresholdInMinutes'].split(","):
            userName, thresholdInMinutes = token.split(":")
            self.usersToWatch[userName]['thresholdInMinutes'] = int(thresholdInMinutes)
        self.verbose = verboseMode

    def followingFile(self, file):
        """ Methode to following the new datas in the logfile
            :param arg1: file: file descriptor
        """
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
            self.analyzeLog()

    def sendEmailInformation(self):
        """ Methode to send the Report Information Email
        """
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "[LogAnalyzer] Rapport de l'analyse du log de pgbouncer"
        msg['From'] = self.configuration['alertingEmail']['emailFrom']
        msg['To'] = self.configuration['alertingEmail']['emailTo']
        text = "Bonjour\nVoici le rapport de l'analyse du log de pgbouncer.\n\n{}\n{}".format(self.printStats(False), self.printLogins(False))
        html = """\
        <html>
          <head></head>
          <body>
            <p>Bonjour<br>
               Voici le rapport de l'analyse du log de pgbouncer.<br>
            </p>
            <p>{}</p>
            <p>{}</p>
          </body>
        </html>
        """.format(self.printStats(False).replace("\n", "<br>"), self.printLogins(False).replace("\n", "<br>"))
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        msg.attach(part1)
        msg.attach(part2)
        s = smtplib.SMTP(self.configuration['alertingEmail']['emailServer'])
        s.sendmail(msg['From'], msg['To'], msg.as_string())
        s.quit()

    def sendEmailAlerting(self, account, timeSinceLastLogin):
        """ Methode to send the Alert Email
            :param arg1: account: user concerned by the alert
            :param arg2: timeSinceLastLogin: duration since the last login
        """
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "[LogAnalyzer] ALERTE concernant le compte {} sans nouvelle connexion depuis plus de {} minutes".format(account, str(timeSinceLastLogin))
        msg['From'] = self.configuration['alertingEmail']['emailFrom']
        msg['To'] = self.configuration['alertingEmail']['emailTo']
        text = "Bonjour\nLe compte {} ne s'est pas connecté depuis plus de {} minutes.\n\n{}".format(account, str(timeSinceLastLogin), self.printLogins(False))
        html = """\
        <html>
          <head></head>
          <body>
            <p>Bonjour<br>
               Le compte {} ne s'est pas connecté depuis plus de {} minutes<br>
            </p>
            <p>
            {}
            </p>
          </body>
        </html>
        """.format(account, str(timeSinceLastLogin), self.printLogins(False).replace("\n", "<br>"))
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        msg.attach(part1)
        msg.attach(part2)
        s = smtplib.SMTP(self.configuration['alertingEmail']['emailServer'])
        s.sendmail(msg['From'], msg['To'], msg.as_string())
        s.quit()

    def updateStats(self, lineReqBySec, lineBytesInBySec, lineBytesOutBySec, lineReqMicroSec):
        """ Methode for updating Stats data
            :param arg1: lineReqBySec: average number of request by second
            :param arg2: lineBytesInBySec: average number of bytes going to the server by second
            :param arg3: lineBytesOutBySec: average number of bytes going to the client by second
            :param arg4: lineReqMicroSec: average request duration by micro second
        """
        if('requestsBySeconds' not in self.stats):
            self.stats['requestsBySeconds'] = []
            self.stats['bytesInBySeconds'] = []
            self.stats['bytesOutBySeconds'] = []
            self.stats['requestDurationInSeconds'] = []
        self.stats['requestsBySeconds'].append(int(lineReqBySec))
        self.stats['bytesInBySeconds'].append(int(lineBytesInBySec))
        self.stats['bytesOutBySeconds'].append(int(lineBytesOutBySec))
        self.stats['requestDurationInSeconds'].append(float(lineReqMicroSec) / 1000000)

    def printStats(self, verbose):
        """ Methode for printing the stats
            :param arg1: verbose: if True, use print else return the string
        """
        msgToUse = ""
        if('requestsBySeconds' in self.stats):
            msgToUse = BLUE + "\nStats for running periode from " + YELLOW + self.startTime + BLUE + " to " + YELLOW + datetime.now().strftime(self.dateTimeFormat) + BLUE + " : \n"
            msgToUse += CYAN + "Average requests by second : " + YELLOW + str(reduce(lambda x, y: x + y, self.stats['requestsBySeconds']) / len(self.stats['requestsBySeconds'])) + "\n"
            msgToUse += CYAN + "Average bytes IN by second : " + YELLOW + str(reduce(lambda x, y: x + y, self.stats['bytesInBySeconds']) / len(self.stats['bytesInBySeconds'])) + "\n"
            msgToUse += CYAN + "Average bytes OUT by second : " + YELLOW + str(reduce(lambda x, y: x + y, self.stats['bytesOutBySeconds']) / len(self.stats['bytesOutBySeconds'])) + "\n"
            msgToUse += CYAN + "Average request duration by second : " + YELLOW + str(reduce(lambda x, y: x + y, self.stats['requestDurationInSeconds']) / len(self.stats['requestDurationInSeconds'])) + DEFAULT + "\n"
        else:
            msgToUse = BLUE + "\nThere is " + RED + "no" + BLUE + " Stats for running periode from " + YELLOW + self.startTime + BLUE + " to " + YELLOW + datetime.now().strftime(self.dateTimeFormat) + DEFAULT + "\n"
        if(verbose):
            print(msgToUse)
        else:
            return msgToUse

    def updateLogin(self, lineLogTime, lineDatabase, lineUser, lineIpFrom, linePortFrom, lineActionType, lineDbCx, lineUserCx, lineTls):
        """ Methode for updating logins data in the object
            :param arg1: lineLogTime: timestamp from the log file
            :param arg2: lineDatabase: database pgbouncer side
            :param arg3: lineUser: user pgbouncer side
            :param arg4: lineIpFrom: Ip from the client side
            :param arg5: linePortFrom: Port from the client side
            :param arg6: lineActionType: Action type as login or closing
            :param arg7: lineDbCx: database server side
            :param arg8: lineUserCx: user server side
            :param arg9: lineTls: Tls used or not
        """
        if(lineUserCx not in self.logins):
            self.logins[lineUserCx]['firstLoginTime'] = datetime.strptime(lineLogTime, self.logFileDateTimeFormat)
            self.logins[lineUserCx]['numberOfLogins'] = 0
            self.logins[lineUserCx]['alerting'] = False
        if('ipFrom' not in self.logins[lineUserCx]):
            self.logins[lineUserCx]['ipFrom'] = defaultdict(dict)
        if(lineIpFrom not in self.logins[lineUserCx]['ipFrom']):
            self.logins[lineUserCx]['ipFrom'][lineIpFrom] = 0
        self.logins[lineUserCx]['lastLoginTime'] = datetime.strptime(lineLogTime, self.logFileDateTimeFormat)
        self.logins[lineUserCx]['numberOfLogins'] += 1
        self.logins[lineUserCx]['ipFrom'][lineIpFrom] += 1
        self.logins[lineUserCx]['alerting'] = False

    def printLogins(self, verbose):
        """ Methode for printing logins report
            :param arg1: verbose: if True, use print, if False return the string
        """
        msgToUse = ""
        if(len(self.logins)):
            msgToUse = BLUE + "\nStats for logins, periode from " + YELLOW + self.startTime + BLUE + " to " + YELLOW + datetime.now().strftime(self.dateTimeFormat) + BLUE + " : \n"
            for account in self.logins:
                msgToUse += BLUE + "Account : " + GREEN + account + "\n"
                msgToUse += CYAN + "First login time : " + YELLOW + self.logins[account]['firstLoginTime'].strftime(self.dateTimeFormat) + "\n" + CYAN + "Last login time : " + YELLOW + self.logins[account]['lastLoginTime'].strftime(self.dateTimeFormat) + "\n" + CYAN + "Number of logins : " + YELLOW + str(self.logins[account]['numberOfLogins']) + "\n"
                for ipFrom in self.logins[account]['ipFrom']:
                    msgToUse += CYAN + "Number of logins from " + YELLOW + ipFrom + CYAN + " : " + YELLOW + str(self.logins[account]['ipFrom'][ipFrom]) + DEFAULT + "\n"
        else:
            msgToUse = BLUE + "\nThere is " + RED + "no" + BLUE + " Stats for logins, periode from " + YELLOW + self.startTime + BLUE + " to " + YELLOW + datetime.now().strftime(self.dateTimeFormat) + DEFAULT + "\n"
        if(verbose):
            print(msgToUse)
        else:
            return msgToUse

    def alerting(self, account, timeSinceLastLogin):
        """ Methode for alerting depending of the option choosen in the configuration file
            :param arg1: account: account name
            :param arg2: timeSinceLastLogin: time since the last login of the user
        """
        if(self.file['alertingToUse'] == "print"):
            print(RED + "\nUser " + YELLOW + account + RED + " no new connection since more than " + YELLOW + str(int(timeSinceLastLogin.total_seconds() / 60)) + RED + " minutes \n" + DEFAULT)
        elif(self.file['alertingToUse'] == "email"):
            self.sendEmailAlerting(account, int(timeSinceLastLogin.total_seconds() / 60))

    def analyzeLog(self):
        """ Methode to analyze the data and issue an alert if we are in the service window
            This methode send the Information Report Email if we reach the tim to do it.
        """
        actualTime = datetime.strptime(datetime.now().strftime(self.dateTimeFormat), self.dateTimeFormat)
        if(actualTime.time() == self.timeToSendEmailInformation):
            self.sendEmailInformation()
        for account in self.logins:
            if(account in self.usersToWatch):
                timeSinceLastLogin = actualTime - self.logins[account]['lastLoginTime']
                if((timeSinceLastLogin.total_seconds() / 60) > self.usersToWatch[account]['thresholdInMinutes'] and not self.logins[account]['alerting']):
                    if(self.windowOpenServiceDateTime < actualTime.time() < self.windowCloseServiceDateTime):
                        self.logins[account]['alerting'] = True
                        self.alerting(account, timeSinceLastLogin)

    def start(self):
        """ Methode to start the log file following and update datas for each line of stats or login
        """
        self.startTime = datetime.now().strftime(self.dateTimeFormat)
        print(BLUE + "Start date : " + YELLOW + self.startTime + BLUE + " with pid : " + YELLOW + str(os.getpid()) + DEFAULT)
        with open(self.file['fileName'], "rb") as f:
            # Go to the END
            f.seek(0, os.SEEK_END)
            for line in self.followingFile(f):
                for match in self.iterLines(line):
                    lineLogTime, linePid, lineType, lineDetail = match.groups()
                    # print(lineLogTime + "," + linePid + "," + lineType + "," + lineDetail)
                    if(lineType == 'Stats'):
                        for matchDetail in self.iterLinesDetailStats(lineDetail):
                            lineReqBySec, lineBytesInBySec, lineBytesOutBySec, lineReqMicroSec = matchDetail.groups()
                            print(BLUE + "Stats for the last minute " + YELLOW + str(datetime.now().strftime(self.dateTimeFormat)) + " : \n" +
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
                    else:
                        print("Unknow line type : " + line)

    def stop(self):
        """ Methode called when we stop the execution, sending an Information Report Email
        """
        print(BLUE + "\nEnd date : " + YELLOW + str(datetime.now().strftime(self.dateTimeFormat)) + DEFAULT)
        # As we quit, we send an email if email is wanted
        if(self.file['alertingToUse'] == "email"):
            self.sendEmailInformation()


def programVersion():
    """ Print the program version
    """
    print("Version : 0.0.1")


def parseCommandLine():
    """ Parsing the command line option
    """
    global vg_arguments
    parser = argparse.ArgumentParser(
        description='Log analyzer for pgbouncer logfile', prog='LogAnalyzer')
    parser.add_argument('-v', '--version', action='store_true', default=False, help='print the version')
    parser.add_argument('-V', '--verbose', action='store_true', default=False, help='verbose mode')
    vg_arguments = vars(parser.parse_args())


def signalHanlder(signal, frame):
    """ Function to catch the SIGUSR1 and call the sendEmailInformation methode
    """
    logAnalyzer.sendEmailInformation()


if __name__ == '__main__':
    reload(sys)
    sys.setdefaultencoding('utf8')
    parseCommandLine()
    if vg_arguments['version']:
        programVersion()
        sys.exit
    # Initiate the object
    logAnalyzer = LogAnalyzer('conf/LogAnalyzer.json', vg_arguments['verbose'])
    # Cath the SIGUSR1 signal for sending Report Information Email
    signal.signal(signal.SIGUSR1, signalHanlder)
    try:
        logAnalyzer.start()
    except KeyboardInterrupt:
        logAnalyzer.printStats(logAnalyzer.verbose)
        logAnalyzer.printLogins(logAnalyzer.verbose)
    finally:
        logAnalyzer.stop()
