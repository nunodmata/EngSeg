# coding: latin-1
###############################################################################
# eVotUM - Electronic Voting System
#
# generateBlindData-app.py
#
# Cripto-7.1.1 - Commmad line app to exemplify the usage of blindData
#       function (see eccblind.py)
#
# Copyright (c) 2016 Universidade do Minho
# Developed by André Baptista - Devise Futures, Lda. (andre.baptista@devisefutures.com)
# Reviewed by Ricardo Barroso - Devise Futures, Lda. (ricardo.barroso@devisefutures.com)
#
# Reviewed and tested with Python 3 @Jan/2021 by
#      José Miranda - Devise Futures, Lda. (jose.miranda@devisefutures.com)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
###############################################################################
"""
Command line app that receives Data and pRDashComponents from STDIN and writes
blindMessage and blindComponents and pRComponents to STDOUT.
"""

import sys
from eVotUM.Cripto import eccblind

def printUsage():
    print("Usage: python ofusca-app.py --msg message --RDash <pRDashComponents>")

def parseArgs():
    if (len(sys.argv) != 5):
        printUsage()
    elif (sys.argv[1] != "-msg" or sys.argv[3] != "-RDash"):
        printUsage()
    else:
        main()

def showResults(errorCode, result):
    print("Output")
    if (errorCode is None):
        blindComponents, pRComponents, blindM = result
        file = open("reqfile","w")
        file.write("blindComponents: " + blindComponents + "\n")
        file.write("pRComponents: " + pRComponents)
        print("Blind message: %s" % blindM)
        print("Components generated and saved!")
    elif (errorCode == 1):
        print("Error: pRDash components are invalid")

def main():
    data = sys.argv[2]
    pRDashComponents = sys.argv[4]
    errorCode, result = eccblind.blindData(pRDashComponents, data)
    showResults(errorCode, result)

if __name__ == "__main__":
    parseArgs()
