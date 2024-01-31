# coding: latin-1
###############################################################################
# eVotUM - Electronic Voting System
#
# verifySignature-app.py
#
# Cripto-7.4.1 - Commmad line app to exemplify the usage of verifySignature
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
Command line app that receives signer's public key from file and Data, Signature, Blind Components and
prComponents from STDIN and writes a message to STDOUT indicating if the signature is valid..
"""

from eVotUM.Cripto import utils

import sys
from eVotUM.Cripto import eccblind


def printUsage():
    print("verify-app.py -cert <certificado do assinante> -msg <mensagem original a assinar> -sDash <Signature> -f <ficheiro do requerente>")

def parseArgs():
    if (len(sys.argv) != 9):
        printUsage()
    elif(sys.argv[1] != "-cert" or sys.argv[3] != "-msg" or sys.argv[5]!= "-sDash" or sys.argv[7] != "-f"):
        printUsage()
    else:
        eccPublicKeyPath = sys.argv[2]
        data = ' '.join(sys.argv[4:-4])
        sDash = sys.argv[-3]
        with open(sys.argv[-1], 'r') as f:
            requesterFile = f.read()
        main(eccPublicKeyPath, data, sDash, requesterFile)

def showResults(errorCode, validSignature):
    print("Output")
    if errorCode is None:
        if validSignature:
            print("Valid signature")
        else:
            print("Invalid signature")
    elif errorCode == 1:
        print("Error: it was not possible to retrieve the public key")
    elif errorCode == 2:
        print("Error: pR components are invalid")
    elif errorCode == 3:
        print("Error: blind components are invalid")
    elif errorCode == 4:
        print("Error: invalid signature format")


def main(eccPublicKeyPath, data, signature, requesterFile):
    pemPublicKey = utils.readFile(eccPublicKeyPath)

    # Store the content of the requester file in variables
    blindComponents = requesterFile[18:requesterFile.find('\n')]
    pRComponents = requesterFile[requesterFile.find('\n') + 15:]

    errorCode, validSignature = eccblind.verifySignature(pemPublicKey, signature, blindComponents, pRComponents, data)
    showResults(errorCode, validSignature)


if __name__ == "__main__":
    parseArgs()

