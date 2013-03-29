#!/bin/sh

################################################################################
# Author: Joshua Spence
#
# Script to easily run a StealthNet client, proxy, server or bank.
################################################################################

#===============================================================================
# Java configuration
#===============================================================================
JRE=java
JRE_FLAGS="-enableassertions -enablesystemassertions"

#===============================================================================
# ANT configuration
#===============================================================================
ANT=$(which ant)
[ -n "$ANT" ] && HAS_ANT=1 || HAS_ANT=0

#===============================================================================
# Get JAR file (specified relative to script)
#===============================================================================
JAR_DIR=$(dirname $0)
if [ $HAS_ANT -eq 1 ]; then
	# Get JAR path from ant
	JAR_DIR="$JAR_DIR/$($ANT jar_dir | sed -n "s/.*JAR directory: '\(.*\)'/\1/p")"
else
	# Use default JAR path
	JAR_DIR="$JAR_DIR/build/jar"
fi

#===============================================================================
# Debug options for the program
#===============================================================================
DEBUG="\
-Ddebug.StealthNet=false \
\
-Ddebug.StealthNet.Bank=false \
-Ddebug.StealthNet.Bank.General=true \
-Ddebug.StealthNet.Bank.ErrorTrace=true \
\
-Ddebug.StealthNet.BankThread=false \
-Ddebug.StealthNet.BankThread.General=true \
-Ddebug.StealthNet.BankThread.ErrorTrace=true \
-Ddebug.StealthNet.BankThread.Commands=false \
-Ddebug.StealthNet.BankThread.Commands.Null=true \
-Ddebug.StealthNet.BankThread.Commands.Payment=true \
-Ddebug.StealthNet.BankThread.Commands.SignHashChain=true \
-Ddebug.StealthNet.BankThread.Commands.GetBalance=true \
-Ddebug.StealthNet.BankThread.Commands.DepositPayment=true \
-Ddebug.StealthNet.BankThread.AsymmetricEncryption=true \
-Ddebug.StealthNet.BankThread.Balances=true \
\
-Ddebug.StealthNet.Chat=false \
-Ddebug.StealthNet.Chat.General=true \
-Ddebug.StealthNet.Chat.ErrorTrace=true \
\
-Ddebug.StealthNet.Client=false \
-Ddebug.StealthNet.Client.General=true \
-Ddebug.StealthNet.Client.ErrorTrace=true \
-Ddebug.StealthNet.Client.Commands=false \
-Ddebug.StealthNet.Client.Commands.Msg=true \
-Ddebug.StealthNet.Client.Commands.Chat=true \
-Ddebug.StealthNet.Client.Commands.FTP=true \
-Ddebug.StealthNet.Client.Commands.List=true \
-Ddebug.StealthNet.Client.Commands.SecretList=true \
-Ddebug.StealthNet.Client.Commands.GetSecret=true \
-Ddebug.StealthNet.Client.Commands.GetPublicKey=true \
-Ddebug.StealthNet.Client.Commands.Payment=true \
-Ddebug.StealthNet.Client.Commands.RequestPayment=true \
-Ddebug.StealthNet.Client.Commands.GetBalance=true \
-Ddebug.StealthNet.Client.Commands.RequestPayment=true \
-Ddebug.StealthNet.Client.Commands.HashChain=true \
-Ddebug.StealthNet.Client.AsymmetricEncryption=true \
\
-Ddebug.StealthNet.Comms=false \
-Ddebug.StealthNet.Comms.General=true \
-Ddebug.StealthNet.Comms.ErrorTrace=true \
-Ddebug.StealthNet.Comms.PureOutput=false \
-Ddebug.StealthNet.Comms.DecodedOutput=true \
-Ddebug.StealthNet.Comms.EncryptedOutput=false \
-Ddebug.StealthNet.Comms.DecryptedOutput=false \
-Ddebug.StealthNet.Comms.RawOutput=false \
-Ddebug.StealthNet.Comms.ReceiveReady=false \
-Ddebug.StealthNet.Comms.Authentication=true \
-Ddebug.StealthNet.Comms.Encryption=true \
-Ddebug.StealthNet.Comms.Integrity=false \
-Ddebug.StealthNet.Comms.ReplayPrevention=false \
-Ddebug.StealthNet.Comms.AsymmetricEncryption=true \
\
-Ddebug.StealthNet.CryptoCreditHashChain=false \
-Ddebug.StealthNet.CryptoCreditHashChain.General=true \
-Ddebug.StealthNet.CryptoCreditHashChain.ErrorTrace=true \
\
-Ddebug.StealthNet.EncryptedFile=false \
-Ddebug.StealthNet.EncryptedFile.FileIO=true \
\
-Ddebug.StealthNet.FileTransfer=false \
-Ddebug.StealthNet.FileTransfer.General=true \
-Ddebug.StealthNet.FileTransfer.ErrorTrace=true \
-Ddebug.StealthNet.FileTransfer.Transfer=true \
\
-Ddebug.StealthNet.Proxy=false \
-Ddebug.StealthNet.Proxy.General=true \
-Ddebug.StealthNet.Proxy.ErrorTrace=true \
\
-Ddebug.StealthNet.ProxyComms=false \
-Ddebug.StealthNet.ProxyComms.General=true \
-Ddebug.StealthNet.ProxyComms.ErrorTrace=true \
-Ddebug.StealthNet.ProxyComms.RawOutput=true \
-Ddebug.StealthNet.ProxyComms.ReceiveReady=true \
\
-Ddebug.StealthNet.ProxyThread=false \
-Ddebug.StealthNet.ProxyThread.General=true \
-Ddebug.StealthNet.ProxyThread.ErrorTrace=true \
\
-Ddebug.StealthNet.Server=false \
-Ddebug.StealthNet.Server.General=true \
-Ddebug.StealthNet.Server.ErrorTrace=true \
\
-Ddebug.StealthNet.ServerThread=false \
-Ddebug.StealthNet.ServerThread.General=true \
-Ddebug.StealthNet.ServerThread.ErrorTrace=true \
-Ddebug.StealthNet.ServerThread.Commands=false \
-Ddebug.StealthNet.ServerThread.Commands.Null=true \
-Ddebug.StealthNet.ServerThread.Commands.Login=true \
-Ddebug.StealthNet.ServerThread.Commands.Message=true \
-Ddebug.StealthNet.ServerThread.Commands.Chat=true \
-Ddebug.StealthNet.ServerThread.Commands.FTP=true \
-Ddebug.StealthNet.ServerThread.Commands.CreateSecret=true \
-Ddebug.StealthNet.ServerThread.Commands.GetSecret=true \
-Ddebug.StealthNet.ServerThread.Commands.GetBalance=true \
-Ddebug.StealthNet.ServerThread.Commands.GetPublicKey=true \
-Ddebug.StealthNet.ServerThread.Commands.RequestPayment=true \
-Ddebug.StealthNet.ServerThread.Commands.Payment=true \
-Ddebug.StealthNet.ServerThread.Commands.HashChain=true \
-Ddebug.StealthNet.ServerThread.AsymmetricEncryption=true \
-Ddebug.StealthNet.ServerThread.Balances=true \
"

#===============================================================================
# Arguments to pass to the JRE
#===============================================================================
DEBUG_ARG=
ADDITIONAL_ARG=

#===============================================================================
# Get program command line options
#-------------------------------------------------------------------------------
# The command line options are:
#     * Mode of operation = [--bank | --client | --malicious-proxy | --proxy | --server ]
#     * Debug output = [ --debug | -d ]
#===============================================================================
PN=$(basename $0)
ARGS=$(getopt --name "$PN" --long bank,debug,client,malicious-proxy,proxy,server --options d -- "$@")
if [ $? -ne 0 ]; then
    echo "getopt failed!" >&2
    exit 1
fi
eval set -- $ARGS
while [ $# -gt 0 ]; do
    case $1 in
        -d | --debug)
            DEBUG_ARG=$DEBUG
            ;;

        --bank)
        	JAR_FILE=StealthNet_bank.jar
        	;;

        --client)
        	JAR_FILE=StealthNet_client.jar
        	;;

    	--malicious-proxy)
    		JAR_FILE=StealthNet_proxy.jar
    		ADDITIONAL_ARG="-DStealthNet.Proxy.Malicious=true"
        	;;

        --proxy)
        	JAR_FILE=StealthNet_proxy.jar
        	;;

        --server)
        	JAR_FILE=StealthNet_server.jar
        	;;

       	--)
            shift
            break
            ;;

	    *)
	        # terminate while loop
	        break
	        ;;
    esac
    shift
done

#===============================================================================
# Make sure a mode of operation (client/server/proxy/bank mode) was specified
#===============================================================================
if [ -z "$JAR_FILE" ]; then
	echo "You must specify bank (\`--bank'), client (\`--client'), malicious proxy (\`--malicious-proxy'), proxy (\`--proxy') or server (\`--server') mode." >&2
	exit 1
fi

#===============================================================================
# Execute the relevant command
#===============================================================================
# Echo the command before executing it
COMMAND="$JRE $DEBUG_ARG $ADDITIONAL_ARG $JRE_FLAGS -jar $JAR_DIR/$JAR_FILE $@"
echo "$COMMAND" && $COMMAND
