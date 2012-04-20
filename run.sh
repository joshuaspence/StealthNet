#!/bin/sh

#
# Author: Joshua Spence
# 
# Script to easily run a StealthNet client, proxy or server.
# 

# Java configuration
JRE=java
JRE_FLAGS="-enableassertions -enablesystemassertions"

# ANT configuration
ANT="$(which ant) -quiet"
[ "$?" -eq 0 ] && HAS_ANT=1 || HAS_ANT=0

# Get classpath
if [ $HAS_ANT -eq 1 ]; then
	# Get classpath from ant
	CLASSPATH=`$ANT classpath | sed -n "s/.*Classpath: '\(.*\)'/\1/p"`
else
	# Use default classpath
	CLASSPATH=""
fi

# Get JAR file (specified relative to script)
JAR_DIR=`dirname $0`
if [ $HAS_ANT -eq 1 ]; then
	# Get JAR path from ant
	JAR_DIR="$CLIENT_DIR`$ANT jar_dir | sed -n "s/.*JAR directory: '\(.*\)'/\1/p"`"
else
	# Use default JAR path
	JAR_DIR="$CLIENT_DIR/build/classes"
fi

# Debug options
DEBUG="\
-Ddebug.StealthNet=false \
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
\
-Ddebug.StealthNet.Comms=false \
-Ddebug.StealthNet.Comms.General=true \
-Ddebug.StealthNet.Comms.ErrorTrace=true \
-Ddebug.StealthNet.Comms.PureOutput=true \
-Ddebug.StealthNet.Comms.DecodedOutput=true \
-Ddebug.StealthNet.Comms.EncryptedOutput=true \
-Ddebug.StealthNet.Comms.DecryptedOutput=true \
-Ddebug.StealthNet.Comms.RawOutput=true \
-Ddebug.StealthNet.Comms.ReceiveReady=true \
-Ddebug.StealthNet.Comms.Authentication=true \
-Ddebug.StealthNet.Comms.Encryption=true \
-Ddebug.StealthNet.Comms.Integrity=true \
-Ddebug.StealthNet.Comms.ReplayPrevention=true \
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
-Ddebug.StealthNet.ServerThread.Commands.Logout=true \
-Ddebug.StealthNet.ServerThread.Commands.Message=true \
-Ddebug.StealthNet.ServerThread.Commands.Chat=true \
-Ddebug.StealthNet.ServerThread.Commands.FTP=true \
-Ddebug.StealthNet.ServerThread.Commands.CreateSecret=true \
-Ddebug.StealthNet.ServerThread.Commands.GetSecret=true \
"
DEBUG_ARG=
ADDITIONAL_ARG=

# Get program command line options
PN=`basename $0`
ARGS=`getopt --name "$PN" --long debug,client,malicious-proxy,proxy,server --options d -- "$@"`
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

# Make sure client or server mode was specified
if [ -z "$JAR_FILE" ]; then
	echo "You must specify client (\`--client'), malicious proxy (\`--malicious-proxy'), proxy (\`--proxy') or server (\`--server') mode." >&2
	exit 1
fi

# Execute the relevant command
if [ -n "$CLASSPATH" ]; then
	# Echo the command before executing it
	echo "$JRE $DEBUG_ARG $ADDITIONAL_ARG -classpath "$CLASSPATH" $JRE_FLAGS -jar $JAR_DIR/$JAR_FILE $@"
	echo ""
	$JRE $DEBUG_ARG $ADDITIONAL_ARG -classpath "$CLASSPATH" $JRE_FLAGS -jar $JAR_DIR/$JAR_FILE $@
else
	# Echo the command before executing it
	echo "$JRE $DEBUG_ARG $ADDITIONAL_ARG $JRE_FLAGS -jar $JAR_DIR/$JAR_FILE $@"
	echo ""
	$JRE $DEBUG_ARG $ADDITIONAL_ARG $JRE_FLAGS -jar $JAR_DIR/$JAR_FILE $@
fi
