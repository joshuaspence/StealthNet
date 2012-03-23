#!/bin/sh

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

# Add -classpath prefix to classpath
[ -n "$CLASSPATH" ] && CLASSPATH="-classpath $CLASSPATH" || CLASSPATH=""

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
DEBUG="-Ddebug.StealthNet.StealthNetChat=true -Ddebug.StealthNet.StealthNetClient=true -Ddebug.StealthNet.StealthNetComms=true -Ddebug.StealthNet.StealthNetFileTransfer=true -Ddebug.StealthNet.StealthNetPacket=true -Ddebug.StealthNet.StealthNetServer=true -Ddebug.StealthNet.StealthNetServerThread=true"

# Execute
$JRE $DEBUG $CLASSPATH $JRE_FLAGS -jar $JAR_DIR/ELEC5616_server.jar $@
