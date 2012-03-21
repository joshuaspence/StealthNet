#!/bin/sh

# Java configuration
JRE=java
JRE_FLAGS="-enableassertions -enablesystemassertions"

# ANT configuration
HAS_ANT=0
ANT="$(which ant) -quiet"
[ "$?" -eq 0 ] && HAS_ANT=1

# TODO: Get classpath
if [ HAS_ANT -eq 1 ]; then
	CLASSPATH=
else
	CLASSPATH=""
fi

# TODO: JAR file (specified relative to script)
if [ HAS_ANT -eq 1 ]; then
	SERVER_JAR=
else
	SERVER_JAR="`dirname $0`/build/classes/ELEC5616_server.jar"
fi

$JRE -classpath $CLASSPATH $JRE_FLAGS -jar $SERVER_JAR
