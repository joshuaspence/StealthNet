#!/bin/sh

# Java configuration
JRE=java
JRE_FLAGS="-enableassertions -enablesystemassertions"

# ANT configuration
HAS_ANT=0
ANT=$(which ant)
[ "$?" -eq 0 ] && HAS_ANT=1

# TODO: Get classpath
if [ HAS_ANT -eq 1 ]; then
	CLASSPATH=
else
	CLASSPATH=""
fi

# TODO: JAR file (specified relative to script)
if [ HAS_ANT -eq 1 ]; then
	CLIENT_JAR=
else
	CLIENT_JAR="`dirname $0`/build/classes/ELEC5616_client.jar"
fi

$JRE -classpath $CLASSPATH $JRE_FLAGS -jar $CLIENT_JAR
