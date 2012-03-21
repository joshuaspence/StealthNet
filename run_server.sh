#!/bin/sh

# Configuration
JRE=java
JRE_FLAGS="-enableassertions -enablesystemassertions"

# TODO: Get classpath
CLASSPATH=

# TODO: JAR file (specified relative to script)
SERVER_JAR=

$JRE -classpath $CLASSPATH $JRE_FLAGS -jar $SERVER_JAR
