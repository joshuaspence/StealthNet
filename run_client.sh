#!/bin/sh

# Configuration
JRE=java
JRE_FLAGS="-enableassertions -enablesystemassertions"

# TODO: Get classpath
CLASSPATH=

# TODO: JAR file (specified relative to script)
CLIENT_JAR=

$JRE -classpath $CLASSPATH $JRE_FLAGS -jar $CLIENT_JAR
