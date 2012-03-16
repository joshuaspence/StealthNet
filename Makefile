################################################################################
# Makefile for StealthNet.
#
# Adapted from http://www.makelinux.net/make3/make3-CHP-9-SECT-2
################################################################################

#-------------------------------------------------------------------------------
# Location of trees.
#-------------------------------------------------------------------------------
DOCS_DIR    := docs
IMAGE_DIR   := img
SOURCE_DIR  := src
OUTPUT_DIR  := classes

JAVA_CLASS_CLIENT := StealthNetClient
JAVA_CLASS_SERVER := StealthNetServer

# Jars

# Set the Java classpath
class_path := OUTPUT_DIR                             \
			  IMAGE_DIR

# space - A blank space
space := $(empty) $(empty)


#-------------------------------------------------------------------------------
# Unix tools
#-------------------------------------------------------------------------------
AWK         := awk
FIND        := find
LN          := ln -s
MKDIR       := mkdir -p
READLINK    := readlink -f
RM          := rm -rf
SHELL       := /bin/bash


#-------------------------------------------------------------------------------
# Path to support tools
#-------------------------------------------------------------------------------


#-------------------------------------------------------------------------------
# Java tools
#-------------------------------------------------------------------------------
JAVA             := java
JAVAC            := javac
JFLAGS           := -sourcepath $(SOURCE_DIR)        \
                    -d $(OUTPUT_DIR)
JFLAGS_DEBUG     := -g
JFLAGS_VERBOSE   := -verbose
JVM              := $(JAVA)
JVMFLAGS         := -enableassertions                \
                    -enablesystemassertions
JVMFLAGS_VERBOSE := -verbose
JAR              := jar
JARFLAGS         := cf
JAVADOC          := javadoc
JDFLAGS          := -sourcepath $(SOURCE_DIR)        \
                    -d $(DOCS_DIR)

#-------------------------------------------------------------------------------
# Functions
#-------------------------------------------------------------------------------
# $(call build-classpath, variable-list)
define build-classpath
$(strip                                              \
  $(patsubst :%,%,                                   \
    $(subst : ,:,                                    \
      $(strip                                        \
        $(foreach j,$1,$(call get-file,$j):)))))
endef

# $(call get-file, variable-name)
define get-file
  $(strip                                            \
    $($1)                                            \
    $(if $(call file-exists-eval,$1),,               \
      $(warning The file referenced by variable      \
                '$1' ($($1)) cannot be found)))
endef

# $(call file-exists-eval, variable-name)
define file-exists-eval
  $(strip                                       \
    $(if $($1),,$(warning '$1' has no value))   \
    $(wildcard $($1)))
endef

# $(call brief-help, makefile)
define brief-help
  $(AWK) '$$1 ~ /^[^.$$][-A-Za-z0-9]*:/                 \
         { print substr($$1, 1, length($$1)-1) }' $1 |  \
  uniq |                                                \
  sort |                                                \
  pr -T -w 80 -4
endef

# $(call file-exists, wildcard-pattern)
file-exists = $(wildcard $1)

# $(call check-file, file-list)
define check-file
  $(foreach f, $1,                              \
    $(if $(call file-exists, $($f)),,           \
      $(warning $f ($($f)) is missing)))
endef

# #(call make-temp-dir, root-opt)
define make-temp-dir
  mktemp -t $(if $1,$1,make).XXXXXXXXXX
endef

# $(call make-jar,jar-variable-prefix)
define make-jar
  .PHONY: $1 $$($1_name)
  $1: $($1_name)
  $$($1_name):
        cd $(OUTPUT_DIR); \
        $(JAR) $(JARFLAGS) $$(notdir $$@) $$($1_packages)
        $$(call add-manifest, $$@, $$($1_name), $$($1_manifest))
endef

################################################################################

# Set the CLASSPATH
export CLASSPATH := $(call build-classpath, $(class_path))

# make-directories - Ensure output directory exists.
make-directories := $(shell $(MKDIR) $(OUTPUT_DIR) $(DOCS_DIR))

# help - The default goal. Simply prints out a list of the possible make targets
.PHONY: help
help:
	@$(call brief-help, $(CURDIR)/Makefile)

# all - Perform all tasks for a complete build
.PHONY: all
all: compile jars javadoc

# debug - Perform all tasks for a complete debug build
.PHONY: debug
debug: JFLAGS += $(JFLAGS) $(JFLAGS_DEBUG)
debug: all

# verbose - Enable verbose output
.PHONY: verbose
verbose: JFLAGS   += $(JFLAGS_VERBOSE)
verbose: JVMFLAGS += $(JVMFLAGS) $(JVMFLAGS_VERBOSE)

# all_javas - Temp file for holding source file list
all_javas := $(OUTPUT_DIR)/all.javas

# compile - Compile the source
.PHONY: compile
compile: $(all_javas) make_links
	$(JAVAC) $(JFLAGS) @$<

# all_javas - Gather source file list
.INTERMEDIATE: $(all_javas)
$(all_javas):
	$(FIND) $(SOURCE_DIR) -name '*.java' > $@

# jar_list - List of all jars to create
jar_list := 

# jars - Create all jars
.PHONY: jars
jars: $(jar_list)

# make_links - Makes symbolic links
.PHONY: make_links
make_links: $(OUTPUT_DIR)/img

$(OUTPUT_DIR)/img:
	$(LN) `$(READLINK) $(IMAGE_DIR)` $(OUTPUT_DIR)

# javadoc - Generate the Java doc from sources
javadoc: $(all_javas)
	$(JAVADOC) $(JDFLAGS) @$<

# clean - Remove output files
.PHONY: clean
clean:
	$(RM) $(OUTPUT_DIR)
	$(RM) $(DOCS_DIR)

# classpath - Print the classpath
.PHONY: classpath
classpath:
	@echo CLASSPATH='$(CLASSPATH)'

# run_client - Execute StealthNet client
.PHONY: run_client
run_client: compile
	$(JVM) $(JVM_OPTIONS) -classpath $(CLASSPATH) $(JAVA_CLASS_CLIENT)

# run_server - Execute StealthNet server
.PHONY: run_server
run_server: compile
	$(JVM) $(JVM_OPTIONS) -classpath $(CLASSPATH) $(JAVA_CLASS_SERVER)

# run - Execute a StealthNet client and a StealthNet server
.PHONY: run
run: run_client run_server
