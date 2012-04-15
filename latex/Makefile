#################################################
# LaTeX makefile
# Author: Joshua Spence
#################################################

##################################################################
# Executables
##################################################################

ACROREAD		:= acroread
BACKGROUND		:= &
DELETE			:= rm -f
ECHO			:= echo
EVINCE			:= evince
FIND			:= find
IGNORE_RESULT 	:= -
LINK		  	:= ln -s
MAKE			:= make
MKDIR			:= mkdir -p
MUTE			:= @
SILENT			:= >/dev/null
SPACE 			:= $(empty) $(empty)
VERYSILENT		:= 1>/dev/null 2>/dev/null
XDVI		  	:= xdvi


##################################################################
# Configuration
##################################################################

MAIN_DOC		:= StealthNet

BUILD_DIR		:= build
EXT_DIR			:= ext
FIG_DIR			:= img
IMG_DIR			:= img
SRC_DIR			:= src
OUT_DIR			:= output

BIB_SRC			:= $(shell $(FIND) $(SRC_DIR) -type f -name "*.bib")
BST_SRC			:= $(shell $(FIND) $(EXT_DIR) -type f -name "*.bst")
FIG_SRC			:= $(shell $(FIND) $(FIG_DIR) -type f -name "*.eps" -o -name "*.png")
STY_SRC			:= $(shell $(FIND) $(EXT_DIR) -type f -name "*.sty") $(shell $(FIND) $(SRC_DIR) -type f -name "*.sty")
TEX_SRC			:= $(shell $(FIND) $(SRC_DIR) -type f -name "*.tex")


##################################################################
# Targets
##################################################################

# Main target
all: pre
	$(MUTE)$(MAKE) -C $(BUILD_DIR) $@
		
# To be run before make
pre: make-directories make-symlinks
	
# Make output directories
make-directories:
	$(IGNORE_RESULT)$(MUTE)$(ECHO) "Creating directories."
	$(MUTE)$(MKDIR) $(OUT_DIR)
	
# Make symbolic links
.PHONY: make-symlinks
make-symlinks: 
	$(IGNORE_RESULT)$(MUTE)$(ECHO) "Creating symbolic links."
	$(MUTE)$(LINK) $(foreach bib, $(BIB_SRC), "$(realpath $(bib))") $(BUILD_DIR)/ $(VERYSILENT) || true
	$(MUTE)$(LINK) $(foreach bst, $(BST_SRC), "$(realpath $(bst))") $(BUILD_DIR)/ $(VERYSILENT) || true
	$(MUTE)$(LINK) $(foreach sty, $(STY_SRC), "$(realpath $(sty))") $(BUILD_DIR)/ $(VERYSILENT) || true
	$(MUTE)$(LINK) $(foreach tex, $(TEX_SRC), "$(realpath $(tex))") $(BUILD_DIR)/ $(VERYSILENT) || true
	$(MUTE)$(LINK) "$(realpath $(IMG_DIR))" $(BUILD_DIR)/ $(VERYSILENT) || true

delete-out-directories:
	$(IGNORE_RESULT)$(MUTE)$(ECHO) "Deleting directories."
	$(MUTE)$(DELETE) -r $(OUT_DIR)
	
delete-build-files:
	$(IGNORE_RESULT)$(MUTE)$(ECHO) "Deleting files."
	$(MUTE)$(DELETE) $(shell find $(BUILD_DIR) -mindepth 1 \( -name Makefile \) -prune -o -print)

##################################################################

# Clean (removes build files but not output files)
.PHONY: clean
clean: delete-build-files
	$(MUTE)$(MAKE) -C $(BUILD_DIR) $@

# Dist-clean (also removes output files)
.PHONY: distclean
distclean: delete-out-directories delete-build-files
	$(MUTE)$(MAKE) -C $(BUILD_DIR) $@

##################################################################

# Portable Document Format (PDF) Output
pdf: pre
	$(MUTE)$(MAKE) -C $(BUILD_DIR) $@

##################################################################

# Read the PDF
.PHONY: read
read: pdf
	$(EVINCE) $(OUT_DIR)/$(MAIN_DOC).pdf $(BACKGROUND)

# Read the PDF using Acrobat
.PHONY: aread
aread: pdf
	$(ACROREAD) $(OUT_DIR)/$(MAIN_DOC).pdf $(BACKGROUND)
