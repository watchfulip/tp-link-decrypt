# Directories
SRCDIR = src
OBJDIR = obj
BINDIR = bin

# Main programs
MAIN = tp-link-decrypt
GEN = gen_keys_for_usr_conf_data

# By default, build both programs:
all: $(BINDIR)/$(MAIN) $(BINDIR)/$(GEN)

# Find all .c source files in SRCDIR (for tp-link-decrypt).
SOURCES := $(shell find $(SRCDIR) -name '*.c' -and -not -name 'gen_keys_for_usr_conf_data.c')
OBJECTS := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Compiler and flags
CC = gcc
CFLAGS = -Wno-implicit-function-declaration -I$(SRCDIR)

###############################################################################
# 1) Build the tp-link-decrypt program
###############################################################################
$(BINDIR)/$(MAIN): $(OBJECTS)
	@mkdir -p $(BINDIR)
	$(CC) $(OBJECTS) -o $@

###############################################################################
# 2) Build the gen_keys_for_usr_conf_data program
###############################################################################

$(BINDIR)/$(GEN): $(OBJDIR)/gen_keys_for_usr_conf_data.o
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $^ -o $@

# We already have a pattern rule for building .o from .c,
# so it will handle gen_keys_for_usr_conf_data.c automatically.

###############################################################################
# Pattern rule for any .c -> .o
###############################################################################
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(BINDIR)

.PHONY: clean all

