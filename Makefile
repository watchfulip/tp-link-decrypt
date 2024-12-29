# Directories
SRCDIR = src
OBJDIR = obj
BINDIR = bin

# Main program
MAIN = tp-link-decrypt

# Find all source files
SOURCES := $(shell find $(SRCDIR) -name '*.c')
OBJECTS := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Compiler and flags
CC = gcc
CFLAGS = -Wno-implicit-function-declaration -I$(SRCDIR)

# Main target
$(BINDIR)/$(MAIN): $(OBJECTS)
	@mkdir -p $(BINDIR)
	$(CC) $(OBJECTS) -o $@

# Rule for object files
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean rule
clean:
	rm -rf $(OBJDIR) $(BINDIR)

.PHONY: clean
