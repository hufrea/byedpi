# TARGET = ciadpi
#
# CPPFLAGS = -D_DEFAULT_SOURCE
# CFLAGS += -I. -std=c99 -O2 -Wall -Wno-unused -Wextra -Wno-unused-parameter -pedantic
# WIN_LDFLAGS = -lws2_32 -lmswsock
#
# HEADERS = conev.h desync.h error.h extend.h kavl.h mpool.h packets.h params.h proxy.h win_service.h
# SRC = packets.c main.c conev.c proxy.c desync.c mpool.c extend.c
# WIN_SRC = win_service.c
#
# OBJ = $(SRC:.c=.o)
# WIN_OBJ = $(WIN_SRC:.c=.o)

# Path you your toolchain installation, leave empty if already in system PATH
# TOOLCHAIN_PATH =
###############################################################################

# Project specific
SRC_DIR = .
INC_DIR = .
BUILD_DIR = Build
DEBUG_DIR = Debug
RELEASE_DIR = Release
OBJ_DIR = Obj
TARGET = ciadpi
# PREFIX = $(HOME)/.local
PREFIX = /usr/local
INSTALL_DIR = $(DESTDIR)$(PREFIX)/bin/
# Some_nonebin_Lib =

# Toolchain
ifdef TOOLCHAIN_PATH
CC = $(TOOLCHAIN_PATH)/gcc
Cp = $(TOOLCHAIN_PATH)/g++
AS = $(TOOLCHAIN_PATH)/gcc -x assembler-with-cpp
CP = $(TOOLCHAIN_PATH)/objcopy
SZ = $(TOOLCHAIN_PATH)/size -d -G
else
CC = gcc
Cp = g++
AS = gcc -x assembler-with-cpp
CP = objcopy
SZ = size -d -G
endif

# Project sources
# CXX_FILES = $(wildcard $(SRC_DIR)/*.c) $(wildcard $(SRC_DIR)/*/*.c)
CXX_FILES = packets.c main.c conev.c proxy.c desync.c mpool.c extend.c
WIN_SRC = win_service.c
# LD_SCRIPT =
# Project includes
INCLUDES   = -I$(INC_DIR)

# ifdef Some_nonebin_Lib
# CXX_FILES += $(wildcard $(Some_nonebin_Lib)/*.c)
# CPP_FILES += $(wildcard $(Some_nonebin_Lib)/*.cpp)
# INCLUDES  += -I$(Some_nonebin_Lib)
# endif
# Compiler Flags

# GCC

# ifdef DEBUG
# $(info [info] debug mode)
# CFLAGS  = -g -Og
# BUILD_MODE = $(DEBUG_DIR)
# else
# $(info [info] nodebug mode)
# CFLAGS  = -O2
# BUILD_MODE = $(RELEASE_DIR)
# endif
CFLAGS = $(INCLUDES)
CFLAGS += -std=c99 -Wall -Wno-unused -Wextra -Wno-unused-parameter -pedantic
# Generate dependency information
CFLAGS += -MMD -MP
CPPFLAGS = -D_DEFAULT_SOURCE
WIN_LDFLAGS = -lws2_32 -lmswsock

#  -MF"$(@:%.o=%.d)"
# PROJECT

# Linker Flags
# LFLAGS = -Wl,--gc-sections -Wl,-T$(LD_SCRIPT) --specs=rdimon.specs

###############################################################################

# Unlike the original source, this file throws object files into the correct directory.
OBJECTS  = $(addprefix $(BUILD_DIR)/$(OBJ_DIR)/,$(notdir $(CXX_FILES:.c=.o)))
WIN_OBJ  = $(addprefix $(BUILD_DIR)/$(OBJ_DIR)/,$(notdir $(WIN_SRC:.c=.o)))
DEPENDS  = $(addprefix $(BUILD_DIR)/$(OBJ_DIR)/,$(notdir $(CXX_FILES:.c=.d)))
WIN_DEP  = $(addprefix $(BUILD_DIR)/$(OBJ_DIR)/,$(notdir $(WIN_SRC:.c=.d)))

.PHONY: clean
vpath %.c $(sort $(dir $(CXX_FILES)))
vpath %.c $(sort $(dir $(WIN_SRC)))
# .PHONY: clean
all: CFLAGS += -O2
all: $(BUILD_DIR)/$(TARGET)

windows: CFLAGS += -O2
windows: $(BUILD_DIR)/$(TARGET).exe

debug: CFLAGS += -g -Og -DDEBUG
debug: $(BUILD_DIR)/$(TARGET)

windows_debug: CFLAGS += -g -Og -DDEBUG
windows_debug: $(BUILD_DIR)/$(TARGET).exe

-include $(DEPENDS)

# Compile c
$(BUILD_DIR)/$(OBJ_DIR)/%.o: %.c Makefile | $(BUILD_DIR)/$(OBJ_DIR)
	@echo "[CC] $< -> $@"
	@$(CC) -c $< -o $@ $(CPPFLAGS) $(CFLAGS)

# Link

$(BUILD_DIR)/$(TARGET).exe: $(OBJECTS) $(WIN_OBJ) Makefile
	@echo "[LD] $@"
	@$(CC) -o $@ $(OBJECTS) $(WIN_OBJ)

$(BUILD_DIR)/$(TARGET): $(OBJECTS) Makefile
	@echo "[LD] $@"
	@$(CC) -o $@ $(OBJECTS)
	@$(SZ) $@


$(BUILD_DIR)/$(OBJ_DIR): | $(BUILD_DIR)
	@mkdir $@

$(BUILD_DIR):
	@mkdir $@

# Clean
clean:
	@rm $(BUILD_DIR)/$(TARGET)* $(BUILD_DIR)/$(OBJ_DIR)/*
# @rm $(BUILD_DIR)/$(DEBUG_DIR)/$(TARGET)* \
# 	$(BUILD_DIR)/$(RELEASE_DIR)/$(TARGET)* \
# 	$(BUILD_DIR)/$(DEBUG_DIR)/$(OBJ_DIR)/* \
# 	$(BUILD_DIR)/$(RELEASE_DIR)/$(OBJ_DIR)/*
#
#
# clean:
# 	rm -f $(TARGET) $(TARGET).exe $(OBJ) $(WIN_OBJ)

install: $(BUILD_DIR)/$(TARGET)
	mkdir -p $(INSTALL_DIR)
	install -m 755 $(BUILD_DIR)/$(TARGET) $(INSTALL_DIR)

uninstall:
	rm $(INSTALL_DIR)/$(TARGET)
