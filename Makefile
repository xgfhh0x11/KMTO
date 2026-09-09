CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2 -g
LDFLAGS =

SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
BIN_DIR = bin

KMTO_SOURCES = \
	$(SRC_DIR)/main.c \
	$(SRC_DIR)/mitigation_detector.c \
	$(SRC_DIR)/telemetry.c \
	$(SRC_DIR)/test_harness.c \
	$(SRC_DIR)/config_manager.c \
	$(SRC_DIR)/reporting.c
KMTO_OBJECTS = $(KMTO_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

ifeq ($(OS),Windows_NT)
CLI_SOURCES = $(SRC_DIR)/kmto_cli.c
CLI_OBJECTS = $(CLI_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
CLI_TARGET = $(BIN_DIR)/kmto_cli.exe
else
CLI_SOURCES =
CLI_OBJECTS =
CLI_TARGET =
endif

INCLUDES = -I$(INC_DIR)

TARGET = $(BIN_DIR)/kmto

all: $(TARGET) $(CLI_TARGET)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(TARGET): $(KMTO_OBJECTS) | $(BIN_DIR)
	$(CC) $(KMTO_OBJECTS) $(LDFLAGS) -o $@

ifeq ($(OS),Windows_NT)
$(CLI_TARGET): $(CLI_OBJECTS) | $(BIN_DIR)
	$(CC) $(CLI_OBJECTS) $(LDFLAGS) -luser32 -lkernel32 -lole32 -ladvapi32 -o $@
endif

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/kmto

test: $(TARGET)
	$(TARGET) -t all -o test_output

matrix: $(TARGET)
	$(TARGET) -m -o matrix_output

.PHONY: all clean install uninstall test matrix
