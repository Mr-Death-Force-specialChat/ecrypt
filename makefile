OBJ=obj
TARGET=test_ecrypt
FLAGS_C=-O3 -std=c++20 -lcryptopp
FLAGS_L=-lcryptopp
TIME=/usr/bin/time
TIME_FORMATTING="Build took %E"
VALGRIND_OUT=$(TARGET)_valgrind

CPP_SOURCES=$(wildcard *.cpp)
H_SOURCES=$(wildcard *.h)
OBJECTS=$(patsubst %.cpp,$(OBJ)/%.o,$(CPP_SOURCES))

default: build

ifeq (leak_check,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "run"
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_ARGS):;@:)
endif

leak_check:
	valgrind --log-file=$(VALGRIND_OUT) --leak-check=full $(TARGET) $(RUN_ARGS)
	cat $(VALGRIND_OUT) | less

build:
	@$(TIME) --format=$(TIME_FORMATTING) make build_s2 --no-print-directory

build_s2: $(TARGET)

$(TARGET): $(OBJECTS)
	g++ $(OBJECTS) -o $(TARGET) $(FLAGS_L)

$(OBJ)/%.o: %.cpp
	g++ -c $^ -o $@ $(FLAGS_C)

setup:
	mkdir $(OBJ)

clean:
	rm -r $(OBJ)
	mkdir $(OBJ)
