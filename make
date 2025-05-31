CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread -g
LDFLAGS = -lcrypto -lpthread

# Source files
COMMON_SRC = common.cpp tun_utils.cpp
SERVER_SRC = server.cpp $(COMMON_SRC)
CLIENT_SRC = client.cpp $(COMMON_SRC)

# Object files
COMMON_OBJ = $(COMMON_SRC:.cpp=.o)
SERVER_OBJ = $(SERVER_SRC:.cpp=.o)
CLIENT_OBJ = $(CLIENT_SRC:.cpp=.o)

# Targets
all: server client

server: $(SERVER_OBJ)
        $(CXX) $(CXXFLAGS) -o server $(SERVER_OBJ) $(LDFLAGS)

client: $(CLIENT_OBJ)
        $(CXX) $(CXXFLAGS) -o client $(CLIENT_OBJ) $(LDFLAGS)

%.o: %.cpp
        $(CXX) $(CXXFLAGS) -c $< -o $@

clean:
        rm -f *.o server client

.PHONY: all clean
