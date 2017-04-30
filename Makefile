CC=g++ -std=c++11
CFLAGS= -c -Wall
LDFLAGS= -lssl -lcrypto
SOURCES= main.cpp Connection.cpp openssl-bio-fetch.cpp
OBJECTS= $(SOURCES:.cpp=.o)
EXECUTABLE= KRY_projekt2

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm *.o $(EXECUTABLE)
