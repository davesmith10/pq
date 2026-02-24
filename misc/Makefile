CXX      = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra
LDFLAGS  = -lssl -lcrypto

all: shannon hashpass

shannon: shannon.cpp
	$(CXX) $(CXXFLAGS) -o shannon shannon.cpp

hashpass: hashpass.cpp
	$(CXX) $(CXXFLAGS) -o hashpass hashpass.cpp $(LDFLAGS)

clean:
	rm -f shannon hashpass
