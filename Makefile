# Makefile

CXX = g++
CXXFLAGS = -Wall -g -I/opt/homebrew/include
LIBS = -L/opt/homebrew/lib -lgpgme
TARGET = encrypt_csv
SOURCES = encrypt_csv.cpp

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

clean:
	rm -f $(TARGET) encrypted_dummy_pan_data.pgp
