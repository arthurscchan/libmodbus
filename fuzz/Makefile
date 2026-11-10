TARGET=Fuzzer

#File
CLIENTEXE=FuzzClient
SERVEREXE=FuzzServer

#Compiler Flags
SET=cd ../ &&
INC=-I../src/
LIB=../src/libmodbus.la
EXTCFLAGS= -Wall -Wextra
LIBTOOL=libtool --mode=link --tag=CXX

all: $(TARGET) fuzzdata

#SETUP
INIT:
	$(SET) ./autogen.sh

CONF:
	$(SET) ./configure --disable-shared CC=$(CC) CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)"

MAKEALL:
	$(SET) make -j$(nproc)

CPFILE:
	cp ../tests/unit-test.h .

$(TARGET): INIT CONF MAKEALL CPFILE
	$(CC) $(EXTCFLAGS) $(CFLAGS) $(INC) -c $(CLIENTEXE).c
	$(LIBTOOL) $(CXX) $(LDFLAGS) $(CFLAGS) $(LIB) $(LIB_FUZZING_ENGINE) $(CLIENTEXE).o -o $(CLIENTEXE)

	$(CC) $(EXTCFLAGS) $(CFLAGS) $(INC) -c $(SERVEREXE).c
	$(LIBTOOL) $(CXX) $(LDFLAGS) $(CFLAGS) $(LIB) $(LIB_FUZZING_ENGINE) $(SERVEREXE).o -o $(SERVEREXE)

clean:
	rm $(CLIENTEXE) $(SERVEREXE) *.o

.PHONY: all clean

DATAEXE=FuzzData

fuzzdata: INIT CONF MAKEALL CPFILE
	$(CC) $(EXTCFLAGS) $(CFLAGS) $(INC) -c $(DATAEXE).c
	$(LIBTOOL) $(CXX) $(LDFLAGS) $(CFLAGS) $(LIB) $(LIB_FUZZING_ENGINE) $(DATAEXE).o -o $(DATAEXE)


.PHONY: fuzzdata
