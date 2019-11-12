.PHONY: all clean

all:
	c++ -O3 -Wall -std=c++11 -shared -fPIC pow.c -I `python3-config --cflags` `python3-config --ldflags` -o pow`python3-config --extension-suffix` -lcrypto 

clean:
	rm -rf pow*.so
