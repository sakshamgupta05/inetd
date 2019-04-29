all: bin/inetd

dir:
	mkdir bin

bin/inetd: src/inetd.c
	gcc -o bin/inetd -lrt src/inetd.c

clean:
	rm -rf bin
