CFLAGS=-lssl -lcrypto -g

all:
	gcc -oip_example ip_example.c $(CFLAGS)
	gcc -ossl_example ssl_example.c $(CFLAGS)
	echo '```' > readme.md
	cat ssl_example.c >> readme.md
	echo '```' >> readme.md