//
// Demonstration of basic OpenSSL skills learned in two days. Simple http/https web client.
//
// compile with 
//   $ make
// run with
//   $ ./ssl_example [-s] <address>
//


#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string.h>
#include <unistd.h>

#include "sslh.h"

int main(int argc, char *const *argv)
{
    int opt, secureflag = 0;
    while ((opt = getopt(argc, argv, "s")) != -1) {
        switch (opt) {
        case 's':
            secureflag = 1;
            break;
        default: /* '?' */
            #define print_usage fprintf(stderr, "Usage: %s [-s] <address>\n", argv[0]), exit(EXIT_FAILURE);
            print_usage;
        }
    }

    if (optind >= argc)
       print_usage;

    char const *hostname = argv[optind];
    char hostname_port[128];
    snprintf(hostname_port, sizeof hostname_port, "%s:%s", hostname, secureflag ? "https" : "http");

    SSL_CTX *ctx = SSLh_init();

    BIO *bio;
    SSL *ssl;
    if (secureflag)
    {
        bio = BIO_push(BIO_new_ssl(ctx, 1), BIO_new(BIO_s_connect()));
        BIOh_get_ssl(bio, &ssl);
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    } 
    else
    {
        bio = BIO_new(BIO_s_connect());
    }   

    BIO_set_conn_hostname(bio, hostname_port);
    BIOh_do_connect(bio);
    
    if (secureflag)
    {
        SSLh_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/certs/");
        long verifyflag = SSL_get_verify_result(ssl);
        if (verifyflag != X509_V_OK)
            fprintf(stderr, "Certificate verification error (%i) but continuing\n", (int) verifyflag);

    }
    
    char request[1024];
    sprintf(request, "GET / HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Connection: Close\r\n"
                     "\r\n", 
                     hostname);
    BIO_puts(bio, request);

    while (1) {
        char response[1024];
        memset(response, '\0', sizeof response);
        int n = BIOh_read(bio, response, sizeof response);
        if (n == 0) break;
        printf("%s", response);
    }

    SSL_CTX_free(ctx);
    BIO_free_all(bio);
}
