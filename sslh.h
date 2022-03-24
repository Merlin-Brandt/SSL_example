#ifndef SSLH_H
#define SSLH_H

// SSLh is a SSL helper library

#define try status =

#define throw_ssl_at(file, line) \
    if (status) {\
        char label[1024];\
        snprintf(label, 1024, "%s:%i", file, line);\
        SSLh_failure(label);\
    }

#define throw_ssl throw_ssl_at(__FILE__, __LINE__)

// SSL helper functions

void SSLh_failure(const char *label)
{
    fprintf(stderr, "at %s\n", label);
    ERR_print_errors_fp(stderr);
    exit(-1);
}

SSL_CTX *SSLh_init()
{
    (void) SSL_library_init();
    SSL_load_error_strings();
    //OPENSSL_config(NULL);

    SSL_METHOD const *method = TLS_method();
    if (!method) SSLh_failure("TLS_method");
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) SSLh_failure("SSL_CTX_new");
    return ctx;
}

#define BIOh_get_ssl(bio, ssl) \
if (1) {\
    int status = BIO_get_ssl(bio, ssl) <= 0; throw_ssl \
}

#define BIOh_do_connect(bio) \
if (1) { \
    int status = BIO_do_connect(bio) <= 0; throw_ssl \
}

#define SSLh_CTX_load_verify_locations(ctx, file, path) \
if (1) { \
    int status = !SSL_CTX_load_verify_locations(ctx, file, path); throw_ssl \
}

#define BIOh_read(bio, response, size) _BIOh_read(bio, response, size, __FILE__, __LINE__)
int _BIOh_read(BIO *bio, void *response, int size, char const *file, int line)
{
    int status = BIO_read(bio, response, size); if (status <= 0) throw_ssl_at(file, line);
    int len = status;
    return len;
}

#define BIOh_new_ssl_connect(ctx) _BIOh_new_ssl_connect(ctx, __FILE__, __LINE__)
BIO *_BIOh_new_ssl_connect(SSL_CTX *ctx, char const *file, int line)
{
    BIO *bio = BIO_new_ssl_connect(ctx); // rewrite with basic calls
    int status = !bio; throw_ssl_at(file, line)
    return bio;
}

#endif