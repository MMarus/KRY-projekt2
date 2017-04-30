
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/x509v3.h>

#ifndef UNUSED
# define UNUSED(x) ((void)(x))
#endif

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

#ifndef HOST_NAME
# define HOST_NAME "07.minotaur.fi.muni.cz"
#endif

#ifndef HOST_PORT
# define HOST_PORT "443"
#endif

#ifndef HOST_RESOURCE
# define HOST_RESOURCE "/"
#endif

/*******************************************/
/* Diagnostics and ASSERT                  */
/*******************************************/

#if !defined(NDEBUG)

#include <signal.h>

static void NullTrapHandler(int unused) { UNUSED(unused); }

// No reason to return a value even though the function can fail.
// Its not like we can assert to alert of a failure.
static int InstallDebugTrapHandler()
{
    // http://pubs.opengroup.org/onlinepubs/007908799/xsh/sigaction.html
    struct sigaction new_handler, old_handler;

    int ret = 0;

    do {
        ret = sigaction (SIGTRAP, NULL, &old_handler);
        if (ret != 0) break; // Failed

        // Don't step on another's handler
        // if (old_handler.sa_handler != NULL) {
        //    ret = 0;
        //    break;
        // }

        // Set up the structure to specify the null action.
        new_handler.sa_handler = &NullTrapHandler;
        new_handler.sa_flags = 0;

        ret = sigemptyset (&new_handler.sa_mask);
        if (ret != 0) break; // Failed

        // Install it
        ret = sigaction (SIGTRAP, &new_handler, NULL);
        if (ret != 0) break; // Failed

        ret = 0;

    } while(0);

    return ret;
}

#  define ASSERT(x) { \
  if(!(x)) { \
    fprintf(stderr, "Assertion: %s: function %s, line %d\n", (char*)(__FILE__), (char*)(__func__), (int)__LINE__); \
  } \
}

#else

#  define ASSERT(x) UNUSED(x)

#endif // !defined(NDEBUG)

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx);

void init_openssl_library(void);
void print_cn_name(const char* label, X509_NAME* const name);
void print_san_name(const char* label, X509* const cert);
void print_error_string(unsigned long err, const char* const label);

/* Cipher suites, https://www.openssl.org/docs/apps/ciphers.html */
const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS";

#if 0
const char* const PREFERRED_CIPHERS = "kEECDH:kEDH:kRSA:AESGCM:AES256:AES128:3DES:SHA256:SHA84:SHA1:!aNULL:!eNULL:!EXP:!LOW:!MEDIUM!ADH:!AECDH";
#endif

#if 0
const char* const PREFERRED_CIPHERS = NULL;
#endif

#if 0
const char* PREFERRED_CIPHERS =

/* TLS 1.2 only */
"ECDHE-ECDSA-AES256-GCM-SHA384:"
"ECDHE-RSA-AES256-GCM-SHA384:"
"ECDHE-ECDSA-AES128-GCM-SHA256:"
"ECDHE-RSA-AES128-GCM-SHA256:"

/* TLS 1.2 only */
"DHE-DSS-AES256-GCM-SHA384:"
"DHE-RSA-AES256-GCM-SHA384:"
"DHE-DSS-AES128-GCM-SHA256:"
"DHE-RSA-AES128-GCM-SHA256:"

/* TLS 1.0 only */
"DHE-DSS-AES256-SHA:"
"DHE-RSA-AES256-SHA:"
"DHE-DSS-AES128-SHA:"
"DHE-RSA-AES128-SHA:"

/* SSL 3.0 and TLS 1.0 */
"EDH-DSS-DES-CBC3-SHA:"
"EDH-RSA-DES-CBC3-SHA:"
"DH-DSS-DES-CBC3-SHA:"
"DH-RSA-DES-CBC3-SHA";
#endif