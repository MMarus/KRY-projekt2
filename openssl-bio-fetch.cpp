
#include "openssl-bio-fetch.h"

void init_openssl_library(void)
{
  /* https://www.openssl.org/docs/ssl/SSL_library_init.html */
  (void)SSL_library_init();
  /* Cannot fail (always returns success) ??? */

  /* https://www.openssl.org/docs/crypto/ERR_load_crypto_strings.html */
  SSL_load_error_strings();
  /* Cannot fail ??? */

  /* SSL_load_error_strings loads both libssl and libcrypto strings */
  /* ERR_load_crypto_strings(); */
  /* Cannot fail ??? */

  /* OpenSSL_config may or may not be called internally, based on */
  /*  some #defines and internal gyrations. Explicitly call it    */
  /*  *IF* you need something from openssl.cfg, such as a         */
  /*  dynamically configured ENGINE.                              */
  OPENSSL_config(NULL);
  /* Cannot fail ??? */

  /* Include <openssl/opensslconf.h> to get this define     */
#if defined (OPENSSL_THREADS)
  /* TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO */
  /* https://www.openssl.org/docs/crypto/threads.html */
  fprintf(stdout, "Warning: thread locking is not implemented\n");
#endif
}

void print_cn_name(const char* label, X509_NAME* const name)
{
  int idx = -1, success = 0;
  unsigned char *utf8 = NULL;

  do
  {
    if(!name) break; /* failed */

    idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    if(!(idx > -1))  break; /* failed */

    X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
    if(!entry) break; /* failed */

    ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
    if(!data) break; /* failed */

    int length = ASN1_STRING_to_UTF8(&utf8, data);
    if(!utf8 || !(length > 0))  break; /* failed */

    fprintf(stdout, "  %s: %s\n", label, utf8);
    success = 1;

  } while (0);

  if(utf8)
    OPENSSL_free(utf8);

  if(!success)
    fprintf(stdout, "  %s: <not available>\n", label);
}

void print_san_name(const char* label, X509* const cert)
{
  int success = 0;
  GENERAL_NAMES* names = NULL;
  unsigned char* utf8 = NULL;

  do
  {
    if(!cert) break; /* failed */

    names = (GENERAL_NAMES*) X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0 );
    if(!names) break;

    int i = 0, count = sk_GENERAL_NAME_num(names);
    if(!count) break; /* failed */

    for( i = 0; i < count; ++i )
    {
      GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
      if(!entry) continue;

      if(GEN_DNS == entry->type)
      {
        int len1 = 0, len2 = -1;

        len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
        if(utf8) {
          len2 = (int)strlen((const char*)utf8);
        }

        if(len1 != len2) {
          fprintf(stderr, "  Strlen and ASN1_STRING size do not match (embedded null?): %d vs %d\n", len2, len1);
        }

        /* If there's a problem with string lengths, then     */
        /* we skip the candidate and move on to the next.     */
        /* Another policy would be to fails since it probably */
        /* indicates the client is under attack.              */
        if(utf8 && len1 && len2 && (len1 == len2)) {
          fprintf(stdout, "  %s: %s\n", label, utf8);
          success = 1;
        }

        if(utf8) {
          OPENSSL_free(utf8), utf8 = NULL;
        }
      }
      else
      {
        fprintf(stderr, "  Unknown GENERAL_NAME type: %d\n", entry->type);
      }
    }

  } while (0);

  if(names)
    GENERAL_NAMES_free(names);

  if(utf8)
    OPENSSL_free(utf8);

  if(!success)
    fprintf(stdout, "  %s: <not available>\n", label);

}

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
  /* For error codes, see http://www.openssl.org/docs/apps/verify.html  */

  int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
  int err = X509_STORE_CTX_get_error(x509_ctx);

  X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
  X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
  X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;

  fprintf(stdout, "verify_callback (depth=%d)(preverify=%d)\n", depth, preverify);

  /* Issuer is the authority we trust that warrants nothing useful */
  print_cn_name("Issuer (cn)", iname);

  /* Subject is who the certificate is issued to by the authority  */
  print_cn_name("Subject (cn)", sname);

  if(depth == 0) {
    /* If depth is 0, its the server's certificate. Print the SANs */
    print_san_name("Subject (san)", cert);
  }

  if(preverify == 0)
  {
    if(err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
      fprintf(stdout, "  Error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY\n");
    else if(err == X509_V_ERR_CERT_UNTRUSTED)
      fprintf(stdout, "  Error = X509_V_ERR_CERT_UNTRUSTED\n");
    else if(err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
      fprintf(stdout, "  Error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN\n");
    else if(err == X509_V_ERR_CERT_NOT_YET_VALID)
      fprintf(stdout, "  Error = X509_V_ERR_CERT_NOT_YET_VALID\n");
    else if(err == X509_V_ERR_CERT_HAS_EXPIRED)
      fprintf(stdout, "  Error = X509_V_ERR_CERT_HAS_EXPIRED\n");
    else if(err == X509_V_OK)
      fprintf(stdout, "  Error = X509_V_OK\n");
    else
      fprintf(stdout, "  Error = %d\n", err);
  }

#if !defined(NDEBUG)
  return 1;
#else
  return preverify;
#endif
}

void print_error_string(unsigned long err, const char* const label)
{
  const char* const str = ERR_reason_error_string(err);
  if(str)
    fprintf(stderr, "%s\n", str);
  else
    fprintf(stderr, "%s failed: %lu (0x%lx)\n", label, err, err);
}