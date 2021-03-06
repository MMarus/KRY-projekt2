//
// Created by archie on 4/27/17.
//

#include <string>
#include <iostream>

#include "Connection.h"


using namespace std;

Connection::Connection() {
  const char *dir = getenv(X509_get_default_cert_dir_env());
  if (!dir)
    dir = X509_get_default_cert_dir();
  defaultTrustStore = dir;
  defaultTrustStore = "/etc/pki/tls/certs";
  cout << "defaultTrustStore = " << defaultTrustStore << endl;
/* Internal function that wraps the OpenSSL init's   */
  /* Cannot fail because no OpenSSL function fails ??? */
  init_openssl_library();

  /* https://www.openssl.org/docs/ssl/SSL_CTX_new.html */
  const SSL_METHOD* method = SSLv23_method();
  ssl_err = ERR_get_error();

  ASSERT(NULL != method);
  if(NULL == method)
  {
    print_error_string(ssl_err, "SSLv23_method");
    throw std::runtime_error("SSLv23_method");
  }

  /* http://www.openssl.org/docs/ssl/ctx_new.html */
  ctx = SSL_CTX_new(method);
  /* ctx = SSL_CTX_new(TLSv1_method()); */
  ssl_err = ERR_get_error();

  ASSERT(ctx != NULL);
  if(ctx == NULL)
  {
    print_error_string(ssl_err, "SSL_CTX_new");
    throw std::runtime_error("SSL_CTX_new");
  }

  /* https://www.openssl.org/docs/ssl/ctx_set_verify.html */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
  /* Cannot fail ??? */

  /* https://www.openssl.org/docs/ssl/ctx_set_verify.html */
  //default 9
  SSL_CTX_set_verify_depth(ctx, 9);
  /* Cannot fail ??? */

  /* Remove the most egregious. Because SSLv2 and SSLv3 have been      */
  /* removed, a TLSv1.0 handshake is used. The client accepts TLSv1.0  */
  /* and above. An added benefit of TLS 1.0 and above are TLS          */
  /* extensions like Server Name Indicatior (SNI).                     */
  const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  long old_opts = SSL_CTX_set_options(ctx, flags);
  UNUSED(old_opts);

  /* http://www.openssl.org/docs/ssl/SSL_CTX_load_verify_locations.html */

  res = SSL_CTX_set_default_verify_paths(ctx);
  ssl_err = ERR_get_error();

  if(res != 1) {
    print_error_string(ssl_err, "SSL_CTX_set_default_verify_paths");
  }

  res = SSL_CTX_load_verify_locations(ctx, "crocs-ca.pem", NULL);
  ssl_err = ERR_get_error();

  ASSERT(1 == res);
  if(1 != res)
  {
    /* Non-fatal, but something else will probably break later */
    print_error_string(ssl_err, "SSL_CTX_load_verify_locations");
    /* break; */
  }
}

bool Connection::createConnection(string hostname) {
  /* https://www.openssl.org/docs/crypto/BIO_f_ssl.html */
  web = BIO_new_ssl_connect(ctx);
  ssl_err = ERR_get_error();

  ASSERT(web != NULL);
  if(web == NULL)
  {
    print_error_string(ssl_err, "BIO_new_ssl_connect");
    return false;
  }
  string conn = hostname + ":" + HOST_PORT;
  /* https://www.openssl.org/docs/crypto/BIO_s_connect.html */
  res = BIO_set_conn_hostname(web, conn.c_str());
  ssl_err = ERR_get_error();

  ASSERT(1 == res);
  if(1 != res)
  {
    print_error_string(ssl_err, "BIO_set_conn_hostname");
    return false;
  }

  /* https://www.openssl.org/docs/crypto/BIO_f_ssl.html */
  /* This copies an internal pointer. No need to free.  */
  BIO_get_ssl(web, &ssl);
  ssl_err = ERR_get_error();

  ASSERT(ssl != NULL);
  if(ssl == NULL)
  {
    print_error_string(ssl_err, "BIO_get_ssl");
    return false;

  }

  /* https://www.openssl.org/docs/ssl/ssl.html#DEALING_WITH_PROTOCOL_CONTEXTS */
  /* https://www.openssl.org/docs/ssl/SSL_CTX_set_cipher_list.html            */
  res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
  ssl_err = ERR_get_error();

  ASSERT(1 == res);
  if(1 != res)
  {
    print_error_string(ssl_err, "SSL_set_cipher_list");
    return false;
  }

  /* No documentation. See the source code for tls.h and s_client.c */
  res = SSL_set_tlsext_host_name(ssl, hostname.c_str());
  ssl_err = ERR_get_error();

  ASSERT(1 == res);
  if(1 != res)
  {
    /* Non-fatal, but who knows what cert might be served by an SNI server  */
    /* (We know its the default site's cert in Apache and IIS...)           */
    print_error_string(ssl_err, "SSL_set_tlsext_host_name");
    /* break; */
  }

  /* https://www.openssl.org/docs/crypto/BIO_s_file.html */
  out = BIO_new_fp(stdout, BIO_NOCLOSE);
  ssl_err = ERR_get_error();

  ASSERT(NULL != out);
  if(NULL == out)
  {
    print_error_string(ssl_err, "BIO_new_fp");
    return false;
  }

  /* https://www.openssl.org/docs/crypto/BIO_s_connect.html */
  res = BIO_do_connect(web);
  ssl_err = ERR_get_error();

  ASSERT(1 == res);
  if(1 != res)
  {
    print_error_string(ssl_err, "BIO_do_connect");
    return false;
  }

  /* https://www.openssl.org/docs/crypto/BIO_f_ssl.html */
  res = BIO_do_handshake(web);
  ssl_err = ERR_get_error();

  ASSERT(1 == res);
  if(1 != res)
  {
    print_error_string(ssl_err, "BIO_do_handshake");
    return false;
  }

  /**************************************************************************************/
  /**************************************************************************************/
  /* You need to perform X509 verification here. There are two documents that provide   */
  /*   guidance on the gyrations. First is RFC 5280, and second is RFC 6125. Two other  */
  /*   documents of interest are:                                                       */
  /*     Baseline Certificate Requirements:                                             */
  /*       https://www.cabforum.org/Baseline_Requirements_V1_1_6.pdf                    */
  /*     Extended Validation Certificate Requirements:                                  */
  /*       https://www.cabforum.org/Guidelines_v1_4_3.pdf                               */
  /*                                                                                    */
  /* Here are the minimum steps you should perform:                                     */
  /*   1. Call SSL_get_peer_certificate and ensure the certificate is non-NULL. It      */
  /*      should never be NULL because Anonymous Diffie-Hellman (ADH) is not allowed.   */
  /*   2. Call SSL_get_verify_result and ensure it returns X509_V_OK. This return value */
  /*      depends upon your verify_callback if you provided one. If not, the library    */
  /*      default validation is fine (and you should not need to change it).            */
  /*   3. Verify either the CN or the SAN matches the host you attempted to connect to. */
  /*      Note Well (N.B.): OpenSSL prior to version 1.1.0 did *NOT* perform hostname   */
  /*      verification. If you are using OpenSSL 0.9.8 or 1.0.1, then you will need     */
  /*      to perform hostname verification yourself. The code to get you started on     */
  /*      hostname verification is provided in print_cn_name and print_san_name. Be     */
  /*      sure you are sensitive to ccTLDs (don't navively transform the hostname       */
  /*      string). http://publicsuffix.org/ might be helpful.                           */
  /*                                                                                    */
  /* If all three checks succeed, then you have a chance at a secure connection. But    */
  /*   its only a chance, and you should either pin your certificates (to remove DNS,   */
  /*   CA, and Web Hosters from the equation) or implement a Trust-On-First-Use (TOFU)  */
  /*   scheme like Perspectives or SSH. But before you TOFU, you still have to make     */
  /*   the customary checks to ensure the certifcate passes the sniff test.             */
  /*                                                                                    */
  /* Happy certificate validation hunting!                                              */
  /**************************************************************************************/
  /**************************************************************************************/


  /* Step 1: verify a server certifcate was presented during negotiation */
  /* https://www.openssl.org/docs/ssl/SSL_get_peer_certificate.html          */
  X509* cert = SSL_get_peer_certificate(ssl);
  if(cert) { X509_free(cert); } /* Free immediately */

  ASSERT(NULL != cert);
  if(NULL == cert)
  {
    /* Hack a code for print_error_string. */
    print_error_string(X509_V_ERR_APPLICATION_VERIFICATION, "SSL_get_peer_certificate");
    return false;
  }

  /* Step 2: verify the result of chain verifcation             */
  /* http://www.openssl.org/docs/ssl/SSL_get_verify_result.html */
  /* Error codes: http://www.openssl.org/docs/apps/verify.html  */
  res = SSL_get_verify_result(ssl);

  ASSERT(X509_V_OK == res);
  if(X509_V_OK != res)
  {
    /* Hack a code into print_error_string. */
    print_error_string((unsigned long)res, "SSL_get_verify_results");
    return false;
  }

  /* Step 3: hostname verifcation.   */
  /* An exercise left to the reader. */

  return true;
}

void Connection::getPage(string hostName, string hostResource){
  /**************************************************************************************/
  /**************************************************************************************/
  /* Now, we can finally start reading and writing to the BIO...                        */
  /**************************************************************************************/
  /**************************************************************************************/
  string request = "GET " + hostResource + " HTTP/1.1\r\nHost: " + hostName + "\r\nConnection: close\r\n\r\n";
  string response = "\nFetching: " + hostResource + "\n\n";
  BIO_puts(web, request.c_str());
  BIO_puts(out, response.c_str());

  int len = 0;
  do {
    char buff[1536] = {};

    /* https://www.openssl.org/docs/crypto/BIO_read.html */
    len = BIO_read(web, buff, sizeof(buff));

    if(len > 0)
      BIO_write(out, buff, len);

    /* BIO_should_retry returns TRUE unless there's an  */
    /* error. We expect an error when the server        */
    /* provides the response and closes the connection. */

  } while (len > 0 || BIO_should_retry(web));
}

Connection::~Connection() {
  if(out)
    BIO_free(out);

  if(web != NULL)
    BIO_free_all(web);

  if(NULL != ctx)
    SSL_CTX_free(ctx);

}

