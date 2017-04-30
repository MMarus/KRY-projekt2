//
// Created by archie on 4/27/17.
//

#ifndef KRY_PROJEKT2_OPENSSLBIOFETCH_H
#define KRY_PROJEKT2_OPENSSLBIOFETCH_H

#include "openssl-bio-fetch.h"
using namespace std;

class Connection {
public:
    Connection();
    ~Connection();

    void getPage(string hostName, string hostResource);

    bool createConnection(string hostname);

    SSL_CTX *ctx = NULL;
    BIO *web = NULL, *out = NULL;
    SSL *ssl = NULL;
    long res = 1;
    int ret = 1;
    unsigned long ssl_err = 0;
    string defaultTrustStore;

};

#endif //KRY_PROJEKT2_OPENSSLBIOFETCH_H
