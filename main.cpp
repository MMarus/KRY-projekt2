#include <iostream>
#include "Connection.h"

using namespace std;

int main(int argc, char *argv[]) {



  string hostname = "minotaur.fi.muni.cz";
  string port = "443";

  if(argc == 2){
    string subdomain = argv[1];
    string newHostName;

    newHostName += subdomain + "." + hostname;

    Connection connection;
    if (connection.createConnection(newHostName))
      connection.getPage(newHostName, "/");
  } else {
    for (int i = 0; i < 4; ++i) {
      string newHostName;
      if (i < 10)
        newHostName = "0";
      newHostName += to_string(i) + "." + hostname;
      cout << newHostName << endl;
      Connection connection;
      if (connection.createConnection(newHostName))
        connection.getPage(newHostName, "/");
    }
  }



}