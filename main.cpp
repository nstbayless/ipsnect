#include <iostream>
#include <fstream>
#include <cstring>

using namespace std;

const char* VERSION = "ipsnect utility v0.1";

int showdiff(const char* ipsfile, const char* binfile, int a, int b, ostream&);

int main(int argc, const char**  argv)
{
  const char* progname = "ipsnect";
  if (argc > 0)
      progname = argv[0];
  char const* ips;
  const char* bin = nullptr;
  bool failed = false;
  bool help = false;
  
  // dispatch usage
  if (argc >= 2)
  {
    if (strcmp(argv[1],"-v") == 0)
      // version number
      cout << VERSION << endl;
    else if (strcmp(argv[1],"-h") == 0)
      // help message (usage)
      help = true;
    else
    {
      // parse args for show IPS difference
      ips = argv[1];
      if (argc > 2)
        bin = argv[2];
      unsigned int a = 0;
      unsigned int b = 0;
      while (argc > 3)
      {
        const char* argcs = argv[argc - 1];
        // parse bytecount arguments (-a, -b)
        if (strlen(argcs) > 3)
        {
          char arg = 0;
          if (strncmp(argcs, "-a=", 3) == 0)
            arg = 'a';
          if (strncmp(argcs, "-b=", 3) == 0)
            arg = 'b';
          if (strncmp(argcs, "-c=", 3) == 0)
            arg = 'c';
          if (arg)
          {
            int bytecount = 0;
            for (int i = 3; i < strlen(argcs); i++)
            {
              char byte = argcs[i];
              int dval = -1;
              if (byte >= '0' && byte <= '9')
              {
                bytecount *= 10;
                bytecount += byte - '0';
              }
              else
              {
                cout << "unrecognized number in argument " << argcs << endl;
                return -1;
              }
            }
            if (arg == 'a' || arg == 'c')
              a = bytecount;
            if (arg == 'b' || arg == 'c')
              b = bytecount;
            argc --;
          }
          else
          {
            cout << "unrecognized argument " << argcs << endl;
            return -1;
          }
        }
        else
        {
          cout << "unrecognized argument " << argcs << " (expecting byte context count)" << endl;
          return -1;
        }
      }
      
      // show difference
      return showdiff(ips, bin, a, b, cout);
    }
  }
  else
    failed = true;
  
  // display usage
  if (failed || help)
  {
    if (help)
    {
      cout << "The ipsnect utility allows you to inspect the contents of IPS files, the binary patching format." << endl;
      cout << "You can also use it to see exactly how it will modify a specific binary file." << endl << endl;
    }
    cout << "Usage:" << endl;
    cout << "  " << progname << " -[hv]" << endl;
    cout << "  " << progname << " IPS [BIN [-a=<bytes>] [-b=<bytes>] [-c=<bytes>]]" << endl;
    if (help)
    {
      cout << endl<< "-v: show the version number" << endl;
      cout << "-h: show this help page" << endl;
      cout << "IPS: an ips file" << endl;
      cout << "BIN: a binary file to compare against (optional)" << endl;
      cout << "-a: number of bytes of context to show before each hunk (decimal)" << endl;
      cout << "-b: number of bytes of context to show after each hunk (decimal)" << endl;
      cout << "-c: number of bytes of context to show around each hunk (decimal)" << endl;
    }
  }
  
  return -failed;
}

int showdiff(const char* ipsfile, const char* binfile, int a, int b, ostream& out)
{
  
  return 0;
}