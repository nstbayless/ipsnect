#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>

using namespace std;

const char* VERSION = "ipsnect utility v1.01";

struct Hunk
{
  bool RLE;
  unsigned int offset;
  unsigned int length;
  unsigned char* payload;
};

int parsehunks(const char* ipsfile, vector<Hunk>&);
int listhunks(vector<Hunk>&, ostream&, ifstream* compare = nullptr, int precontext = 0, int postcontext = 0);
void writehex(ostream&, unsigned int hex, unsigned char nbytes);

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
      
      // parse IPS file
      vector<Hunk> hunks;
      if (parsehunks(ips, hunks))
        return -1;
      
      if (!bin)
        listhunks(hunks, cout);
      else
      {
        ifstream inBIN(bin, ios::binary);
  
        // create binary streams
        if (inBIN.bad())
        {
          cerr << "ERROR opening binary file " << bin << endl;
          return -1;
        }
        listhunks(hunks, cout, &inBIN, b, a);
      }
      
      // clean up
      for (Hunk& hunk : hunks)
      {
        if (!hunk.RLE)
          delete[](hunk.payload);
      }
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

#define recs reinterpret_cast<char*>
#define errcheck(in, ipsfile) if (in.bad()) {cerr << "ERROR, corrupt IPS file " << ipsfile << endl; return -1;}

const char* const magic = "PATCH";

// reades a sequence of big-endian binary data as an int
unsigned int readbin(istream& in, unsigned char nbytes)
{
  // check for endianness
  int t = 1;
  bool le = (*(char *)&t == 1);
  // allocate buffer
  unsigned char buffer[4];
  for (int i = 0; i < 4; i++)
    buffer[i] = 0;
  
  // read into buffer
  for (int i = 0; i < nbytes; i++)
  {
    int index = i + (4-nbytes);
    if (le)
      index = nbytes-i - 1;
    in.read(recs(buffer+index), 1);
    if (in.bad())
      return -1;
  }
  return *(int*)(char*)(buffer);
}

int parsehunks(const char* ipsfile, vector<Hunk>& hunks)
{
  ifstream inIPS(ipsfile, ios::binary);
  
  // create binary streams
  if (inIPS.bad())
  {
    cerr << "ERROR opening IPS file " << ipsfile << endl;
    return -1;
  }
  
  // begin parsing
  int pos = 0;
  char header[5];
  inIPS.read(header, 5);
  errcheck(inIPS, ipsfile);
  if (strncmp(header, magic, 5))
  {
    cerr << "ERROR, IPS file " << ipsfile << " does not start with \"PATCH\" header." << endl;
    return -1;
  }
  
  // parse a hunk
  while (true)
  {
    Hunk hunk;
    
    // read offset
    hunk.offset = readbin(inIPS, 3);
    errcheck(inIPS, ipsfile);
    if (hunk.offset == 0x454f46)
      // EOF marker
      break;
    
    // read length
    hunk.length = readbin(inIPS, 2);
    errcheck(inIPS, ipsfile);
    if (hunk.length == 0)
    {
      // RLE
      hunk.RLE = true;
      hunk.length = readbin(inIPS, 2);
      errcheck(inIPS, ipsfile);
      inIPS.read(recs(&hunk.payload), 1);
      errcheck(inIPS, ipsfile);
    }
    else
    {
      // standard payload
      hunk.RLE = false;
      hunk.payload = new unsigned char[hunk.length];
      inIPS.read(recs(hunk.payload), hunk.length);
      errcheck(inIPS, ipsfile);
    }
    
    // append hunk to list
    hunks.push_back(hunk);
  }
  
  return 0;
}

void writehex(ostream& out, unsigned int val, unsigned char nbytes)
{
  for (int i = 0; i < nbytes * 2; i++)
  {
    char nibble = (val >> ((nbytes * 8 - 4) - i*4)) & 0xf;
    if (nibble <= 9)
      out << (char)('0' + nibble);
    else
      out << (char)('A' + (nibble - 10));
  }
}

void streamhex(istream* in, ostream &out, int nbytes)
{
  if (in->bad() || in->eof())
    out << "(error reading binary)";
  else {
    for (long i = 0; i < nbytes; i++)
    {
      if (i != 0)
      {
        if (i % 16)
          out<<" ";
        else
          out<<endl;
      }
      unsigned char b;
      if (in->eof())
      {
        if (i != 0)
          out << endl;
        out << "(exceeds binary length)";
        break;
      }
      b = readbin(*in, 1);
      writehex(out, b, 1);
    }
  }
  out << endl;
}

int listhunks(vector<Hunk>& hunks, ostream& out, ifstream* vs, int pre, int post)
{
  long totalbytes = 0;
  int nrle = 0;
  for (Hunk& hunk : hunks)
  {
    totalbytes += hunk.length;
    nrle += hunk.RLE;
  }
  
  out << "====== IPS summary ======" << endl;
  out << "hunks: " << hunks.size() << endl;
  out << "regular hunks: " << hunks.size() - nrle << endl;
  out << "RLE hunks:     " << nrle << endl;
  out << "sum of hunk lengths: x";
  writehex(out, totalbytes, 4);
  out << " bytes (" << totalbytes << " bytes)" << endl;
  out << "========= hunks =========";
  for (Hunk& hunk : hunks)
  {
    // specific hunk statistic
    out << endl << endl;
    if (hunk.length == 0)
    {
      out << "empty hunk at x";
      writehex(out, hunk.offset, 3);
      out << endl;
      continue;
    }
    if (hunk.RLE)
      out << "RLE";
    else
      out << "regular";
    if (hunk.length == 1)
    {
      // single-byte summary
      out << " hunk on byte x";
      writehex(out, hunk.offset, 3);
      out << " (1 byte)" << endl;
    }
    else
    {
      // multi-byte summary
      out << " hunk on bytes x";
      writehex(out, hunk.offset, 3);
      out << "-x";
      writehex(out, hunk.offset + hunk.length - 1, (hunk.offset + hunk.length - 1 > 0xffffff)?4:3);
      out << " (" << hunk.length << " bytes)" << endl;
    }
    if (vs)
    {
      if (pre > 0)
      {
        // display binary comparison context:
        if (vs)
        {
          out << "--------- context before (unpatched): ---------" << endl;
          vs->seekg(hunk.offset - pre);
          streamhex(vs, out, pre);
        }
      }
      out << "------------- in unpatched binary: ------------" << endl;
      vs->seekg(hunk.offset);
      streamhex(vs, out, hunk.length);
      out << "---------------- in IPS patch: ----------------" << endl;
    }
    // display IPS hunk data:
    if (hunk.RLE)
    {
      // RLE hunk
      unsigned char hex = reinterpret_cast<unsigned char*>(&hunk.payload)[0];
      if (hunk.length <= 16)
      {
        // display RLE patch verbatim
        for (int i=0; i<hunk.length; i++)
        {
          if (i != 0)
            out<<" ";
          writehex(out, hex, 1);
        }
        out<<endl;
      }
      else
      {
        // compress RLE patch with ellipsis
        for (int i = 0; i < 4; i++)
        {
          writehex(out, hex, 1);
          out<<" ";
        }
        out<<"... (repeats for " << hunk.length << " bytes)" << endl;
      }
    }
    else
    {
      // regular hunk
      for (int i = 0; i < hunk.length; i++)
      {
        if (i != 0)
        {
          if (i % 16)
            out<<" ";
          else
            out<<endl;
        }
        writehex(out, hunk.payload[i], 1);
      }
      out<<endl;
    }
    
    // display binary comparison:
    if (vs)
    {
      if (post > 0)
      {
        // display binary comparison context:
        out << "---------- context after (unpatched): ---------" << endl;
        streamhex(vs, out, post);
      }
    }
  }
}