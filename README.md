# IPSnect

*An IPS patch inspector*

This utility allows you to inspect the contents of an IPS patch, as well as
compare a binary file to what it would appear when patched.

### Sample output

```
$ ./ipsnect patch.ips base.bin

====== IPS summary ======
hunks: 3
regular hunks: 2
RLE hunks:     1
sum of hunk lengths: x00000044 bytes (68 bytes)
========= hunks =========

regular hunk on bytes x017F17-x017F3B (37 bytes)
------------- in unpatched binary: ------------
C5 FF FF FF 85 FF FF FF FF FF FF FF FF FF FF FF
FF FF FF FF FF FF FF FF FF FF A3 FF FF FF FF FF
FF FF FF FF D3
---------------- in IPS patch: ----------------
A0 00 8C 09 05 AD 20 05 10 01 60 A5 2A 29 04 D0
F9 A2 10 A9 00 20 DE FC D0 F0 EA EA EA EA EA EA
EA A2 00 8A 48 


regular hunk on byte x03965D (1 byte)
------------- in unpatched binary: ------------
9D
---------------- in IPS patch: ----------------
8D


RLE hunk on bytes x001016-x000FF6 (30 bytes)
------------- in unpatched binary: ------------
A5 2A 85 10 A2 00 A9 16 9D 00 04 A9 00 9D C1 05
A9 09 9D A5 2A 85 10 A2 00 A9 16 9D 00 04
---------------- in IPS patch: ----------------
FE FE FE FE ... (repeats for 30 bytes)
```
