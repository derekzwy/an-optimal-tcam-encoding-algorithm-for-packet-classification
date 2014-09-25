#define BITSLENGTH 16

struct prefix {
  unsigned int value[BITSLENGTH];
  unsigned int length[BITSLENGTH];
  unsigned int cmplvalue[BITSLENGTH];
  unsigned int cmpllength[BITSLENGTH];
  unsigned int fullpf;
  unsigned int fpf_len;
  unsigned int nvalid;
  unsigned int ninvalid;
};