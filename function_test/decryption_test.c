#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  int pt_fd;
  int ct_fd;
  int n_write = 0;
  int n_read = 0;
  int i;
  unsigned char buffer[1024] = {0};
/*
  // Original test data with tiny-AES-c
  // Need to set iv data in driver 
  unsigned char in[] = {
      0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e,
      0x9b, 0x12, 0xe9, 0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72,
      0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2, 0x73,
      0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e,
      0x22, 0x22, 0x95, 0x16, 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac,
      0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7};

  unsigned char out[] = {
      0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
      0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
      0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
      0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
      0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
      0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
  unsigned char key[] = {
      0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
      0x88, 0x09, 0xcf, 0x4f, 0x3c };
  unsigned char iv[]  = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
  };
*/

/* 
* Test Data from the AES standard
* https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
* PLAINTEXT: 00112233445566778899aabbccddeeff
* KEY: 000102030405060708090a0b0c0d0e0f
* EQUIVALENT INVERSE CIPHER (DECRYPT):
* round[ 0].iinput 69c4e0d86a7b0430d8cdb78070b4c55a
* ...
* round[10].ioutput 00112233445566778899aabbccddeeff
*/

/*
Running the test case with the following cmd with root user
***************************
insmod aes_cbc_module.ko encrypt=0 key="000102030405060708090a0b0c0d0e0f"
***************************
*/
  unsigned char out[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  
  unsigned char in[] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd,
    0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};



  ct_fd = open("/dev/vencrypt_ct", O_WRONLY | O_NONBLOCK);
  if (ct_fd < 0) {
    fprintf(stderr, "Open /dev/vencrypt_ct for decryption test failed! \n");
    exit(1);
  }
  pt_fd = open("/dev/vencrypt_pt", O_RDONLY | O_NONBLOCK);
  if (pt_fd < 0) {
    fprintf(stderr, "Open /dev/vencrypt_pt for decryption test failed! \n");
    close(ct_fd);
    exit(1);
  }
  n_write = write(ct_fd, &in, sizeof(in));
  n_read = read(pt_fd, &buffer, sizeof(buffer));

  for (i = 0; i < sizeof(out); i++) {
    printf("Byte %02d 0x%02x 0x%02x ", i, buffer[i], out[i]);
    if(buffer[i] != out[i]) {
      printf("diff\n");
      break;
    }
    else{
      printf("same\n");
    }
  }
  if(i < sizeof(out)){
    printf("Decryption Test FAIL!\n");
  }
  else{
    printf("Decryption Test PASS!\n");  
  }
  close(pt_fd);
  close(ct_fd);
  return 0;
}