#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define BUFFER_SIZE 10240 
int main(int argc, char *argv[]) {
  int pt_fd;
  int ct_fd;
  size_t n_write = 0;
  size_t n_read = 0;
  size_t n_trans = 0;
  int i;
  FILE * in_fp, *out_fp;
  struct stat file_stat;
  
  unsigned char buffer[BUFFER_SIZE] = {0};
  if(argc != 3)
  {
    fprintf(stderr, "Usage: decrypt_binary [in_filename] [out_filename]\n");
    exit(1);
  }
  printf("Try to decrypt\nin_file = %s\nout_file= %s\n", argv[1], argv[2]);
  in_fp = fopen(argv[1], "rb");
  if(NULL == in_fp){
    fprintf(stderr, "Failed to open %s\n", argv[1]);
    exit(1);
  }
  out_fp = fopen( argv[2], "wb");
  if(NULL == out_fp){
    fprintf(stderr, "Failed to open %s\n", argv[2]);
    fclose(in_fp);
    exit(1);
  }
  stat(argv[1],&file_stat);
  printf("Size of %s is %ld\n", argv[1], file_stat.st_size);

  ct_fd = open("/dev/vencrypt_ct", O_WRONLY | O_NONBLOCK);
  if (ct_fd < 0) {
    fprintf(stderr, "Open /dev/vencrypt_ct failed! \n");
    fclose(out_fp);
    fclose(in_fp);
    exit(1);
  }
  pt_fd = open("/dev/vencrypt_pt", O_RDONLY | O_NONBLOCK);
  if (pt_fd < 0) {
    fprintf(stderr, "Open /dev/vencrypt_pt failed! \n");
    close(ct_fd);
    fclose(out_fp);
    fclose(in_fp);
    exit(1);
  }

  while(!feof(in_fp)){
    memset(buffer, 0, sizeof(buffer));
    n_trans = fread(buffer,sizeof(char), sizeof(buffer), in_fp);
    // printf("Read %ld bytes from file, and write to pt node\n", n_trans);
    n_write += write(ct_fd, &buffer, n_trans);
  }

  while(n_trans = read(pt_fd, &buffer, sizeof(buffer)))
  {
    // printf("Read %ld bytes from ct node\n", n_trans);
    fwrite(buffer, n_trans, 1, out_fp);
  }

  close(pt_fd);
  close(ct_fd);
  fclose(in_fp);
  fclose(out_fp);

  return 0;
}
