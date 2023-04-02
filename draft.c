// the file is for test the HMAC and AES locally

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

int main(int argc, char *argv[]){

printf("hhhhhhh start");
  //zilin initialize the encryption and decryption contexts
  EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(enc_ctx);
  EVP_CIPHER_CTX_set_padding(enc_ctx, 1); // enable padding

  EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(dec_ctx);
  EVP_CIPHER_CTX_set_padding(dec_ctx, 1); // enable padding
printf("hhhhhhh0");
  //chosse the encryption algorithm
  const EVP_CIPHER *cipher = EVP_aes_256_cbc();
  unsigned char *key = (unsigned char *)malloc(EVP_MAX_KEY_LENGTH);
  // kust set as all 0
  memset(key,0,sizeof(key));
  unsigned char *iv = (unsigned char *)malloc(EVP_MAX_IV_LENGTH);
  memset(iv, 0, sizeof(iv));
  // initial the encryption
  if(!EVP_EncryptInit_ex(enc_ctx, cipher, NULL, key,iv)){
    perror("encrption init");
    exit(1);
  }
  //initial the decryption
  if (!EVP_DecryptInit_ex(dec_ctx, cipher, NULL, key, iv)) {
    perror("decrption init");
    exit(1);
  }
  
  printf("hhhhhhh1");
  // then start the HMAC part
  unsigned char *hmac = (unsigned char *)malloc(EVP_MAX_MD_SIZE);
  unsigned int hmac_len = 0;

  int plength = htons(100);
  unsigned char *ciphertext = (unsigned char *)malloc(sizeof(plength) + EVP_CIPHER_CTX_block_size(enc_ctx));
  int ciphertext_len = 0;
  if (!EVP_EncryptUpdate(enc_ctx, ciphertext, &ciphertext_len, (char *)&plength, sizeof(plength))) {
    perror("evp encrypt update");
    exit(1);
    }
    int final_len = 0;
    if (!EVP_EncryptFinal_ex(enc_ctx, ciphertext + ciphertext_len, &final_len)) {
    perror("evp encrypt final");
    exit(1);
    }
    ciphertext_len += final_len;

    HMAC(EVP_sha256(), key, strlen(key), ciphertext, ciphertext_len, hmac, &hmac_len);
    unsigned char * packet = (unsigned char *)malloc(ciphertext_len + hmac_len);
    memcpy(packet, ciphertext, strlen(ciphertext));
    memcpy(packet + strlen(ciphertext), hmac, hmac_len);
  
  printf("hhhhhh2");
  int nread = ciphertext_len + hmac_len;
  char * buffer = (unsigned char *)malloc(BUFSIZE);
  memcpy(buffer, packet, nread);
  // start the HMAC processing
    unsigned char*rec_data = (unsigned char *)malloc(nread - hmac_len);
    memcpy(rec_data, buffer, nread-hmac_len);
    unsigned char *rec_hmac = (unsigned char*)malloc(hmac_len);
    memcpy(rec_hmac, buffer+nread-hmac_len, hmac_len);
    unsigned char *computed_hmac = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
    unsigned int computed_hmac_len = 0;
    HMAC(EVP_sha256(), key, strlen(key), rec_data, nread - hmac_len, computed_hmac, &computed_hmac_len);
    if (computed_hmac_len != hmac_len || memcmp(rec_hmac, computed_hmac, hmac_len) != 0) {
      // HMAC-SHA256 verification failed
      perror("the HMAC verification failed");
      exit(1);
    } else {
      // HMAC-SHA256 verification succeeded
      printf("HMAC-SHA256 verification succeeded");
    }
    printf("hhhhhhh3");
    // (char *)&plength, sizeof(plength), 
    unsigned char *decrypted_text = (unsigned char *)malloc(nread - hmac_len + EVP_CIPHER_CTX_block_size(dec_ctx));
    int decrypted_len = 0;
    if (!EVP_DecryptUpdate(dec_ctx, decrypted_text, &decrypted_len, rec_data, nread-hmac_len)) {
        perror("decrypt update");
        exit(1);
    }
    final_len = 0;
    if (!EVP_DecryptFinal_ex(dec_ctx, decrypted_text + decrypted_len, &final_len)) {
        perror("decrypt final");
        exit(1);
    }
    decrypted_len += final_len;
    memcpy((char *)&plength, decrypted_text, decrypted_len);
    printf("the whole process finished, and the plength is:%d", plength);

return 0;


}