// the file is to modify the simpletun from TCP to UDP
// Then add the AES encryption algorithm

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

#include <signal.h>
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

int debug;
char *progname;

int sock_fd, net_fd;

// this function is for handle break the tunnel
void signal_handler(int sig){
  printf("\nReceived CTRL+C signal. Closing socket and terminating program...\n");
  close(sock_fd);
  close(net_fd);
  exit(0);
}

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

int main(int argc, char *argv[]){

  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd;
  int nwrite, nread, plength;
  //  uint16_t total_len, ethertype;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = ""; //server ip
  char local_ip[16] = "192.168.15.8"; //client ip
  unsigned short int port = PORT;
  int optval = 1;
  sock_fd = 1;
  net_fd = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

  progname = argv[0];

  //zilin initialize the encryption and decryption contexts
  EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(enc_ctx);
  EVP_CIPHER_CTX_set_padding(enc_ctx, 1); // enable padding

  EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(dec_ctx);
  EVP_CIPHER_CTX_set_padding(dec_ctx, 1); // enable padding

  //chosse the encryption algorithm
  const EVP_CIPHER *cipher = EVP_aes_256_cbc();
  unsigned char *key = (unsigned char *)malloc(EVP_MAX_KEY_LENGTH);
  const char* hmac_key = "my_secret_key";
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

  // then start the HMAC part
  unsigned char *hmac = (unsigned char *)malloc(EVP_MAX_MD_SIZE);
  unsigned int hmac_len = 0;
    
  printf("hhhh0");
    /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        //strncpy(local_ip,optarg,15);
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        header_len = ETH_HDR_LEN;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0){
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0'){
    my_err("Must specify interface name!\n");
    usage();
  }else if(cliserv < 0){
    my_err("Must specify client or server mode!\n");
    usage();
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    my_err("Must specify server address!\n");
    usage();
  }else if((cliserv == SERVER)&&(*local_ip == '\0')){
    my_err("Must specify client address!\n");
    usage();
  }

  
  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  // start the socket for UDP
  if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }
  printf("hhhhh1");
  // try to connect with
  if(cliserv==CLIENT){
    //client, the remote ip is server ip
    memset(&remote,0,sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);

    //UDP doesn't need to connect to the server, can send the message directly
    net_fd = sock_fd;

    do_debug("CLIENT: the server address: %s\n", inet_ntoa(remote.sin_addr));

  }else{

    //Server, waiting for conenctions
    /* avoid EADDRINUSE error on bind() */
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
      perror("setsockopt()");
      exit(1);
    }

    memset(&remote,0,sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = htonl(INADDR_ANY);
    remote.sin_port = htons(port);

    //bind the socket to the server address
    if (bind(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0){
      perror("bind()");
      exit(1);
    }
    // because it's UDP, don't need to accept the connection
    // there is no accept function rather than TCP
    net_fd = sock_fd;

    //do_debug("SERVER: Client address: %s\n", inet_ntoa(remote.sin_addr));
  
  }

  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd)?tap_fd:net_fd;
  // set the client/local ip address
  memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = inet_addr(local_ip);
  local.sin_port = htons(port);

  //the new variables for AES and HMAC
  unsigned char *ciphertext = (unsigned char *)malloc(sizeof(plength) + EVP_CIPHER_CTX_block_size(enc_ctx));
  int ciphertext_len = 0;
  int final_len = 0;
  unsigned char rec_packet[BUFSIZE];
  unsigned char * packet;
  // // register signal handler for CTRL+C
  signal(SIGINT, signal_handler);

  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(tap_fd, &rd_set)){
      /* data from tun/tap: just read it and write it to the network */
      // now only change the write part
      nread = cread(tap_fd, buffer, BUFSIZE);

      // it seems like the buffer don't need to encrypt and decrpt
      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      /* write length + packet */
      plength = htons(nread);

      //then encrypt the length, (char *)&plength, sizeof(plength)
      //unsigned char *ciphertext = (unsigned char *)malloc(sizeof(plength) + EVP_CIPHER_CTX_block_size(enc_ctx));
      ciphertext_len = 0;
      if (!EVP_EncryptUpdate(enc_ctx, ciphertext, &ciphertext_len, (char *)&plength, sizeof(plength))) {
        perror("evp encrypt update");
        exit(1);
      }
      final_len = 0;
      if (!EVP_EncryptFinal_ex(enc_ctx, ciphertext + ciphertext_len, &final_len)) {
        perror("evp encrypt final");
        exit(1);
      }
      do_debug("the final length is %d\n", final_len);
      ciphertext_len += final_len;
      do_debug("kkkkkkk1");
      HMAC(EVP_sha256(), hmac_key, strlen(hmac_key), ciphertext, ciphertext_len, hmac, &hmac_len);
      packet = (unsigned char *)malloc(ciphertext_len+ hmac_len);
      memcpy(packet, ciphertext, ciphertext_len);
      memcpy(packet + ciphertext_len, hmac, hmac_len);
      // the version with HMAC function   packet, strlen(ciphertext)+hmac_len
      do_debug("kkkkkkk2");
      if(cliserv==CLIENT){
          nwrite = sendto(net_fd, packet, ciphertext_len + hmac_len, 0, (struct sockaddr *)&remote, sizeof(remote));
          nwrite = sendto(net_fd,  buffer, nread, 0, (struct sockaddr *)&remote, sizeof(remote));
      }else{
          nwrite = sendto(net_fd, packet, ciphertext_len + hmac_len, 0, (struct sockaddr *)&local, sizeof(local));
          if(nwrite < 0){
		        perror("sendto");
		        exit(EXIT_FAILURE);
          }
	        nwrite = sendto(net_fd,  buffer, nread, 0, (struct sockaddr *)&local, sizeof(local));
	        if(nwrite<0){
		        perror("sendto");
		        exit(EXIT_FAILURE);
	        }
      }
      
      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    if(FD_ISSET(net_fd, &rd_set)){
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */

      /* Read length */      
      //nread = read_n(net_fd, (char *)&plength, sizeof(plength));
    socklen_t remote_len = sizeof(remote);
    socklen_t local_len = sizeof(local);

    
    if(cliserv==CLIENT){
	    nread = recvfrom(net_fd, rec_packet, BUFSIZE, 0, (struct sockaddr *)&remote, &remote_len);
    }else{
	    nread = recvfrom(net_fd, rec_packet, BUFSIZE, 0, (struct sockaddr *)&local, &local_len);
    }
	
    if(nread == 0) {
        break;
    }
    do_debug("kkkkkkk3");
    // start the HMAC processing
    unsigned char *computed_hmac = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
    unsigned int computed_hmac_len = 0;
    HMAC(EVP_sha256(), hmac_key, strlen(hmac_key), rec_packet, nread - hmac_len, computed_hmac, &computed_hmac_len);
    if (memcmp(computed_hmac, &rec_packet[nread - hmac_len], hmac_len)==0){
        do_debug("the HMAC verification is good\n");
    }else{
        perror("HMAC verification fails");
        exit(1);
    }

    // (char *)&plength, sizeof(plength), 
    unsigned char *decrypted_text = (unsigned char *)malloc(nread -hmac_len + EVP_CIPHER_CTX_block_size(dec_ctx));
    int decrypted_len = 0;
    if (!EVP_DecryptUpdate(dec_ctx, decrypted_text, &decrypted_len, rec_packet, nread-hmac_len)) {
        perror("decrypt update");
        exit(1);
    }
    final_len = 0;
    do_debug("the decrypted text:%s", decrypted_text);
    if (!EVP_DecryptFinal_ex(dec_ctx, decrypted_text + decrypted_len, &final_len)) {
        perror("decrypt final\n");
        unsigned long error_code = ERR_get_error();
        char error_message[256];
        ERR_error_string(error_code, error_message);
        do_debug("Decryption error: %s\n", error_message);
        exit(1);
    }
    decrypted_len += final_len;
    memcpy((char *)&plength, decrypted_text, decrypted_len);
    net2tap++;

      /* read packet */
      //nread = read_n(net_fd, buffer, ntohs(plength));
    if(cliserv==CLIENT){
	    nread = recvfrom(net_fd, buffer, ntohs(plength), 0, (struct sockaddr *)&remote, &remote_len);
    }else{
	    nread = recvfrom(net_fd, buffer, ntohs(plength),0,(struct sockaddr *)&local, &local_len);
    }
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, buffer, nread);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }

  return(0);

}


