// the file is the server code of TCP connection
// which includes authentication part

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>

#define SERVER_ADDRESS "192.168.15.7"
#define SERVER_PORT 55555
#define CERT_FILE "client.crt"
#define KEY_FILE "client.key"
#define CA_FILE "ca.crt"

int main(){
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd, ret;
    struct sockaddr_in hints, *res, *p;
    //char buffer[1024];
    // Initialize OpenSSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_BIO_strings();

    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        fprintf(stderr, "Error creating SSL context: %s\n", ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }

    // Load client certificate and key
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Error loading client certificate file %s: %s\n", CERT_FILE, ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Error loading client key file %s: %s\n", KEY_FILE, ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }

    // Load trusted CA certificate
    if (SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL) != 1) {
        fprintf(stderr, "Error loading trusted CA certificate file %s: %s\n", CA_FILE, ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }

    // require server certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    // Create a TCP socket
    memset(&hints, 0, sizeof(hints));
    hints.sin_family = AF_INET;
    hints.sin_addr.s_addr = inet_addr(SERVER_ADDRESS);
    hints.sin_port = htons(SERVER_PORT);
    //hints.ai_family = AF_UNSPEC;
    //hints.ai_socktype = SOCK_STREAM;

    //if (getaddrinfo(SERVER_ADDRESS, SERVER_PORT, &hints, &res) != 0) {
    //    fprintf(stderr, "Error resolving server address: %s\n", strerror(errno));
    //    exit(EXIT_FAILURE);
    //}

    // Connect to server
    
    //sock_fd=1;
    if((sockfd = socket(AF_INET, SOCK_STREAM,0))<0){
        perror("socket()");
        exit(1);
    }

    if (connect(sockfd, (struct sockaddr*) &hints, sizeof(hints)) == -1) {
        perror("connect()");
        exit(1);
        close(sockfd);
    }
    //for (p = res; p != NULL; p = p->ai_next) {
    //    sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    //    if (sockfd == -1) {
    //        continue;
    //    }
    //    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
    //        close(sockfd);
    //        continue;
    //   }
    //    break;
    //}
    //freeaddrinfo(res);


    printf("Connection established.\n");

    char buffer[1024];
    //memset(buffer,'C',9);
    // change the method to randomly generating 16 chars string 
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    srand(time(NULL));
    int i;
    for (i = 0; i < 16; i++) {
        buffer[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    send(sockfd, buffer, 16, 0);
    printf("sent the key %s\n", buffer);

    // Wrap the SSL session around the socket
    /***
    ssl = SSL_new(ctx);
    printf("after SSL_new function");
    if (!ssl) {
        fprintf(stderr, "Error creating SSL object: %s\n", ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }
    if (SSL_set_fd(ssl, sockfd) != 1) {
        fprintf(stderr, "Error setting SSL file descriptor: %s\n", ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        char *message = "Hello, Server, I'm Client!";
        SSL_write(ssl, message, strlen(message));
        printf("Message sent.\n");
    }

    // Shutdown and cleanup SSL
    SSL_shutdown(ssl);
    SSL_free(ssl);
***/
    close(sockfd);
    //SSL_CTX_free(ctx);

    return 0;

}
