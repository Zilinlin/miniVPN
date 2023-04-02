// the file is the server code of TCP connection
// which includes authentication part

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 55555
#define CERT_FILE "server.crt"
#define KEY_FILE "server.key"
#define CA_FILE "ca.crt"

int main(int argc, char *argv[]){
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt=1;
    int addrlen = sizeof(address);
    SSL_CTX *ctx;

    // Initialize OpenSSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_server_method());

    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error: Failed to load server certificate.\n");
        exit(EXIT_FAILURE);
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ) {
        fprintf(stderr, "Error: Failed to load server private key.\n");
        exit(EXIT_FAILURE);
    }

    // Load trusted CA certificate
    if (SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL) != 1) {
        fprintf(stderr, "Error loading trusted CA certificate: %s\n", ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }

    // Require client certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);


    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Error: Socket creation failed.\n");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Error: setsockopt failed.\n");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind socket to address
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Error: Bind failed.\n");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Error: Listen failed.\n");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    // Accept incoming connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("Error: Accept failed.\n");
        exit(EXIT_FAILURE);
    }

    printf("Connection established.\n");

    char buffer[1024];
    memset(buffer,0,sizeof(buffer));
    recv(new_socket, buffer, 1024, 0);
    printf("The key is %s\n",buffer);
    // Wrap the SSL session around the socket
    /***SSL *ssl;
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, new_socket);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        char *message = "Hello, world, I'm Server!";
        SSL_write(ssl, message, strlen(message));
        printf("Message sent.\n");
    }

    // Shutdown and cleanup SSL
    SSL_shutdown(ssl);
    SSL_free(ssl);
***/
    // Close the socket and cleanup OpenSSL
    close(new_socket);
    close(server_fd);
    //SSL_CTX_free(ctx);

    return 0;
    
}


