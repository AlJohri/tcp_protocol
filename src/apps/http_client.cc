#include "minet_socket.h"
#include <stdlib.h>
#include <ctype.h>

#define BUFSIZE 1024

int write_n_bytes(int fd, char * buf, int count);

int main(int argc, char * argv[]) {
    char * server_name = NULL;
    int server_port = 0;
    char * server_path = NULL;

    int sock = 0;
    int rc = -1;
    int datalen = 0;
    bool ok = true;
    struct sockaddr_in sa;
    FILE * wheretoprint = stdout;
    struct hostent * site = NULL;
    char * req = NULL;

    char buf[BUFSIZE + 1];
    char * bptr = NULL;
    char * bptr2 = NULL;
    char * endheaders = NULL;
   
    struct timeval timeout;
    fd_set set;

    /*parse args */
    if (argc != 5) {
	fprintf(stderr, "usage: http_client k|u server port path\n");
	exit(-1);
    }

    server_name = argv[2];
    server_port = atoi(argv[3]);
    server_path = argv[4];



    /* initialize minet */
    if (toupper(*(argv[1])) == 'K') { 
	minet_init(MINET_KERNEL);
    } else if (toupper(*(argv[1])) == 'U') { 
	minet_init(MINET_USER);
    } else {
	fprintf(stderr, "First argument must be k or u\n");
	exit(-1);
    }

    /* create socket */
    sock = minet_socket(SOCK_STREAM);

    if (sock < 0) {
	minet_perror("couldn't make socket ");
	exit(-1);
    }

    // Do DNS lookup
    site = gethostbyname(server_name);

    if (site == NULL) {
	fprintf(stderr, "INVALD SERVER\n");
	exit(-1);
    }


    /* set address */
    memset(&sa, 0, sizeof(sa));
    sa.sin_port = htons(server_port);
    memcpy(&sa.sin_addr, site->h_addr_list[0], site->h_length);
    sa.sin_family = AF_INET;

    /* connect socket */
    rc = minet_connect(sock, &sa);
    if (rc < 0) {
	minet_perror("couldn't connect ");
	exit(-1);
    }
    
    /* send request */
    req = (char *)malloc(strlen("GET  HTTP/1.0\r\n\r\n") +
			 strlen(server_path) + 1);  
    sprintf(req, "GET %s HTTP/1.0\r\n\r\n", server_path);

    rc = write_n_bytes(sock, req, strlen(req));
    if (rc < 0)	{
	minet_perror("couldn't write request to server ");
	exit(-1);
    }

    /* wait till socket can be read */
    FD_ZERO(&set);
    FD_SET(sock, &set);

    memset(&timeout, 0, sizeof(timeout));
    timeout.tv_usec = 0;
    timeout.tv_sec = 20;

    rc = minet_select(sock + 1, &set, 0, 0, 0); //decided not to use timeout for now
    if (rc < 0) {
	minet_perror("select failed ");
    } else if (rc == 0) {
	minet_perror("timeout ");
    }

    if (!FD_ISSET(sock, &set)) {
	fprintf(stderr, "socket can't be read\n");
	exit(-1);
    }
    
    /* first read loop -- read headers */
    while ((rc = minet_read(sock, buf + datalen, BUFSIZE - datalen)) > 0) {
	datalen += rc;  
	buf[datalen] = '\0';

	if ((endheaders = strstr(buf, "\r\n\r\n")) != NULL) {
	    //endheaders[2] = '\0';
	    endheaders += 4;
	    break;
	}
    }

    if (rc < 0) {
	minet_perror("Couldn't get headers ");
	exit(-1);
    }   
    
    /* examine return code */   
    bptr = buf;
    bptr2 = strsep(&bptr," "); //Skip "HTTP/1.0"
    bptr2[strlen(bptr2)] = ' ';  //remove the '\0'
    bptr2 = strsep(&bptr, " "); //bptr2 is now pointing to the return code

    if (atoi(bptr2) != 200) {
	ok = false;
	wheretoprint = stderr;
    }
    bptr2[strlen(bptr2)] = ' '; //remove the '\0'

    /* print first part of response */
    if (!ok) {
	fprintf(wheretoprint, "%s", buf); //print everything read so far
    } else {
	fprintf(wheretoprint, "%s", endheaders); //print everything after headers
    }  

    /* second read loop -- print out the rest of the response */
    while ((rc = minet_read(sock, buf, BUFSIZE)) != 0) {

	if (rc < 0) {	     
	    minet_perror("not all data read ");
	    break;
	}

	datalen += rc;
	buf[rc] = '\0';
	fprintf(wheretoprint, "%s", buf);
    }
        
    //fprintf(wheretoprint,"TOTAL BYTES READ: %d bytes\n",datalen);
    
    /*close socket and deinitialize */
    free(req);
    minet_close(sock);
    minet_deinit();


    if (ok) {
	return 0;
    } else {
	return -1;
    }
}

int write_n_bytes(int fd, char * buf, int count) {
    int rc = 0;
    int totalwritten = 0;

    while ((rc = minet_write(fd, buf + totalwritten, count - totalwritten)) > 0) {
	totalwritten += rc;
    }
    
    if (rc < 0) {
	return -1;
    } else {
	return totalwritten;
    }
}


