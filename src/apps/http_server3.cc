#include "minet_socket.h"
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/stat.h>


#define FILENAMESIZE 100
#define BUFSIZE 1024

typedef enum \
{NEW,READING_HEADERS,WRITING_RESPONSE,READING_FILE,WRITING_FILE,CLOSED} states;

typedef struct connection_s connection;
typedef struct connection_list_s connection_list;

struct connection_s
{
  int sock;
  int fd;
  char filename[FILENAMESIZE+1];
  char buf[BUFSIZE+1];
  char *endheaders;
  bool ok;
  long filelen;
  states state;
  int headers_read,response_written,file_read,file_written;

  connection *next;
};

struct connection_list_s
{
  connection *first,*last;
};

void add_connection(int,connection_list *);
void insert_connection(int,connection_list *);
void init_connection(connection *con);


int writenbytes(int,char *,int);
int readnbytes(int,char *,int);
void read_headers(connection *);
void write_response(connection *);
void read_file(connection *);
void write_file(connection *);

int main(int argc,char *argv[])
{
  int server_port;
  int sock,sock2;
  struct sockaddr_in sa,sa2;
  int rc;
  fd_set readlist,writelist;
  connection_list connections;
  connection *i;
  int maxfd;

  /* parse command line args */
  if (argc != 3)
  {
    fprintf(stderr, "usage: http_server3 k|u port\n");
    exit(-1);
  }
  server_port = atoi(argv[2]);
  if (server_port < 1500)
  {
    fprintf(stderr,"INVALID PORT NUMBER: %d; can't be < 1500\n",server_port);
    exit(-1);
  }

  /* initialize and make socket */
  if (toupper(*(argv[1]))=='K') { 
    minet_init(MINET_KERNEL);
  } else if (toupper(*(argv[1]))=='U') { 
    minet_init(MINET_USER);
  } else {
    fprintf(stderr, "First argument must be k or u\n");
    exit(-1);
  }
  sock = minet_socket(SOCK_STREAM);
  if (sock < 0)
  {
    minet_perror("couldn't make socket\n");
    exit(-1);
  }

  /* set server address*/
  memset(&sa, 0, sizeof sa);
  sa.sin_port = htons(server_port);
  sa.sin_addr.s_addr = htonl(INADDR_ANY);
  sa.sin_family = AF_INET;

  /* bind listening socket */
  rc = minet_bind(sock,&sa);
  if (rc < 0)
  {
    
    minet_perror("couldn't bind\n");
    exit(-1);
  }

  /* start listening */
  rc = minet_listen(sock,5);
  if (rc < 0)
  {
    minet_perror("couldn't listen\n");
    exit(-1);
  }

  /* connection handling loop */
  connections.first = NULL; 
  connections.last = NULL;
  maxfd = sock;
  while(1)
  {
    /* create read and write lists */
    FD_ZERO(&readlist);
    FD_ZERO(&writelist);
    FD_SET(sock,&readlist);
    for (i = connections.first; i != NULL; i = i->next)
    {
      if (i->state == CLOSED)
	continue;
      else if ((i->state == READING_HEADERS)||
	       (i->state == NEW))
      {
	FD_SET(i->sock,&readlist);
	if (i->sock > maxfd)
	  maxfd = i->sock;
      }
      else if ((i->state == WRITING_RESPONSE)||
	       (i->state == WRITING_FILE))
      {	
	FD_SET(i->sock,&writelist);
	if (i->sock > maxfd)
	  maxfd = i->sock;
      }
      else if (i->state == READING_FILE)
      {
	FD_SET(i->fd,&readlist);
	if (i->fd > maxfd)
	  maxfd = i->fd;
      }
    }

    /* do a select */
    rc = select(maxfd+1,&readlist,&writelist,0,0);
    while ((rc < 0) && (errno == EINTR))
      rc = select(maxfd+1,&readlist,&writelist,0,0);
    if (rc < 0)
    {
      minet_perror("select failed ");
      continue;
    }

    /* process sockets that are ready */
    for (i = connections.first; i != NULL; i=i->next)
    {
      if (i->state == CLOSED)
	continue;
      if (i->state == NEW)
      {
	init_connection(i);
	i->state = READING_HEADERS;
	read_headers(i);
      }
      else if (i->state == READING_HEADERS &&
	       FD_ISSET(i->sock,&readlist))
	read_headers(i);
      else if (i->state == WRITING_RESPONSE &&
	       FD_ISSET(i->sock,&writelist))
	write_response(i);
      else if (i->state == READING_FILE &&
	       FD_ISSET(i->fd,&readlist))
	read_file(i);
      else if (i->state == WRITING_FILE &&
	       FD_ISSET(i->sock,&writelist))
	write_file(i);
    }
    if (FD_ISSET(sock,&readlist))
    {
      sock2 = minet_accept(sock,&sa2);
      if (sock2 < 0)
	minet_perror("couldn't accept ");
      else
      { 
	insert_connection(sock2,&connections);
        fcntl(sock2,F_SETFL,O_NONBLOCK);
      }
    }
  }
}

void read_headers(connection *con)
{
  int sock2 = con->sock;
  char *bptr,*endheaders;
  struct stat filestat;
  int rc;
  char *buf = con->buf;

  /* first read loop -- get request and headers*/
  while ((rc = minet_read(sock2,buf+con->headers_read,BUFSIZE-con->headers_read)) > 0)
  {
    con->headers_read += rc;  
    con->buf[con->headers_read] = '\0';
    endheaders = strstr(con->buf,"\r\n\r\n");
    if (endheaders != NULL)
    {
      endheaders[2] = '\0';
      endheaders += 4;
      break;
    }
  }
  if (rc < 0)
  {
      if (errno == EAGAIN)
	return;
      minet_perror("Error reading request\n");
      minet_close(sock2);
      return;
  }

  /* parse request to get file name */
  /* Assumption: this is a GET request and filename contains no spaces*/
  con->ok = true;
  bptr = con->buf;
  strsep(&bptr," ");
  if (bptr == NULL) //Not a valid request
  {
      con->ok = false;
  }
  /* get file name and size, set to non-blocking */
  else
  {
    /* get name */
    bptr = strsep(&bptr," ");
    if (strlen(bptr) > FILENAMESIZE)
      {
	fprintf(stderr,"Filename too big\n");
	minet_close(sock2);
	con->state = CLOSED;
	return;
      }
    if (bptr[0] == '/')
      bptr += 1;
    strcpy(con->filename,bptr);
    
    /* try opening the file */
    con->fd = open(con->filename,O_RDONLY);
    if (con->fd < 0)
	con->ok = false;
    else
    {
      /* set to non-blocking, get size */
      fcntl(con->fd,F_SETFL,O_NONBLOCK);
      rc = stat(con->filename,&filestat);
      if (rc < 0)
	{
	  perror("error getting file stat ");
	  //minet_close(sock2);
	  return;
	}
      else
	con->filelen = filestat.st_size;
    }
  }

  con->state = WRITING_RESPONSE;
  write_response(con);
}

void write_response(connection *con)
{
  int sock2 = con->sock;
  int rc;
  int written = con->response_written;
  char *ok_response_f = "HTTP/1.0 200 OK\r\n"\
                      "Content-type: text/plain\r\n"\
                      "Content-length: %d \r\n\r\n";
  char ok_response[100];
  char *notok_response = "HTTP/1.0 404 FILE NOT FOUND\r\n"\
                         "Content-type: text/html\r\n\r\n"\
                         "<html><body bgColor=black text=white>\n"\
                         "<h2>404 FILE NOT FOUND</h2>\n"\
                         "</body></html>\n";
  /* send response */
  if (con->ok)
  {
    /* send headers */
    sprintf(ok_response,ok_response_f,con->filelen);
    rc = writenbytes(sock2,ok_response+written,strlen(ok_response)-written);
    if (rc < 0)
    {
      if (errno == EAGAIN)
	return;
      minet_perror("error writing response ");
      con->state = CLOSED;
      minet_close(sock2);
      return;
    }
    con->state = READING_FILE;
    read_file(con);
  }
  else
  {
    rc = writenbytes(sock2,notok_response+written,strlen(notok_response)-written);
    if (rc < 0)
    {
      if (errno == EAGAIN)
	return;
      minet_perror("error writing response ");
    }
    con->state = CLOSED;
    minet_close(con->sock);
  }  
}

void read_file(connection *con)
{
  int rc;

    /* send file */
  rc = read(con->fd,con->buf,BUFSIZE);
  if (rc < 0)
  { 
    if (errno == EAGAIN)
      return;
    fprintf(stderr,"error reading requested file %s\n",con->filename);
    return;
  }
  else if (rc == 0)
  {
    con->state = CLOSED;
    minet_close(con->sock);
  }
  else
  {
    con->file_read = rc;
    con->state = WRITING_FILE;
    write_file(con);
  }
}

void write_file(connection *con)
{
  int towrite = con->file_read;
  int written = con->file_written;
  int rc = writenbytes(con->sock, con->buf+written, towrite-written);
  if (rc < 0)
  {
    if (errno == EAGAIN)
      return;
    minet_perror("error writing response ");
    con->state = CLOSED;
    minet_close(con->sock);
    return;
  }
  else
  {
    con->file_written += rc;
    if (con->file_written == towrite)
    {
      con->state = READING_FILE;
      con->file_written = 0;
      read_file(con);
    }
    else
      printf("shouldn't happen\n");
  }
}

int readnbytes(int fd,char *buf,int size)
{
  int rc = 0;
  int totalread = 0;
  while ((rc = minet_read(fd,buf+totalread,size-totalread)) > 0)
    totalread += rc;

  if (rc < 0)
  {
    return -1;
  }
  else
    return totalread;
}  

int writenbytes(int fd,char *str,int size)
{
  int rc = 0;
  int totalwritten =0;
  while ((rc = minet_write(fd,str+totalwritten,size-totalwritten)) > 0)
    totalwritten += rc;
  
  if (rc < 0)
    return -1;
  else
    return totalwritten;
}


// inserts a connection in place of a closed connection
// if there are no closed connections, appends the connection 
// to the end of the list

void insert_connection(int sock,connection_list *con_list)
{
  connection *i;
  for (i = con_list->first; i != NULL; i = i->next)
  {
    if (i->state == CLOSED)
    {
      i->sock = sock;
      i->state = NEW;
      return;
    }
  }
  add_connection(sock,con_list);
}
 
void add_connection(int sock,connection_list *con_list)
{
  connection *con = (connection *) malloc(sizeof(connection));
  con->next = NULL;
  con->state = NEW;
  con->sock = sock;
  if (con_list->first == NULL)
    con_list->first = con;
  if (con_list->last != NULL)
  {
    con_list->last->next = con;
    con_list->last = con;
  }
  else
    con_list->last = con;
}

void init_connection(connection *con)
{
  con->headers_read = 0;
  con->response_written = 0;
  con->file_read = 0;
  con->file_written = 0;
}
