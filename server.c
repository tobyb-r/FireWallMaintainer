#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFERLENGTH 256
#define THREADPOOL_SIZE 8

int interactive; // stores 1 if the server is run in -i mode, 0 otherwise
pthread_t threadpool[THREADPOOL_SIZE];

typedef unsigned char ip_address_t[4];

typedef struct address_node {
  struct address_node *next;
  ip_address_t ip_address;
  unsigned short port;
} address_node;

typedef struct request_node {
  atomic_intptr_t next;
  char *request;
} request_node;

typedef struct rule_node {
  // points to first element of query list
  // type address_node *
  atomic_intptr_t queries;

  // least significant bit is 1 if ip is a range, 0 otherwise
  // second least significant bit is 1 if port is a range, 0 otherwise
  int flags;

  union {
    struct {
      ip_address_t low;
      ip_address_t high;
    } ip_range;
    ip_address_t ip_exact;
  };
  union {
    struct {
      unsigned short low;
      unsigned short high;
    } port_range;
    unsigned short port_exact;
  };
} rule_node;

typedef struct {
  atomic_intptr_t next; // next rule_link
  // number of threads reading rule
  // always >=1 if this link is still linked in the list
  atomic_int refcount;
  rule_node *rule;
} rule_link;

typedef struct rulelist_t {
  atomic_intptr_t head;
} rulelist_t;

rulelist_t rulelist;

typedef struct requestlist_t {
  atomic_intptr_t head;
  atomic_intptr_t tail;
} requestlist_t;

requestlist_t requestlist;

typedef struct {
  int fileout;
  char *buf;
} thread_job;

typedef struct work_node {
  struct work_node *next;
  thread_job job;
} work_node;

typedef struct {
  work_node *head;
  work_node *tail;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  int join;
} work_list_t;

work_list_t worklist;

void *thread_work(void *);

void handle_request(thread_job param);

void create_threads() {
  worklist.head = worklist.tail = NULL;
  worklist.mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
  worklist.cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
  worklist.join = 0;

  for (int i = 0; i < THREADPOOL_SIZE; i++) {
    threadpool[i] = (pthread_t)i;
    pthread_create(&threadpool[i], NULL, thread_work, NULL);
  }
}

void join_all_threads() {
  worklist.join = 1;

  for (int i = 0; i < 8; i++) {
    pthread_join(threadpool[i], NULL);
  }
}

void *thread_work(void *_) {
  while (1) {
    pthread_mutex_lock(&worklist.mutex);

    while (worklist.head == NULL && !worklist.join) {
      pthread_cond_wait(&worklist.cond, &worklist.mutex);
    }

    if (worklist.join) { // joining all threads
      pthread_mutex_unlock(&worklist.mutex);
      return NULL;
    }

    if (worklist.head == NULL) {
      pthread_mutex_unlock(&worklist.mutex);
      continue;
    }

    work_node *work = worklist.head;
    worklist.head = work->next;

    if (work->next == NULL)
      worklist.tail = NULL;

    pthread_mutex_unlock(&worklist.mutex);

    handle_request(work->job);

    if (!interactive)
      close(work->job.fileout);

    free(work);
  }

  return NULL;
}

void add_work(thread_job job) {
  work_node *work = malloc(sizeof(work_node));
  work->job = job;

  pthread_mutex_lock(&worklist.mutex);

  if (worklist.tail == NULL) {
    worklist.head = work;
    worklist.tail = work;
  } else {
    worklist.tail->next = work;
    worklist.tail = work;
  }

  pthread_cond_broadcast(&worklist.cond);
  pthread_mutex_unlock(&worklist.mutex);
}

// error handling
// mostly used for sockets
void error(char *msg) {
  fprintf(stderr, "%s\n", msg);
  perror("");
  exit(EXIT_FAILURE);
}

// read from input into buffer
// uses stdin if in -i mode, sokcets otherwise
void readbuf(int fileint, char *buf, int length) {
  int n = read(fileint, buf, BUFFERLENGTH);

  if (n < 0) {
    error("Error reading from socket");
  }

  if (n == 0 && interactive) {
    join_all_threads();
    exit(0);
  }
}

// write from buffer into output
// uses stdout if in -i model, sockets otherwise
void writebuf(int fileint, char *buf) { write(fileint, buf, strlen(buf)); }

// compares ip address
// 0 if left and right are equal
// +ve value if left is greater
// -ve value if right is greater
int ipcmp(ip_address_t left, ip_address_t right) {
  int res = 0;

  for (int i = 0; i < 4; i++) {
    res = left[i] - right[i];

    if (res)
      return res;
  }

  return 0;
}

rule_node parserule(char *str) {
  rule_node new_rule = {0};

  int pos;

  // bc of C padding ip_range.low and ip_exact have the same memory location
  // first ip is stored in ip_exact and ip_range.low
  // if there is a second ip it is stored in ip_range.high
  // pos is used to store the end of the ip segment
  int x = sscanf(str, " %hhu.%hhu.%hhu.%hhu%n-%hhu.%hhu.%hhu.%hhu%n",
                 &new_rule.ip_range.low[0], &new_rule.ip_range.low[1],
                 &new_rule.ip_range.low[2], &new_rule.ip_range.low[3], &pos,
                 &new_rule.ip_range.high[0], &new_rule.ip_range.high[1],
                 &new_rule.ip_range.high[2], &new_rule.ip_range.high[3], &pos);

  if (x == 8) { // lower and upper ip bound
    if (ipcmp(new_rule.ip_range.low, new_rule.ip_range.high) >= 0) {
      // lower ip bound is >= the upper bound
      // Illegal request
      errno = 1;
      return new_rule;
    }

    new_rule.flags |= 1; // set flag bit for ip range
  } else if (x != 4) {   // sscanf didn't find 1 or 2 full ip addresses
    errno = 1;
    return new_rule;
  }

  x = sscanf(&str[pos], " %hu-%hu", &new_rule.port_exact,
             &new_rule.port_range.high);

  if (x == 2) { // two ports written
    if (new_rule.port_range.low > new_rule.port_range.high) {
      errno = 1;
      return new_rule;
    }

    new_rule.flags |= 2; // set flag bit for port range
  } else if (x != 1) {   // no port written
    errno = 1;
    return new_rule;
  }

  return new_rule;
}

// decrements refcount and frees link if refcount == 0
void decr_refcount(rule_link *link) {
  int count = link->refcount;

  while (1) {
    if (count == 1) {
      if (atomic_compare_exchange_strong(&link->refcount, &count, 0)) {
        // free the node
        rule_node *rule = link->rule;
        address_node *query = (address_node *)rule->queries;

        while (query != NULL) {
          address_node *next = query->next;
          free(query);
          query = next;
        }

        free(rule);
        free(link);
      } else {
        continue;
      }
    } else {
      if (atomic_compare_exchange_strong(&link->refcount, &count, count - 1)) {
        return;
      } else {
        continue;
      }
    }
  }
}

int main(int argc, char **argv) {
  socklen_t clilen;
  int sockfd = -1;
  int portno;
  int file, infile;
  char buffer[BUFFERLENGTH];
  struct sockaddr_in6 servaddr, cliaddr;

  if (argc < 2) {
    printf("Usage is '%s port' or '%s -i'\n", argv[0], argv[0]);
    exit(0);
  }

  if (!strcmp(argv[1], "-i")) { // interactive mode
    interactive = 1;
    infile = 0; // stdin
    file = 1;   // stdout
  } else {
    // server mode
    // setup sockets

    // create socket
    sockfd = socket(AF_INET6, SOCK_STREAM, 0);

    if (sockfd < 0) {
      error("Error opening socket");
    }

    memset((char *)&servaddr, 0, sizeof(servaddr));
    portno = atoi(argv[1]);
    servaddr.sin6_family = AF_INET6;
    servaddr.sin6_addr = in6addr_any;
    servaddr.sin6_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
      error("Error binding socket");
    }

    listen(sockfd, 5);
    clilen = sizeof(cliaddr);

    if (sockfd < 0) {
      error("Error opening socket");
    }

    interactive = 0;
  }

  create_threads();

  while (1) {
    if (!interactive) {
      // connect to next client
      file = infile = accept(sockfd, (struct sockaddr *)&cliaddr, &clilen);

      if (file < 0) {
        error("Error on accept");
      }
    }

    // read request
    memset(buffer, 0, BUFFERLENGTH);
    readbuf(infile, buffer, BUFFERLENGTH - 1);

    // request handling function

    void *buf = malloc(strlen(buffer) + 1);
    strcpy(buf, buffer);

    thread_job param = {0};
    param.fileout = file;
    param.buf = buf;

    add_work(param);

    // add request to requestlist
    request_node *new_request_node = malloc(sizeof(request_node));
    new_request_node->next = (atomic_intptr_t)NULL;
    new_request_node->request = buf;

    void *nullptr = NULL;

    // try to set requestlist.tail to new_request_node if this is the first
    // request
    if (atomic_compare_exchange_strong(&requestlist.tail, (intptr_t *)&nullptr,
                                       (intptr_t)new_request_node)) {

      requestlist.head = (atomic_intptr_t)new_request_node;
    } else { // another thread got to it first

      request_node *old = (request_node *)atomic_exchange(
          &requestlist.tail, (intptr_t)new_request_node);

      old->next = (atomic_intptr_t)new_request_node;
    }
  }
}

void handle_request(thread_job job) {
  int file = job.fileout;
  char *buffer = job.buf;

  // execute request
  if (!strcmp(buffer, "R\n")) { // list request history command
    // R
    request_node *current = (request_node *)requestlist.head;

    while (current != NULL) {
      writebuf(file, current->request);
      current = (request_node *)current->next;
    }
  } else if (!strcmp(buffer, "L\n")) { // list all rules and information command
    // L
    rule_link *cur = (rule_link *)rulelist.head;
    rule_link *old;

    while (cur != NULL) {
      cur->refcount++;
      rule_node *rule = cur->rule;

      // output rule
      char formatted_rule_str[256] = "Rule: ";
      char *endptr = &formatted_rule_str[6];

      if (rule->flags & 1) { // ip is a range command
        endptr += sprintf(endptr, "%hhu.%hhu.%hhu.%hhu-%hhu.%hhu.%hhu.%hhu ",
                          rule->ip_range.low[0], rule->ip_range.low[1],
                          rule->ip_range.low[2], rule->ip_range.low[3],
                          rule->ip_range.high[0], rule->ip_range.high[1],
                          rule->ip_range.high[2], rule->ip_range.high[3]);
      } else {
        endptr +=
            sprintf(endptr, "%hhu.%hhu.%hhu.%hhu ", rule->ip_exact[0],
                    rule->ip_exact[1], rule->ip_exact[2], rule->ip_exact[3]);
      }

      if (rule->flags & 2) { // port is a range
        endptr += sprintf(endptr, "%hu-%hu\n", rule->port_range.low,
                          rule->port_range.high);
      } else {
        endptr += sprintf(endptr, "%hu\n", rule->port_exact);
      }

      writebuf(file, formatted_rule_str);

      for (address_node *cur2 = (address_node *)rule->queries; cur2 != NULL;
           cur2 = cur2->next) {
        char formatted_query_str[256];
        sprintf(formatted_query_str, "Query: %hhu.%hhu.%hhu.%hhu %hu\n",
                cur2->ip_address[0], cur2->ip_address[1], cur2->ip_address[2],
                cur2->ip_address[3], cur2->port);
        writebuf(file, formatted_query_str);
      }

      old = cur;
      cur = (rule_link *)cur->next;
      decr_refcount(old);
    }
  } else if (buffer[0] == 'A') { // add new rule
    // A <ip address/ip range> <port/port range>
    errno = 0;

    rule_node result = parserule(&buffer[1]);

    if (errno) { // some issue parsing command
      writebuf(file, "Invalid rule\n");
      return;
    }

    rule_node *new_node = malloc(sizeof(rule_node));
    memcpy(new_node, &result, sizeof(rule_node));
    rule_link *new_link = malloc(sizeof(rule_link));
    new_link->rule = new_node;
    new_link->refcount = 1;

    // add our new_node node to the list
    new_link->next = (intptr_t)rulelist.head;

    while (!atomic_compare_exchange_weak(&rulelist.head, (intptr_t *)&new_link->next,
                                         (intptr_t)new_link))
      ;

    writebuf(file, "Rule added\n");
  } else if (buffer[0] == 'C') { // check if ip matches rules
    // C <IP address> <port>
    ip_address_t ip;
    unsigned short port;

    int x = sscanf(buffer, "C %hhu.%hhu.%hhu.%hhu %hu", &ip[0], &ip[1], &ip[2],
                   &ip[3], &port);

    if (x < 5) { // didn't successfully read command
      writebuf(file, "Illegal IP address or port specified\n");
      return;
    }

    int connection_accepted = 0; // if a rule accepts the connection

    rule_link *cur = (rule_link *)rulelist.head;
    rule_link *old;

    while (cur != NULL) {
      cur->refcount++;
      rule_node *rule = cur->rule;

      if (rule->flags & 1) { // ip is range
        if ((ipcmp(ip, rule->ip_range.low) < 0) ||
            (ipcmp(ip, rule->ip_range.high) > 0)) {
          old = cur;
          cur = (rule_link *)cur->next;
          decr_refcount(old);
          continue;
        }
      } else { // ip is exact
        if (ipcmp(ip, rule->ip_exact)) {
          old = cur;
          cur = (rule_link *)cur->next;
          decr_refcount(old);
          continue;
        }
      }

      if (rule->flags & 2) { // port is range
        if (rule->port_range.low > port || port > rule->port_range.high) {
          old = cur;
          cur = (rule_link *)cur->next;
          decr_refcount(old);
          continue;
        }
      } else { // port is exact
        if (rule->port_exact != port) {
          old = cur;
          cur = (rule_link *)cur->next;
          decr_refcount(old);
          continue;
        }
      }

      connection_accepted = 1;
      int query_found =
          0; // if we find the query already in the list of queries

      for (address_node *cur2 = (address_node *)rule->queries; cur2 != NULL;
           cur2 = cur2->next) {
        if (!ipcmp(cur2->ip_address, ip) && port == cur2->port) {
          query_found = 1;
          break;
        }
      }

      if (!query_found) {
        address_node *new_query = malloc(sizeof(address_node));

        memcpy(new_query->ip_address, ip, 4);
        new_query->port = port;

        new_query->next = (address_node *)rule->queries;

        while (!atomic_compare_exchange_weak(
            &rule->queries, (intptr_t *)&new_query->next, (intptr_t)new_query))
          ;
      }

      decr_refcount(cur);

      break;
    }

    if (connection_accepted) {
      writebuf(file, "Connection accepted.\n");
    } else {
      writebuf(file, "Connection rejected.\n");
    }
  } else if (buffer[0] == 'D') { // delete a rule from store
    // D <rule>
    errno = 0;

    rule_node rule = parserule(&buffer[1]);

    if (errno) { // some issue parsing command
      writebuf(file, "Rule invalid\n");
      return;
    }

    int rule_found = 0;

    atomic_intptr_t *cur = &rulelist.head;

    while ((*cur) != 0) {
      intptr_t old = *cur;
      rule_link *link = (rule_link *)old;
      link->refcount++;

      rule_node cur_rule = *link->rule;

      if (cur_rule.flags != rule.flags) {
        cur = &link->next;
        decr_refcount(link);
        continue;
      }

      if (cur_rule.flags & 1) { // ip is range
        if (ipcmp(cur_rule.ip_range.low, rule.ip_range.low) ||
            ipcmp(cur_rule.ip_range.high, rule.ip_range.high)) {
          cur = &link->next;
          decr_refcount(link);
          continue;
        }
      } else { // ip is exact
        if (ipcmp(cur_rule.ip_exact, rule.ip_exact)) {
          cur = &link->next;
          decr_refcount(link);
          continue;
        }
      }

      if (cur_rule.flags & 2) { // port is range
        if (cur_rule.port_range.low != rule.port_range.low ||
            cur_rule.port_range.high != rule.port_range.high) {
          cur = &link->next;
          decr_refcount(link);
          continue;
        }
      } else { // port is exact
        if (cur_rule.port_exact != rule.port_exact) {
          cur = &link->next;
          decr_refcount(link);
          continue;
        }
      }

      if (atomic_compare_exchange_strong(cur, &old, link->next)) {
        // successfully unlinked node
        decr_refcount(link);
        decr_refcount(link);
      } else {
        decr_refcount(link);
        // another thread unlinked this node. restart with the new node cur
        // points to
        continue;
      }

      rule_found = 1;
      break;
    }

    if (rule_found) {
      writebuf(file, "Rule deleted\n");
    } else {
      writebuf(file, "Rule not found\n");
    }
  } else { // didn't match any command
    writebuf(file, "Illegal request\n");
  }

  return;
}
