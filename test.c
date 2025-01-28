#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <stdint.h>


#define TOP_BITS 

typedef unsigned char ip_address_t[4];

struct stuff {
    union {
        struct {
            unsigned long ptr : 48;
            unsigned int refcount : 15;
            _Bool flag: 1;
        } things;
        atomic_intptr_t next;
    };
};

int main() {

    char *x = "Hello World\n";
    printf("size is %d\n", sizeof(struct stuff));

    struct stuff y = {0};
    y.things.ptr = (intptr_t) x;
    struct stuff z = y;
    struct stuff _y = y;

    printf("%d, %d, %ld, %ld\n", y.things.flag, y.things.refcount, y.things.ptr, y.next);

    z.things.flag = 1;
    z.things.refcount += 30 + INT32_MAX;

    atomic_compare_exchange_strong(&y, &_y, z);
    printf("%d, %d, %ld, %ld\n", y.things.flag, y.things.refcount, y.things.ptr, y.next);
}
