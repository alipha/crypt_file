#include <sodium.h>
#include <stdio.h>
#include <stdint.h>

int main() {
    if(sodium_init() == -1)
        return 1;
    puts("hi");
    return 0;
}

