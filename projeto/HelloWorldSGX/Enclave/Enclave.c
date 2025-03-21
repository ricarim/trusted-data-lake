#include <stdarg.h>
#include <stdio.h>  
#include "Enclave_t.h"

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_printf(buf);
}

void ecall_entrypoint() {
    printf("Hello from inside SGX Enclave!\n");
}


