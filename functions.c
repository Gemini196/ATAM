#include <stdio.h>


int add(int a, int b) {
    return a+b;
}

static int sub(int a, int b) {
    return a-b;
}

void nothing(int n) {
    for (int i = 0; i < n; i++);    
}

char abc() {
    return 'a';
}

void print_t(){
    printf("t");
}

int main(int argc, char *argv[])
{
    return 0;
}