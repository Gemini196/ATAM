#include <stdio.h>
#include <stdbool.h>

extern int mul(int a, int b);
extern int div(int a, int b);
extern bool bigger(int a, int b);

int bar(int n);
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

int factorial(int n) 
{
    if(n == 1 || n < 1)
        return 1;
    return factorial(n - 1) * n;
}

int foo(int n)
{
    if(n <= 1) {
        return 1;
    }
    return bar(n - 1) + 1;
}

int bar(int n) 
{
    if(n <= 1) {
        return 0;
    }
    return foo(n - 2) * 2;
}

int main(int argc, char *argv[])
{
    printf("toast\n");
    add(2,3);
    factorial(3);
    sub(10, 5);
    mul(1, 1);
    nothing(5);
    add(0, 0);
    factorial(7);
    mul(2, 2);
    abc();
    nothing(17);
    div(10, 5);
    factorial(0);
    mul(100000, 4);
    add(42, 42);
    add(1000000, 45000);
    bigger(10, 9);
    div(16, 4);
    factorial(10);
    add(3, 7);

    foo(1);
    bar(10);
    foo(10);
    
    return 0;
}