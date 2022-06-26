#include <stdbool.h>

int mul(int a, int b)
{
    return a * b;
}

int div(int a, int b)
{
    return a / b;
}

bool bigger(int a, int b)
{
    return (a < b);
}

int sumOfAllNums(int n)
{
    if(n <= 0)
        return 0;
    return n + sumOfAllNums(n - 1);
}
