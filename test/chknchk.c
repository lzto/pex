#include <stdio.h>
/*
 * This is a critical function
 */
void critical_function()
{
    printf("\n");
}

/*
 * normally only uid==0 can reach critical_function()
 */
void foo(int uid)
{
    if (uid==0)
    {
        critical_function();
    }
}

/*
 * but bar can also reach to critical_function();
 */
void bar(int uid)
{
    critical_function();
}


