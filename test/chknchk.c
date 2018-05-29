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
void foo(int uid, int cap)
{
    if (uid==0)
    {
        critical_function();
    }
}

/*
 * but bar can also reach to critical_function();
 */
void bar(int uid, int cap)
{
    if (cap==0)
        critical_function();
}


int main(int argc, char** argv)
{
#if 1
    int uid = 0;
    int cap = 0;
    //default is 0
    if (argc>0)
    {
        uid = atoi(argv[1]);
        cap = atoi(argv[2]);
    }
#else
    int uid = atoi(argv[1]);
    int cap = atoi(argv[2]);
#endif
    //a phi node here
    printf("uid=%d, cap=%d\n", uid, cap);
    foo(uid, cap);
    bar(uid, cap);
    return 0;
}

