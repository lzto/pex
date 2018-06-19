
struct non_trivial_struct 
{
	int a,b,c,d,e,f,g;
};

int capable(int i)
{
	return i;
}


//////////////////
//global function pointer
void (*fun_ptr)(int);
void (*xxx_ptr)(struct non_trivial_struct*);

void fun(int i)
{
	printf("this is protected function(used as fptr) %d\n", i);
}

void xxx(struct non_trivial_struct *p)
{
	printf("this is protected xxx(used as fptr) %p\n", p);
}

void yyy(struct non_trivial_struct *p)
{
	printf("this is protected xxx(used as fptr) %p\n", p);
}


void device_function()
{
	printf("this is device function\n");
}

void bar()
{
	printf("This is protected function\n");
}

void foo()
{
	printf("do init\n");
	fun_ptr = &fun;
	xxx_ptr = &yyy;
}

void start_kernel()
{
	foo();
}

void x86_64_start_kernel()
{
	start_kernel();
}

void bar_ioctl()
{
    struct non_trivial_struct a;
	if (capable(1))
	{
		bar();
		fun_ptr(1);
		xxx(&a);
		return;
	}
	zoo();
}

void bar_open()
{
    struct non_trivial_struct a;
	bar();
	fun_ptr(0);
    xxx_ptr(&a);
}

//dummy function to help reason about data flow
void dummy()
{
    struct non_trivial_struct b;
    x86_64_start_kernel();
    bar_open();
    xxx_ptr = &xxx;
    xxx_ptr(&b);
}

