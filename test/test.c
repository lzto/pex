void bar_ioctl();
void bar_open();
void bar_private(){};

struct file_operations {
   void (*ioctl) ();
   void (*open)();
   void (*private)();
} bar_file = 
{
    .ioctl = bar_ioctl,
    .open = bar_open,
    .private = bar_private,
};

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

//critical function
void fun(int i)
{
	printf("this is protected function(used as fptr) %d\n", i);
}

//critical function
void xxx(struct non_trivial_struct *p)
{
	printf("this is protected xxx(used as fptr) %p\n", p);
}

//non-critical function
void yyy(struct non_trivial_struct *p)
{
	printf("this is protected yyy(used as fptr) %p\n", p);
}

//un-used function
void device_function()
{
	printf("this is device function\n");
}

//critical function
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
        bar_file.private();
		return;
	}
	zoo();//external symbol
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

void SyS_private()
{
    bar_file.private();
}

void SyS_ioctl()
{
    bar_file.ioctl();
}

void SyS_open()
{
    bar_file.open();
}



