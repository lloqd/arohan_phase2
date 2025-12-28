long long _init()
{
    unsigned long v1;  // rax

    return v1;
}

extern unsigned long long g_403f68;
extern unsigned long long g_403f70;

void sub_401010()
{
    unsigned long v0;  // [bp-0x8]

    v0 = g_403f68;
    goto g_403f70;
}

extern FILE stderr;
extern FILE stdin;
extern FILE stdout;

int main()
{
    unsigned int v0;  // [bp-0x24]
    unsigned long v1;  // [bp-0x20]
    unsigned long long v2;  // [bp-0x18]
    unsigned long long v3;  // [bp-0x8]
    unsigned long long v5;  // r12
    unsigned long long v6;  // rbx
    unsigned long v7;  // fs

    v3 = v5;
    v2 = v6;
    v1 = *((long long *)(40 + v7));
    setbuf(*((long long *)&stdout), NULL);
    setbuf(*((long long *)&stdin), NULL);
    setbuf(*((long long *)&stderr), NULL);
    while (true)
    {
        while (true)
        {
            menu();
            scanf("%d", &v0);
            if (v0 != 2)
                break;
            action();
        }
        if (v0 == 3)
            break;
        if (v0 == 1)
            make_char();
        else
            puts("wrong option");
    }
    exit(0); /* do not return */
}

void _start()
{
    char v0;  // [bp+0x0]

    _start_c(&v0); /* do not return */
}

void _start_c(char *a0)
{
    __libc_start_main(main, *((int *)&a0), a0 + 8, _init, _fini, 0); /* do not return */
}


void deregister_tm_clones()
{
    return;
}


void register_tm_clones()
{
    return;
}

extern char __bss_start;
extern unsigned long long __dso_handle;
extern unsigned long long g_403fd8;

void __do_global_dtors_aux()
{
    if (__bss_start)
    {
        return;
    }
    else if (g_403fd8)
    {
        __cxa_finalize(__dso_handle); /* do not return */
    }
    else
    {
        deregister_tm_clones();
        __bss_start = 1;
        return;
    }
}

void frame_dummy()
{
    register_tm_clones();
    return;
}

void menu()
{
    puts("---MUD---");
    puts("1.Make a new Character");
    puts("2.Defeat the Yellow King");
    puts("3.Return");
    printf(">>");
    return;
}

extern struct_0 *list;

void make_char()
{
    unsigned int v0;  // [bp-0x14]
    unsigned long v1;  // [bp-0x10]
    char v3[33];  // rbx
    unsigned long v4;  // fs

    v0 = 0;
    puts("enter index:");
    scanf("%d", &v0);
    if (v0 > 15)
    {
        puts("wrong index");
        return;
    }
    v3 = malloc(33);
    puts("Enter the class");
    printf("1.magician\n2.swordsman\n3.thief\n>>");
    scanf("%hhu", (char [33])&v3[32]);
    if (v3[32] - 1 <= 2)
    {
        printf("Enter the name for character\n>>");
        v3[read(0, v3, 32)] = 0;
        (&list)[v0] = v3;
        return;
    }
    if (v3[32])
    {
        puts("Wrong class");
        if (v1 != *((long long *)(40 + v4)))
            __stack_chk_fail(); /* do not return */
    }
    else
    {
        puts("You aren't D3rdlord3");
        if (v1 != *((long long *)(40 + v4)))
            __stack_chk_fail(); /* do not return */
    }
    free(v3);
    return;
}

char count_char(char *a0, unsigned long a1, unsigned int a2)
{
    uint128_t v0;  // [bp-0x138]
    char v1;  // [bp-0x128]
    unsigned int v3;  // ebx
    unsigned long v4;  // rbp

    v3 = 0;
    v0 = 0;
    memset(&v1, 0, 240);
    while (true)
    {
        v4 = v3;
        if (v4 >= strlen(a0))
            break;
        v3 += 1;
        *((char *)&v0 + a0[v4]) = *((char *)&v0 + a0[v4]) + 1;
    }
    return a2 < *((char *)&v0 + (a1 & 4294967295));
}

extern struct struct_0 *list[4];

void action()
{
    char v0;  // [bp-0x6c], Other Possible Types: unsigned int
    char v1;  // [bp-0x68]
    unsigned long v3;  // rax
    unsigned long v4;  // rbx
    unsigned long v5;  // rax
    unsigned long v6;  // cc_ndep

    puts("enter index:");
    scanf("%d", &v0);
    v3 = v0;
    if ((unsigned int)v3 > 15)
    {
        puts("wrong index");
        return;
    }
    v4 = list[v3];
    printf("You chose %s \n", v4);
    v5 = *((char *)(v4 + 32));
    if ((char)v5 != 2)
    {
        if ((char)_ccall(6, 5, v5 & 255, 2, v6))
        {
            if (!(char)v5)
            {
                puts("You may leave a message about your encounter and leave..");
                read(0, &v1, 48);
                if (count_char(&v1, 37, 13))
                {
                    puts("No one can handle that much knowledge..");
                    return;
                }
                puts("The message left for other adventurers..");
                printf(&v1);
                return;
            }
        }
        else
        {
            if ((char)v5 != 3)
                return;
        }
    }
    puts("You have lost");
    list[v0] = 0;
    free(v4);
    return;
}

long long _fini()
{
    unsigned long v1;  // rax

    return v1;
}
