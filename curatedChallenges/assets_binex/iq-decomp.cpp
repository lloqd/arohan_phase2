extern struct_0 *g_403ff8;

void _init()
{
    if (g_403ff8)
        g_403ff8();
    return;
}

extern unsigned long long g_404008;
extern unsigned long long g_404010;

void sub_401020()
{
    unsigned long v0;  // [bp-0x8]

    v0 = g_404008;
    goto g_404010;
}

void _start(unsigned long a0, unsigned long a1, unsigned long long a2)
{
    unsigned long long v1;  // [bp+0x0]
    unsigned long v2;  // [bp+0x8]
    unsigned long long v3;  // rax

    v1 = v3;
    __libc_start_main(main, v1, &v2, __libc_csu_init, __libc_csu_fini, a2, &v1, v1); /* do not return */
}

void sub_40112e()
{
    [D] Unsupported jumpkind Ijk_SigTRAP at address 4198702()
}

void _dl_relocate_static_pie()
{
    return;
}

void deregister_tm_clones()
{
    return;
}

void register_tm_clones()
{
    return;
}

extern char completed.8061;

void __do_global_dtors_aux()
{
    if (!completed.8061)
    {
        deregister_tm_clones();
        completed.8061 = 1;
    }
    return;
}

void frame_dummy()
{
    register_tm_clones();
    return;
}

typedef struct FILE_t {
    unsigned int _flags;
    char padding_4[4];
    char * _IO_read_ptr;
    char * _IO_read_end;
    char * _IO_read_base;
    char * _IO_write_base;
    char * _IO_write_ptr;
    char * _IO_write_end;
    char * _IO_buf_base;
    char * _IO_buf_end;
    char * _IO_save_base;
    char * _IO_backup_base;
    char * _IO_save_end;
    struct _IO_marker *_markers;
    struct _IO_FILE * _chain;
    unsigned int _fileno;
    unsigned int _flags2;
    unsigned int _old_offset;
    char padding_7c[4];
    unsigned short _cur_column;
    char _vtable_offset;
    char _shortbuf[1];
    char padding_84[4];
    struct pthread_mutex_t *_lock;
    unsigned long long _offset;
    struct _IO_codecvt * _codecvt;
    struct _IO_wide_data * _wide_data;
    struct _IO_FILE * _freeres_list;
    char __pad5;
    char padding_b1[7];
    unsigned int _mode;
    char _unused2[20];
} FILE_t;

typedef struct _IO_marker {
    struct _IO_marker * _next;
    FILE * _sbuf;
    unsigned int _pos;
} _IO_marker;

typedef struct _IO_FILE {
} _IO_FILE;

typedef struct pthread_mutex_t {
} pthread_mutex_t;

typedef struct _IO_codecvt {
    _IO_iconv_t __cd_out;
} _IO_codecvt;

typedef struct _IO_wide_data {
    wchar_t * _IO_read_ptr;
    wchar_t * _IO_read_end;
    wchar_t * _IO_read_base;
    wchar_t * _IO_write_base;
    wchar_t * _IO_write_ptr;
    wchar_t * _IO_write_end;
    wchar_t * _IO_buf_base;
    wchar_t * _IO_buf_end;
    wchar_t * _IO_save_base;
    wchar_t * _IO_backup_base;
    wchar_t * _IO_save_end;
    __mbstate_t _IO_state;
    char padding_5d[3];
    __mbstate_t _IO_last_state;
    char padding_65[3];
    unsigned short _shortbuf[1];
    _IO_jump_t _wide_vtable;
} _IO_wide_data;

typedef struct FILE {
} FILE;

typedef struct _IO_iconv_t {
} _IO_iconv_t;

typedef struct __mbstate_t {
    unsigned int __count;
    char __value;
} __mbstate_t;

typedef struct _IO_jump_t {
} _IO_jump_t;

long long win3(unsigned int a0, unsigned int a1, unsigned int a2)
{
    char v0[44];  // [bp-0x58]
    char v1[9];  // [bp-0x2c]
    char v2[9];  // [bp-0x23]
    char v3[9];  // [bp-0x1a]
    char v4;  // [bp-0x11]
    FILE_t *v5;  // [bp-0x10]

    if (a0 == 3735928559 && a1 == 3736074958 && a2 == -17970434)
    {
        puts("Congratulations. You are deserving of you reward\n");
        sprintf(&v3, "%X", a0);
        sprintf(&v2, "%X", a1);
        sprintf(&v1, "%X", a2);
        sprintf(&v0, "%s%s%s.txt", &v3, &v2, &v1);
        v5 = fopen(&v0, "r");
        if (!v5)
        {
            perror("Error opening file");
            return 1;
        }
        while (true)
        {
            v4 = fgetc(v5);
            if (v4 == 255)
                break;
            putchar(v4);
        }
        fclose(v5);
        return 0;
    }
    puts("You have failed to bring all 3 artifacts. Return and try again.");
    exit(1); /* do not return */
}

extern FILE_t *stdin;

long long win2(unsigned int a0)
{
    void* v0;  // [bp-0x38]
    void* v1;  // [bp-0x30]
    char v2;  // [bp-0x1e]
    char v3;  // [bp-0x11]
    void* v4;  // [bp-0x10]

    if (a0 != 3735928559)
    {
        puts("You have failed to bring the artifact to the this temple. Return and try again");
        exit(1); /* do not return */
    }
    sprintf(&v2, "%X.txt", a0);
    puts("You have done well, however you still have one final test. You must now bring 3 artifacts of [0xDEADBEEF] [0xDEAFFACE] and [0xFEEDCAFE]. You must venture out and find the temple yourself. I believe in you");
    v4 = fopen(&v2, "r");
    if (!v4)
    {
        perror("Error opening file");
        return 1;
    }
    while (true)
    {
        v3 = fgetc(v4);
        if (v3 == 255)
            break;
        putchar(v3);
    }
    fclose(v4);
    v0 = 0;
    v1 = 0;
    puts("Final Test: ");
    fgets(&v0, 0x100, stdin);
    return 1;
}

extern FILE_t *stdin;

long long win1()
{
    void* v0;  // [bp-0x28]
    void* v1;  // [bp-0x20]
    char v2;  // [bp-0x11]
    void* v3;  // [bp-0x10]

    puts("You have passed the first challenge. The next one won't be so simple.");
    printf("Lesson 2 Arguments: Research how arguments are passed to functions and apply your learning. Bring the artifact of 0xDEADBEEF to the temple of %p to claim your advance.", win2);
    v3 = fopen("flag1.txt", "r");
    if (!v3)
    {
        perror("Error opening file");
        return 1;
    }
    while (true)
    {
        v2 = fgetc(v3);
        if (v2 == 255)
            break;
        putchar(v2);
    }
    fclose(v3);
    v0 = 0;
    v1 = 0;
    puts("Continue: ");
    fgets(&v0, 96, stdin);
    return 0;
}

extern FILE_t *stdin;

long long askQuestion(char *a0, unsigned long long *a1, unsigned int a2, char *a3)
{
    char v0;  // [bp-0x28]
    unsigned int v1;  // [bp-0xc]

    puts(a0);
    for (v1 = 0; v1 < a2; v1 += 1)
    {
        printf("[%d] %s\n", v1 + 1, a1[v1]);
    }
    printf("> ");
    if (!fgets(&v0, 16, stdin))
    {
        puts("Input error!");
        return 0;
    }
    (&v0)[strcspn(&v0, "\n")] = 0;
    if (strcmp(&v0, a3))
    {
        puts("Incorrect!");
        return 0;
    }
    puts("Correct!");
    return 1;
}

extern FILE_t *stderr;
extern FILE_t *stdin;
extern FILE_t *stdout;

int main()
{
    void* v0;  // [bp-0x98]
    void* v1;  // [bp-0x90]
    unsigned long long v2;  // [bp-0x88]
    unsigned long long v3;  // [bp-0x80]
    unsigned long long v4;  // [bp-0x78]
    unsigned long long v5;  // [bp-0x70]
    unsigned long long v6;  // [bp-0x68]
    unsigned long long v7;  // [bp-0x60]
    unsigned long long v8;  // [bp-0x58]
    unsigned long long v9;  // [bp-0x50]
    unsigned long long v10;  // [bp-0x48]
    unsigned long long v11;  // [bp-0x40]
    char *v12;  // [bp-0x38]
    char *v13;  // [bp-0x30]
    char *v14;  // [bp-0x28]
    char *v15;  // [bp-0x20]
    char *v16;  // [bp-0x18]
    char *v17;  // [bp-0x10]

    setvbuf(stdout, NULL, 2, 0);
    setvbuf(stderr, NULL, 2, 0);
    setvbuf(stdin, NULL, 2, 0);
    puts("=========== Welcome to the Exploitation Dojo ==============");
    puts("You must first prove your knowledge if you want access to my secrets");
    v17 = "Question 1: In an x86-64 Linux architecture, a function reads its arguments from the stack, left-to-right. True or False?";
    v10 = "True";
    v11 = "False";
    v16 = "2";
    if (!(int)askQuestion(v17, &v10, 2, v16))
        return 4294967295;
    v15 = "Question 2: In an x86-64 Linux architecture, which register holds the first integer or pointer argument to a function?";
    v6 = "RDI";
    v7 = "RSI";
    v8 = "RAX";
    v9 = "RCX";
    v14 = "1";
    if (!(int)askQuestion(v15, &v6, 4, v14))
        return 4294967295;
    v13 = "Question 3: In an x86-64 Linux architecture, where is the return value of a function typically stored?";
    v2 = "RDX";
    v3 = "RSP";
    v4 = "RBP";
    v5 = "RAX";
    v12 = "4";
    if ((int)askQuestion(v13, &v2, 4, v12))
    {
        puts("You may have passed my test but I must see you display your knowledge before you can access my secrets");
        printf("Lesson 1: For your first challenge you have to simply jump to the function at this address: %p\n", win1);
        v0 = 0;
        v1 = 0;
        fgets(&v0, 0x200, stdin);
        return 0;
    }
    return 4294967295;
}

void pop_rdi_ret(unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5, unsigned long a6)
{
    return;
}

void pop_rsi_ret(unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5, unsigned long a6)
{
    return;
}

void pop_rdx_ret(unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5, unsigned long a6)
{
    return;
}

extern struct_1 __init_array_start;

void __libc_csu_init(unsigned int a0, unsigned long long a1, unsigned long long a2)
{
    void* v1;  // rbx

    _init();
    v1 = 0;
    do
    {
        *((long long *)((char *)&__init_array_start.field_0 + 0x8 * v1))(a0, a1, a2);
        v1 += 1;
    } while (v1 != 1);
    return;
}

void __libc_csu_fini()
{
    return;
}

void _fini()
{
    return;
}

