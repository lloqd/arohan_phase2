typedef struct struct_0 {
    struct struct_0 *field_0;
} struct_0;

extern struct_0 *g_403fe8;

long long _init()
{
    struct_0 **v1;  // rax

    v1 = g_403fe8;
    if (g_403fe8)
        v1 = g_403fe8();
    return v1;
}

extern unsigned long long g_403f50;
extern unsigned long long g_403f58;

void sub_401020()
{
    unsigned long v0;  // [bp-0x8]

    v0 = g_403f50;
    goto g_403f58;
}

void sub_401030()
{
    void* v0;  // [bp-0x8]

    v0 = 0;
    sub_401020();
    return;
}

void sub_401040()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 1;
    sub_401020();
    return;
}

void sub_401050()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 2;
    sub_401020();
    return;
}

void sub_401060()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 3;
    sub_401020();
    return;
}

void sub_401070()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 4;
    sub_401020();
    return;
}

void sub_401080()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 5;
    sub_401020();
    return;
}

void sub_401090()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 6;
    sub_401020();
    return;
}

void sub_4010a0()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 7;
    sub_401020();
    return;
}

void sub_4010b0()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 8;
    sub_401020();
    return;
}

void sub_4010c0()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 9;
    sub_401020();
    return;
}

void sub_4010d0()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 10;
    sub_401020();
    return;
}

void sub_4010e0()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 11;
    sub_401020();
    return;
}

void sub_4010f0()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 12;
    sub_401020();
    return;
}

void sub_401100()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 13;
    sub_401020();
    return;
}

void sub_401110()
{
    unsigned long long v0;  // [bp-0x8]

    v0 = 14;
    sub_401020();
    return;
}

void _start(unsigned long a0, unsigned long a1, unsigned long long a2)
{
    unsigned long long v1;  // [bp+0x0]
    unsigned long v2;  // [bp+0x8]
    unsigned long long v3;  // rax

    v1 = v3;
    __libc_start_main(main, v1, &v2, 0, 0, a2, &v1, v1); /* do not return */
}

void sub_401245()
{
    [D] Unsupported jumpkind Ijk_SigTRAP at address 4198981()
}


void deregister_tm_clones()
{
    return;
}


void register_tm_clones()
{
    return;
}

extern char __TMC_END__;
extern unsigned long long __dso_handle;
extern unsigned long long g_403ff8;

void __do_global_dtors_aux()
{
    if (__TMC_END__)
        return;
    if (g_403ff8)
        __cxa_finalize(__dso_handle);
    deregister_tm_clones();
    __TMC_END__ = 1;
    return;
}

void frame_dummy()
{
    register_tm_clones();
    return;
}

void rotate_block_left(char *a0, unsigned int a1, unsigned int a2)
{
    unsigned int v0;  // [bp-0x1c]
    unsigned int v1;  // [bp-0x18]
    unsigned int v2;  // [bp-0x14]
    unsigned long long v3;  // [bp-0x10]

    if (a2 && a1)
    {
        v3 = 0;
        for (v0 = 0; v0 < a1; v0 += 1)
        {
            v3 |= a0[v0] << ((char)v0 * 8 & 63);
        }
        v2 = a1 * 8;
        v3 &= ~(18446744073709551615 << ((char)v2 & 63));
        v3 = ~(18446744073709551615 << ((char)v2 & 63)) & (v3 << ((char)a2 & 63) | v3 >> ((char)(v2 - a2) & 63));
        for (v1 = 0; v1 < a1; v1 += 1)
        {
            a0[v1] = v3 >> ((char)v1 * 8 & 63);
        }
        return;
    }
    return;
}

long long rotate_block_right(char *a0, unsigned int a1, unsigned int a2)
{
    unsigned int v0;  // [bp-0x1c]
    unsigned int v1;  // [bp-0x18]
    unsigned int v2;  // [bp-0x14]
    unsigned long long v3;  // [bp-0x10]
    unsigned long v5;  // rax

    if (a2 && a1)
    {
        v3 = 0;
        for (v0 = 0; v0 < a1; v0 += 1)
        {
            v3 |= a0[v0] << ((char)v0 * 8 & 63);
        }
        v2 = a1 * 8;
        v3 &= ~(18446744073709551615 << ((char)v2 & 63));
        v3 = ~(18446744073709551615 << ((char)v2 & 63)) & (v3 >> ((char)a2 & 63) | v3 << ((char)(v2 - a2) & 63));
        for (v1 = 0; v1 < a1; v1 += 1)
        {
            a0[v1] = v3 >> ((char)v1 * 8 & 63);
        }
        return v1;
    }
    return v5;
}

void anti_debug()
{
    if (ptrace(0, 0, 1, 0) != -1)
        return;
    puts("THOU SHALL NOT READ MY MIND WITH GOTHIC MAGIC CAESER!!!\n");
    exit(1); /* do not return */
}

void flipBits(char *a0, unsigned int a1)
{
    char v0;  // [bp-0x11]
    unsigned int v1;  // [bp-0x10]
    unsigned int v2;  // [bp-0xc]

    v1 = 0;
    v0 = 105;
    for (v2 = 0; v2 < a1; v2 += 1)
    {
        if (!v1)
        {
            a0[v2] = ~(a0[v2]);
        }
        else
        {
            a0[v2] = a0[v2] ^ v0;
            v0 += 32;
        }
        v1 = !v1;
    }
    return;
}

extern char SBOX;

long long doWeirdStuff(char *a0, unsigned int a1)
{
    unsigned int v0;  // [bp-0x24]
    unsigned int v1;  // [bp-0x20]
    unsigned int v2;  // [bp-0x1c]
    unsigned int v3;  // [bp-0x18]
    unsigned int v4;  // [bp-0x14]
    char *v5;  // [bp-0x10]
    unsigned int v7;  // eax

    v2 = 5;
    for (v0 = 0; v0 < a1; v0 += v2)
    {
        v7 = a1 - v0;
        v3 = (v2 <= v7 ? v2 : v7);
        v5 = &a0[v0];
        for (v1 = 0; v1 < v3; v1 += 1)
        {
            v5[v1] = *(&(&SBOX)[v5[v1] ^ v1]);
        }
        v4 = v3 * 3;
        rotate_block_left(v5, v3, v4);
    }
    return v0;
}

long long expand(char *a0, unsigned int a1)
{
    char v0;  // [bp-0x1d]
    unsigned int v1;  // [bp-0x1c]
    unsigned int v2;  // [bp-0x18]
    unsigned int v3;  // [bp-0x14]
    unsigned long long v4;  // [bp-0x10]

    v1 = 0;
    v0 = 105;
    v4 = malloc(a1 * 2);
    for (v2 = 0; v2 < a1; v2 += 1)
    {
        v3 = 1;
        if (v3)
        {
            if (v3 == 3)
            {
                if (!v1)
                {
                    *((char *)(v4 + v2 * 2)) = a0[v2] & 31 | v0 * 16;
                    *((char *)(v4 + v2 * 2 + 1)) = a0[v2] & 0xfffffff0 | v0;
                }
                else
                {
                    *((char *)(v4 + v2 * 2)) = a0[v2] & 0xfffffff0 | v0;
                    *((char *)(v4 + v2 * 2 + 1)) = a0[v2] & 15 | v0 * 16;
                }
                v0 *= 11;
                v1 = !v1;
            }
            else if (v3 <= 3)
            {
                if (v3 == 1)
                {
                    if (!v1)
                    {
                        *((char *)(v4 + v2 * 2)) = a0[v2] & 15 | v0 * 16;
                        *((char *)(v4 + v2 * 2 + 1)) = a0[v2] & 0xfffffff0 | v0 >> 4;
                    }
                    else
                    {
                        *((char *)(v4 + v2 * 2)) = a0[v2] & 0xfffffff0 | v0 >> 4;
                        *((char *)(v4 + v2 * 2 + 1)) = a0[v2] & 15 | v0 * 16;
                    }
                    v0 *= 11;
                    v1 = !v1;
                }
                else if (v3 == 2)
                {
                    if (!v1)
                    {
                        *((char *)(v4 + v2 * 2)) = a0[v2] | v0 * 2;
                        *((char *)(v4 + v2 * 2 + 1)) = a0[v2] | v0 >> 3;
                    }
                    else
                    {
                        *((char *)(v4 + v2 * 2)) = a0[v2] & 4294967290 | v0 >> 2;
                        *((char *)(v4 + v2 * 2 + 1)) = a0[v2] & 4294967215 | v0 * 4;
                    }
                    v0 *= 11;
                    v1 = !v1;
                }
            }
        }
    }
    printf("fie");
    return v4;
}

long long teehee()
{
    unsigned long long v0;  // [bp-0x28]
    unsigned long long v1;  // [bp-0x20]
    unsigned long long v2;  // [bp-0x18]
    unsigned long long v3;  // [bp-0x10]

    v0 = sysconf(30);
    v1 = expand;
    v2 = -(v0) & v1;
    mprotect(v2, v0, 7, v0);
    v3 = expand;
    *((char *)(v3 + 29)) = 1;
    return v3 + 29;
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

extern char g_401bfa;
extern char g_401c0b;
extern char g_401c1c;
extern char g_401c34;
extern char g_401c50;
extern char g_401c5e;
extern char g_401c81;
extern char g_401c9a;
extern char g_401cb3;
extern char g_401cd5;
extern char g_401ce1;

int main()
{
    char v0;  // [bp-0x88]
    unsigned int v1;  // [bp-0x80]
    unsigned int v2;  // [bp-0x7c]
    FILE_t *v3;  // [bp-0x78]
    unsigned long v4;  // [bp-0x70]
    void* v5;  // [bp-0x68]
    char *v6;  // [bp-0x60]
    char *v7;  // [bp-0x58]
    char *v8;  // [bp-0x50]
    FILE_t *v9;  // [bp-0x48]
    unsigned int v11;  // eax
    unsigned long long v12;  // rax
    unsigned int v13;  // edi
    int v14;  // [bp-0x1088]

    puts("\nMay Jupiter strike you down Caeser before you seize the treasury!! You will have to tear me apart");
    puts("for me to tell you the flag to unlock the Roman Treasury and fund your civil war. I, Lucius Caecilius");
    puts("Metellus, shall not let you pass until you get this password right. (or threaten to kill me-)\n");
    v3 = fopen("palatinepackflag.txt", "r");
    fseek(v3, 0, 2);
    v2 = (int)ftell(v3) + 1;
    fseek(v3, 0, 0);
    v11 = v2;
    v4 = v11 - 1;
    v12 = ((long long)((0 CONCAT v11 + 15) % 16) CONCAT (long long)((0 CONCAT v11 + 15) / 16)) * 16;
    while (&v14 != &(&v0)[-1 * (v12 & 0xfffffffffffff000)])
    ;
    if (((unsigned short)v12 & 4095))
        *((long long *)(-8 + ((unsigned int)v12 & 4095) + (char *)v5)) = *((long long *)(-8 + ((unsigned int)v12 & 4095) + (char *)v5));
    v5 = &v14 - ((unsigned int)v12 & 4095);
    vvar_134{r48|8b} = v5 - 8;
    *((char **)&v5[8]) = &g_401bfa;
    fgets(v5, v2, v3);
    vvar_140{r48|8b} = vvar_134{r48|8b} - 8;
    *((char **)(vvar_134{r48|8b} - 8)) = &g_401c0b;
    flipBits(v5, v2);
    vvar_146{r48|8b} = vvar_140{r48|8b} - 8;
    *((char **)(vvar_140{r48|8b} - 8)) = &g_401c1c;
    v6 = expand(v5, v2);
    vvar_153{r48|8b} = vvar_146{r48|8b} - 8;
    *((char **)(vvar_146{r48|8b} - 8)) = &g_401c34;
    v7 = expand(v6, v2 * 2);
    vvar_160{r48|8b} = vvar_153{r48|8b} - 8;
    *((char **)(vvar_153{r48|8b} - 8)) = &g_401c50;
    v8 = expand(v7, v2 * 4);
    vvar_163{r48|8b} = vvar_160{r48|8b} - 8;
    *((char **)(vvar_160{r48|8b} - 8)) = &g_401c5e;
    anti_debug();
    v1 = 0;
    while (true)
    {
        vvar_9{r48|8b} = vvar_261{r48|8b};
        if (v1 >= v2 * 8)
            break;
        v13 = v8[v1];
        vvar_180{r48|8b} = vvar_9{r48|8b} - 8;
        *((char **)(vvar_9{r48|8b} - 8)) = &g_401c81;
        putchar(v13);
        v1 += 1;
        vvar_261{r48|8b} = vvar_180{r48|8b};
    }
    vvar_186{r48|8b} = vvar_9{r48|8b} - 8;
    *((char **)(vvar_9{r48|8b} - 8)) = &g_401c9a;
    putchar(10);
    vvar_192{r48|8b} = vvar_186{r48|8b} - 8;
    *((char **)(vvar_186{r48|8b} - 8)) = &g_401cb3;
    v9 = fopen("flag.txt", "wb");
    *((char **)(vvar_192{r48|8b} - 8)) = &g_401cd5;
    fwrite(v8, 1, v2 * 8, v9);
    *((char **)(vvar_192{r48|8b} - 16)) = &g_401ce1;
    fclose(v9);
    return 0;
}

void _fini()
{
    return;
}

