---
title: linux上jdk配置以及eclipse安装
date: 2018-10-17 10:19:18
tags: java
---
先上一下jdk和eclipse文件:https://pan.baidu.com/s/1VDy_W0t8iomJomrzAvV2hw密码:fb73
然后在/usr/local目录下mkdir software创建一个software文件夹(名字自己随便取)
![Image text](https://i.loli.net/2018/10/17/5bc69f3b1ad8c.png)
然后把文件解压到这个文件夹下..
然后就是配置java环境变量: 
```bash
vi /etc/profile
export JAVA_HOME=/usr/local/software/jdk1.8.0_181 //这个跟的是你jdk1.8.0_181那个目录

export CLASSPATH=.:$JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib/tools.jar

export PATH=$JAVA
_HOME/bin:$PATH
```
把这个加到最前面

保存之后 source /etc/profile 更新下环境变量
然后输入java -version和javac看是否配置成功
![Image text](https://i.loli.net/2018/10/17/5bc6a04f83023.png)
![Image text](https://i.loli.net/2018/10/17/5bc6a0707fe93.png)
下面把那个ecplise解压到和jdk同样的目录下(我的这个就是software目录下) 然后解压

然后移动到eclipse目录下./eclipse即可运行
![Image text](https://i.loli.net/2018/10/17/5bc6a0a136c26.png)
到此就可以了!然后这样每次运行就非常的麻烦 我们可以来写一个shell脚本
vi javae.sh内容是
```bash
#！/bin/sh
cd /usr/local/software/eclipse
./eclipse
```
保存之后在桌面tohch javae.desktop
紧接着gedit javae.desktop 内容是
```bash
Encoding=UTF-8
Name=javac
Exec=sh /home/pig/javae.sh //你的.sh的完整路径(*前面的sh不能删)
Icon=/home/pig/图片/Wallpapers/1.jpg//你的快捷方式图片的路径
Info="Spark"
Terminal=false
Type=Application
StartupNotify=true
```
弄完之后就可以在桌面上双击运行了
最后推荐一下dark颜色 巨好看
![Image text](https://i.loli.net/2018/10/17/5bc6a1579e61a.png)
