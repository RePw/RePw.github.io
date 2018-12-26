---
title: github+hexo个人博客搭建
date: 2018-10-12 16:22:11
tags: 搭建
---
<strong><h1>0x00 前言</h1></strong>
以前博客搭建在WORDPRESS上 需要不停续费服务器太麻烦了 迁移也太麻烦了 就想着搭建一个hexo个人博客
<strong><h1>0x01 准备</h1></strong>
1.node.js在官方上下载并安装
2.git官方下载并安装
看一下node/npm/git的版本 有一个没显示就是有错误!!
```bash
C:\Users\89860>node -v
v8.12.0

C:\Users\89860>npm -v
6.4.1

C:\Users\89860>git --version
git version 2.19.1.windows.1
```
<strong><h1>0x02 开始</h1></strong>
首先在一个盘中创建个文件夹 比如我在D:创建一个blog 然后打开cmd移动到你创建的文件夹下
```bash
C:\Users\89860>d:

D:\>cd blog
```
安装hexo
```bash
npm install hexo -g
```
hexo -v     检查版本
```bash
C:\Users\89860>hexo -v
hexo-cli: 1.1.0
os: Windows_NT 10.0.17134 win32 x64
http_parser: 2.8.0
node: 8.12.0
v8: 6.2.414.66
uv: 1.19.2
zlib: 1.2.11
ares: 1.10.1-DEV
modules: 57
nghttp2: 1.32.0
napi: 3
openssl: 1.0.2p
icu: 60.1
unicode: 10.0
cldr: 32.0
tz: 2017c
```
初始化
```bash
hexo init
```
更新后面所需要用到的软件
```bash
npm install
```
配置服务
```bash
hexo g
```
开启服务
```bash
D:\blog>hexo s
INFO  Start processing
INFO  Hexo is running at http://localhost:4000 . Press Ctrl+C to stop.
```
可以看到我们可以访问http://localhost:4000
![Image text](https://i.loli.net/2018/10/12/5bc067a181f5b.png)
<strong><h1>0x03 Github与hexo连接</h1></strong>
创建一个github账户 创建仓库 注:域名必须和自己账户名一样
![Image text](https://i.loli.net/2018/10/12/5bc068cc0b69d.png)
进入自己创建的那个blog文件夹 右键使用git bash here
```bash
git config --global user.name "自己github名字"
git config --global user.email "自己github邮箱"
```
生成密钥
```bash
 ssh-keygen -t rsa -C "自己github邮箱"
 ```
 同样在_config.yml文件中，找到Deployment，然后按照如下修改
 ```bash
 deploy:
  type: git
  repo: git@github.com:yourname/yourname.github.io.git  注:yourname是自己账户
  branch: master
 ```
 登陆github 在自己头像下找到Settings
 进入找到 SSH and GPG keys
 New一个新的SSH-keys
 然后在自己根目录下(就是你的用户目录) 找到./ssh
 将id_rsa.pub文件里的内容复制上去
  ![Image text]( https://i.loli.net/2018/10/12/5bc06bb34e5f2.png)
 看自己是否配置成功
 ```bash
 89860@MSI MINGW64 /d/blog
$ ssh -T git@github.com
Hi RePw! You've successfully authenticated, but GitHub does not provide shell access.
```
到此就搭建成功 可以登陆https://名字.github.io进入自己博客
```bash
hexo new "标题"   创建新博文
进入D:\blog\source\_posts可以看到md文件 可以向里面写博客内容
hexo d -g 更新部署就可以看到自己博文更新上去
```
资料来源:
https://www.cnblogs.com/fengxiongZz/p/7707219.html
https://blog.csdn.net/gdutxiaoxu/article/details/53576018
