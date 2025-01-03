# Linux 环境变量

{{#include ../banners/hacktricks-training.md}}

## 全局变量

全局变量 **将会** 被 **子进程** 继承。

您可以通过以下方式为当前会话创建全局变量：
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
此变量将被当前会话及其子进程访问。

您可以通过以下方式**删除**变量：
```bash
unset MYGLOBAL
```
## 本地变量

**本地变量**只能被**当前的 shell/script**访问。
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## 列出当前变量
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## 常见变量

来自: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X** 使用的显示器。此变量通常设置为 **:0.0**，表示当前计算机上的第一个显示器。
- **EDITOR** – 用户首选的文本编辑器。
- **HISTFILESIZE** – 历史文件中包含的最大行数。
- **HISTSIZE** – 用户结束会话时添加到历史文件的行数。
- **HOME** – 你的主目录。
- **HOSTNAME** – 计算机的主机名。
- **LANG** – 你当前的语言。
- **MAIL** – 用户邮件存储的位置。通常是 **/var/spool/mail/USER**。
- **MANPATH** – 搜索手册页的目录列表。
- **OSTYPE** – 操作系统的类型。
- **PS1** – bash 中的默认提示符。
- **PATH** – 存储所有目录的路径，这些目录包含你想通过指定文件名而不是相对或绝对路径执行的二进制文件。
- **PWD** – 当前工作目录。
- **SHELL** – 当前命令 shell 的路径（例如，**/bin/bash**）。
- **TERM** – 当前终端类型（例如，**xterm**）。
- **TZ** – 你的时区。
- **USER** – 你当前的用户名。

## 有趣的黑客变量

### **HISTFILESIZE**

将 **此变量的值更改为 0**，这样当你 **结束会话** 时，**历史文件** (\~/.bash_history) **将被删除**。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

将**此变量的值更改为 0**，这样当您**结束会话**时，任何命令都将被添加到**历史文件**（\~/.bash_history）中。
```bash
export HISTSIZE=0
```
### http_proxy & https_proxy

进程将使用此处声明的 **proxy** 通过 **http 或 https** 连接到互联网。
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

进程将信任**这些环境变量**中指示的证书。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

更改提示的外观。

[**这是一个示例**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

普通用户:

![](<../images/image (740).png>)

一个、两个和三个后台作业:

![](<../images/image (145).png>)

一个后台作业，一个已停止，最后一个命令未正确完成:

![](<../images/image (715).png>)

{{#include ../banners/hacktricks-training.md}}
