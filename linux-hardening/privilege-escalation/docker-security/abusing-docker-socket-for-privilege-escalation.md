# Abusing Docker Socket for Privilege Escalation

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

There are some occasions were you just have **access to the docker socket** and you want to use it to **escalate privileges**. Some actions might be very suspicious and you may want to avoid them, so here you can find different flags that can be useful to escalate privileges:

### Via mount

You can **mount** different parts of the **filesystem** in a container running as root and **access** them.\
You could also **abuse a mount to escalate privileges** inside the container.

* **`-v /:/host`** -> Mount the host filesystem in the container so you can **read the host filesystem.**
  * If you want to **feel like you are in the host** but being on the container you could disable other defense mechanisms using flags like:
    * `--privileged`
    * `--cap-add=ALL`
    * `--security-opt apparmor=unconfined`
    * `--security-opt seccomp=unconfined`
    * `-security-opt label:disable`
    * `--pid=host`
    * `--userns=host`
    * `--uts=host`
    * `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> This is similar to the previous method, but here we are **mounting the device disk**. Then, inside the container run `mount /dev/sda1 /mnt` and you can **access** the **host filesystem** in `/mnt`
  * Run `fdisk -l` in the host to find the `</dev/sda1>` device to mount
* **`-v /tmp:/host`** -> If for some reason you can **just mount some directory** from the host and you have access inside the host. Mount it and create a **`/bin/bash`** with **suid** in the mounted directory so you can **execute it from the host and escalate to root**.

{% hint style="info" %}
Note that maybe you cannot mount the folder `/tmp` but you can mount a **different writable folder**. You can find writable directories using: `find / -writable -type d 2>/dev/null`

**Note that not all the directories in a linux machine will support the suid bit!** In order to check which directories support the suid bit run `mount | grep -v "nosuid"` For example usually `/dev/shm` , `/run` , `/proc` , `/sys/fs/cgroup` and `/var/lib/lxcfs` don't support the suid bit.

Note also that if you can **mount `/etc`** or any other folder **containing configuration files**, you may change them from the docker container as root in order to **abuse them in the host** and escalate privileges (maybe modifying `/etc/shadow`)
{% endhint %}

### Escaping from the container

* **`--privileged`** -> With this flag you [remove all the isolation from the container](docker-privileged.md#what-affects). Check techniques to [escape from privileged containers as root](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> To [escalate abusing capabilities](../linux-capabilities.md), **grant that capability to the container** and disable other protection methods that may prevent the exploit to work.

### Curl

In this page we have discussed ways to escalate privileges using docker flags, you can find **ways to abuse these methods using curl** command in the page:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
