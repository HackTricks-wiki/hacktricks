# Abusing Docker Socket for Privilege Escalation

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
