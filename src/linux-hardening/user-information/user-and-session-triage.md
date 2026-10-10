# Korisnici, sesije i artefakti akreditiva

{{#include ../../banners/hacktricks-training.md}}

Počnite od identiteta koji poseduje trenutnu ljusku, a zatim popišite ostale korisnike, grupe, aktivne sesije i skladišta akreditiva. Stranica o [stvarnom, efektivnom i sačuvanom ID-u korisnika](euid-ruid-suid.md) objašnjava zašto se efektivne privilegije procesa mogu razlikovati od privilegija njegovog naloga za prijavu.

## Popisivanje identiteta i pristupa zasnovanog na grupama

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` uključuje naloge iz direktorijumske usluge koje obično čitanje datoteke `/etc/passwd` može da propusti. Proverite naloge sa UID 0, login shells, home direktorijume, supplementary groups i naloge čija konfiguracija neočekivano dozvoljava interaktivnu prijavu. Stranica [interesting groups](interesting-groups-linux-pe/README.md) obrađuje delegirani pristup kao što su `sudo`, `docker`, `disk` i `shadow`. Proverite stvarne ACL-ove sistema datoteka i lokalnu politiku pre nego što grupu smatrate privilegovanom samo na osnovu njenog imena.

Ako [NSS mapira pretrage `passwd`, `group` ili `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) na bazu podataka, proverite aktivnog provajdera i putanju njegove konfiguracije pre procene identiteta iz baze podataka. Kod PostgreSQL NSS implementacija, `/etc/nss-pgsql.conf` i `/etc/nss-pgsql-root.conf` su samo putanje koje vredi proveriti, jer podešavanja povezivanja mogu da sadrže akreditive. Uloga u bazi podataka je važna samo ako može da menja zapise koje aktivni NSS provajder zaista vraća i ako nalog može da se autentifikuje pomoću njih. Primarni GID 0 daje članstvo u root grupi, a ne UID 0; mapiranje na sudo grupu zahteva efektivno [sudoers pravilo za grupu](https://man7.org/linux/man-pages/man5/sudoers.5.html) i svaku potrebnu autentifikaciju. Mapiranje UID-a 0 predstavlja drugu granicu identiteta. Tokom pasivnog enumerisanja nemojte ispisivati connection strings niti menjati zapise naloga.

Uporedite i numeričke UID-ove lokalnih imena naloga. Dva imena u datoteci [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) mogu da se odnose na isti Unix identitet datoteke, iako se njihovi zapisi za autentifikaciju pri prijavi mogu razlikovati. Zato novododati alias sa zajedničkim UID-om koji nije nula može, nakon uspešne autentifikacije, da omogući pristup datotekama ili procesima drugog korisnika; ne daje root pristup, osim ako je taj UID privilegovan ili postoji zaseban put do privilegija. Zajednički UID-ovi mogu biti namerni. Proverite izvor naloga (`/etc/passwd` naspram NSS-a), istoriju kreiranja, shell i home direktorijum, stvarnu politiku autentifikacije i da li su nalozi ovlašćeni da dele identitet. Provera duplikata samo u lokalnim nalozima ne može da isključi alias iz direktorijumske usluge.

## Pronađite aktivne i nedavne sesije

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

`screen` ili `tmux` soket može da izloži postojeću shell sesiju ako njegove dozvole omogućavaju trenutnom korisniku da joj se pridruži. Proverite vlasnika i režim dozvola soketa pre pokušaja pristupa; sesiji drugog korisnika ne može se automatski pristupiti. Aktivna `sudo` vremenska oznaka ili soket SSH agenta takođe mogu biti važni, ali njihova ponovna upotreba zavisi od identiteta korisnika, dozvola i pravila. Za zloupotrebu prosleđivanja agenta pogledajte [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

[OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster) odvojen je od `SSH_AUTH_SOCK`: `ControlMaster` i `ControlPath` omogućavaju kasnijim SSH klijentima da dele postojeću autentifikovanu vezu, dok `ControlPersist` može da zadrži glavni proces dostupnim i nakon završetka prve sesije. Pregledajte `.ssh/config` trenutnog korisnika i plitko smeštene putanje do soketa u `.ssh`, uključujući vlasnika i dozvole. Sam naziv datoteke soketa ne dokazuje da je glavni proces aktivan, da trenutni korisnik može da se poveže niti koji udaljeni nalog koristi.

## Pregled artefakata korisnika

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Istorija shell komandi, startup datoteke, SSH ključevi, konfiguracija aplikacija, GPG privesci ključeva i Kerberos keševi mogu otkriti akreditive ili tačke za uspostavljanje postojanosti u koje je moguće upisivati. Datoteke `authorized_keys` ili startup datoteke shell-a za privilegovaniji nalog u koje je moguće upisivati treba proveriti. [Stranica o post-exploitation](../post-exploitation/README.md) obrađuje premeštanje GPG homedir-a i potragu za akreditivima; [Linux Active Directory](linux-active-directory.md) obrađuje ponovnu upotrebu Kerberos keša i keytab datoteka. [PAM stranica](../software-information/pam-pluggable-authentication-modules.md) objašnjava rizike pravila autentifikacije.
{{#include ../../banners/hacktricks-training.md}}
