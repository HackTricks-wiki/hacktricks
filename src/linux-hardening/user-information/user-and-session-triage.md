# Korisnici, sesije i artefakti akreditiva

{{#include ../../banners/hacktricks-training.md}}

Počnite od identiteta koji poseduje trenutni shell, a zatim popišite ostale korisnike, grupe, aktivne sesije i skladišta akreditiva. Stranica [real, effective, and saved user ID](euid-ruid-suid.md) objašnjava zašto se efektivne privilegije procesa mogu razlikovati od njegovog naloga za prijavu.

## Popisivanje identiteta i pristupa zasnovanog na grupama

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` obuhvata naloge iz direktorijuma koje obično čitanje datoteke `/etc/passwd` može da propusti. Proverite naloge sa UID 0, login shell-ove, početne direktorijume, dopunske grupe i naloge čija konfiguracija neočekivano dozvoljava interaktivno prijavljivanje. Stranica [interesting groups](interesting-groups-linux-pe/README.md) obrađuje delegirani pristup kao što su `sudo`, `docker`, `disk` i `shadow`. Pre nego što naziv grupe protumačite kao privilegiju, proverite stvarne ACL-ove sistema datoteka i lokalnu politiku.

Ako [NSS preusmerava upite za `passwd`, `group` ili `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) na bazu podataka, pre procene identiteta zasnovanih na bazi proverite aktivnog pružaoca i putanju njegove konfiguracije. U PostgreSQL NSS implementacijama, `/etc/nss-pgsql.conf` i `/etc/nss-pgsql-root.conf` samo su putanje koje vredi proveriti, jer podešavanja veze mogu sadržati akreditive. Uloga baze podataka važna je samo ako može da menja zapise koje aktivni NSS pružalac zaista vraća i ako nalog može da se autentifikuje pomoću njih. Primarni GID 0 daje članstvo u root grupi, a ne UID 0; mapiranje u sudo grupu zahteva efektivno [sudoers pravilo za grupu](https://man7.org/linux/man-pages/man5/sudoers.5.html) i svaku potrebnu autentifikaciju. Mapiranje UID-a 0 predstavlja drugačiju granicu identiteta. Tokom pasivnog popisivanja nemojte ispisivati nizove za povezivanje niti menjati zapise naloga.

Uporedite i numeričke UID-ove lokalnih imena naloga. Dva imena u datoteci [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) mogu da predstavljaju isti Unix identitet datoteke, dok se njihovi zapisi za autentifikaciju pri prijavljivanju mogu razlikovati. Zato novododati alias sa zajedničkim UID-om koji nije nula može, nakon uspešne autentifikacije, da omogući pristup datotekama ili procesima drugog korisnika; ne daje root privilegije osim ako taj UID ili zaseban put privilegija to omogućava. Zajednički UID-ovi mogu biti namerni. Proverite izvor naloga (`/etc/passwd` naspram NSS-a), istoriju kreiranja, shell i početni direktorijum, stvarnu politiku autentifikacije i da li je nalozima dozvoljeno da dele identitet. Provera samo lokalnih naloga ne može da isključi alias iz direktorijuma.

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

`screen` ili `tmux` socket može da izloži postojeći shell ako njegove dozvole omogućavaju trenutnom korisniku da mu se pridruži. Pre pokušaja pristupa proverite vlasnika i režim dozvola socketa; sesija drugog korisnika ne može se automatski koristiti. Aktivna sudo vremenska oznaka ili SSH agent socket takođe mogu biti relevantni, ali njihova ponovna upotreba zavisi od identiteta korisnika, dozvola i pravila. Za zloupotrebu prosleđivanja agenta pogledajte [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

[OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster) odvojen je od `SSH_AUTH_SOCK`: `ControlMaster` i `ControlPath` omogućavaju kasnijim SSH klijentima da dele postojeću autentifikovanu vezu, dok `ControlPersist` može da zadrži master dostupnim nakon završetka prve sesije. Pregledajte `.ssh/config` trenutnog korisnika i putanje do socketa u plitkom nivou direktorijuma `.ssh`, uključujući vlasnika i dozvole. Sam naziv socketa ne dokazuje da je master aktivan, da trenutni korisnik može da se poveže niti koji udaljeni nalog koristi.

## Pregled korisničkih artefakata

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Istorija shell-a, datoteke za pokretanje, SSH ključevi, konfiguracija aplikacija, GPG prstenovi ključeva i Kerberos keševi mogu otkriti kredencijale ili tačke postojanosti u koje može da se upisuje. Datoteku `authorized_keys` ili datoteku za pokretanje shell-a za privilegovaniji nalog u koju može da se upisuje treba pregledati. [Stranica o posteksploataciji](../post-exploitation/README.md) obrađuje premeštanje GPG homedir-a i potragu za kredencijalima; [Linux Active Directory](linux-active-directory.md) obrađuje ponovnu upotrebu Kerberos keša i keytab-a. [Stranica o PAM-u](../software-information/pam-pluggable-authentication-modules.md) objašnjava rizike pravila autentifikacije.
{{#include ../../banners/hacktricks-training.md}}
