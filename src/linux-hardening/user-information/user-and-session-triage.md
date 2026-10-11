# Korisnici, sesije i artefakti akreditiva

{{#include ../../banners/hacktricks-training.md}}

Počnite od identiteta koji poseduje trenutnu ljusku, a zatim popišite ostale korisnike, grupe, aktivne sesije i skladišta akreditiva. Stranica [real, effective, and saved user ID](euid-ruid-suid.md) objašnjava zašto se efektivne privilegije procesa mogu razlikovati od njegovog naloga za prijavu.

## Popis identiteta i pristupa zasnovanog na grupama

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` uključuje naloge iz direktorijuma koje obično čitanje datoteke `/etc/passwd` može da propusti. Pregledajte naloge sa UID 0, login shell-ove, matične direktorijume, dodatne grupe i naloge čija konfiguracija neočekivano dozvoljava interaktivno prijavljivanje. Stranica [zanimljive grupe](interesting-groups-linux-pe/README.md) pokriva delegirani pristup kao što su `sudo`, `docker`, `disk` i `shadow`. Proverite stvarne ACL-ove sistema datoteka i lokalnu politiku pre nego što naziv grupe smatrate privilegijom.

Ako [NSS usmerava pretrage `passwd`, `group` ili `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) na bazu podataka, pregledajte aktivnog provajdera i putanju do njegove konfiguracije pre procene identiteta iz baze podataka. Kod PostgreSQL NSS implementacija, `/etc/nss-pgsql.conf` i `/etc/nss-pgsql-root.conf` su samo naznake putanja, jer podešavanja veze mogu da sadrže akreditive. Uloga u bazi podataka važna je samo ako može da menja zapise koje aktivni NSS provajder zaista vraća i ako nalog može da se autentifikuje pomoću njih. Primarni GID 0 daje članstvo u root grupi, a ne UID 0; mapiranje na sudo grupu zahteva efektivno [sudoers pravilo za grupu](https://man7.org/linux/man-pages/man5/sudoers.5.html) i svaku potrebnu autentifikaciju. Mapiranje na UID 0 predstavlja drugu granicu identiteta. Tokom pasivnog popisivanja nemojte prikazivati stringove za povezivanje niti menjati zapise naloga.

Takođe uporedite numeričke UID-ove između lokalnih imena naloga. Dva imena u datoteci [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) mogu da se odnose na isti Unix identitet datoteke, dok se njihovi zapisi za autentifikaciju pri prijavljivanju mogu razlikovati. Zato novododati alias sa zajedničkim UID-om koji nije nula može da omogući pristup datotekama ili procesima drugog korisnika nakon uspešne autentifikacije; ne daje root pristup osim ako taj UID ili zaseban put do privilegija to omogućava. Zajednički UID-ovi mogu biti namerni. Proverite izvor naloga (`/etc/passwd` ili NSS), istoriju kreiranja, shell i matični direktorijum, stvarnu politiku autentifikacije i da li je nalozima odobreno da dele identitet. Provera samo lokalnih naloga ne može da isključi alias iz direktorijuma.

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

`screen` ili `tmux` socket može da izloži postojeću shell sesiju ako njegove dozvole trenutnom korisniku dozvoljavaju povezivanje. Proverite vlasnika i režim dozvola socketa pre pokušaja pristupa; sesija drugog korisnika nije automatski dostupna za povezivanje. Aktivna sudo vremenska oznaka ili SSH agent socket takođe mogu biti važni, ali njihova ponovna upotreba zavisi od identiteta korisnika, dozvola i pravila. Za zloupotrebu prosleđivanja agenta pogledajte [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

[OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster) odvojen je od `SSH_AUTH_SOCK`: `ControlMaster` i `ControlPath` omogućavaju kasnijim SSH klijentima da dele postojeću autentifikovanu vezu, dok `ControlPersist` može da zadrži master dostupan i nakon završetka prve sesije. Pregledajte `.ssh/config` trenutnog korisnika i plitko ugnježdene putanje socketa u `.ssh`, uključujući vlasnika i dozvole. Sam naziv socketa ne dokazuje da je master aktivan, da trenutni korisnik može da se poveže niti koji udaljeni nalog koristi.

## Pregled korisničkih artefakata

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Istorija shell-a, startup fajlovi, SSH ključevi, konfiguracija aplikacija, GPG prstenovi ključeva i Kerberos keševi mogu otkriti kredencijale ili tačke za perzistenciju koje mogu da se menjaju. `authorized_keys` ili shell startup fajl za privilegovaniji nalog koji može da se menja zaslužuje proveru. [Stranica o post-exploitation-u](../post-exploitation/README.md) obrađuje premeštanje GPG homedir-a i pronalaženje kredencijala; [Linux Active Directory](linux-active-directory.md) obrađuje ponovnu upotrebu Kerberos keša i keytab-a. [Stranica o PAM-u](../software-information/pam-pluggable-authentication-modules.md) objašnjava rizike politika autentifikacije.
{{#include ../../banners/hacktricks-training.md}}
