# Korisnici, sesije i artefakti akreditiva

{{#include ../../banners/hacktricks-training.md}}

Počnite od identiteta kojem pripada trenutna shell sesija, a zatim popišite ostale korisnike, grupe, aktivne sesije i skladišta akreditiva. Stranica o [stvarnom, efektivnom i sačuvanom ID-u korisnika](euid-ruid-suid.md) objašnjava zašto se efektivne privilegije procesa mogu razlikovati od njegovog naloga za prijavu.

## Popišite identitete i pristup zasnovan na grupama

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` uključuje naloge iz direktorijuma koje obično čitanje datoteke `/etc/passwd` može da propusti. Proverite naloge sa UID 0, login shell-ove, matične direktorijume, dodatne grupe i naloge čija konfiguracija neočekivano dozvoljava interaktivno prijavljivanje. Stranica [zanimljive grupe](interesting-groups-linux-pe/README.md) obrađuje delegirani pristup, kao što su `sudo`, `docker`, `disk` i `shadow`. Pre nego što naziv grupe protumačite kao privilegiju, proverite stvarne ACL-ove sistema datoteka i lokalnu politiku.

Ako [NSS mapira pretrage `passwd`, `group` ili `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) na bazu podataka, pre procene identiteta zasnovanih na bazi proverite aktivnog dobavljača i putanju njegove konfiguracije. Kod PostgreSQL NSS implementacija, `/etc/nss-pgsql.conf` i `/etc/nss-pgsql-root.conf` samo su putanje koje treba proveriti, jer podešavanja veze mogu sadržati akreditive. Uloga baze podataka je bitna samo ako može da menja zapise koje aktivni NSS dobavljač zaista vraća i ako nalog može da se autentifikuje pomoću njih. Primarni GID 0 daje članstvo u root grupi, a ne UID 0; mapiranje na sudo grupu zahteva [efektivno sudoers правило за групу](https://man7.org/linux/man-pages/man5/sudoers.5.html) i svaku potrebnu autentifikaciju. Mapiranje na UID 0 predstavlja drugačiju granicu identiteta. Tokom pasivne enumeracije nemojte ispisivati nizove za povezivanje niti menjati zapise naloga.

Takođe uporedite numeričke UID-ove lokalnih naziva naloga. Dva naziva u [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) mogu da predstavljaju isti Unix identitet datoteke, dok se njihovi zapisi za autentifikaciju pri prijavljivanju mogu razlikovati. Zato novododati pseudonim sa istim UID-om različitim od нуле може, након успешне аутентификације, омогућити приступ датотекама или процесима другог корисника; не даје root приступ, осим ако тај UID или засебан пут привилегија то омогућава. Заједнички UID-ови могу бити намерни. Проверите извор налога (`/etc/passwd` или NSS), историју креирања, shell и матични директоријум, стварну политику аутентификације и да ли је налозима дозвољено да деле идентитет. Провера дупликата само у локалним налозима не може да искључи псеудоним из директоријума.

## Пронађите активне и недавне сесије

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

`screen` ili `tmux` socket može da izloži postojeću shell sesiju ako njegove dozvole omogućavaju trenutnom korisniku da joj se priključi. Proverite vlasnika i režim dozvola socketa pre pokušaja pristupa; sesija drugog korisnika ne može se automatski preuzeti. Aktivna sudo vremenska oznaka ili SSH agent socket takođe mogu biti važni, ali njihovo ponovno korišćenje zavisi od identiteta korisnika, dozvola i pravila. Za zloupotrebu prosleđivanja agenta pogledajte [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

[OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster) odvojen je od `SSH_AUTH_SOCK`: `ControlMaster` i `ControlPath` omogućavaju kasnijim SSH klijentima da dele postojeću autentifikovanu vezu, dok `ControlPersist` može da zadrži master dostupan i nakon završetka prve sesije. Pregledajte `.ssh/config` trenutnog korisnika i plitko smeštene socket putanje u `.ssh`, uključujući vlasnika i dozvole. Sam naziv socketa ne dokazuje da je master aktivan, da trenutni korisnik može da se poveže niti koji udaljeni nalog koristi.

## Pregled korisničkih artefakata

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Istorija shell-a, startup datoteke, SSH ključevi, konfiguracija aplikacija, GPG privesci ključeva i Kerberos keševi mogu da otkriju kredencijale ili upisive tačke za perzistenciju. Datoteku `authorized_keys` ili startup datoteku privilegovanijeg naloga u koju može da se upisuje treba pregledati. [Stranica o post-eksploataciji](../post-exploitation/README.md) obrađuje premeštanje GPG home direktorijuma i pronalaženje kredencijala; [Linux Active Directory](linux-active-directory.md) obrađuje ponovnu upotrebu Kerberos keša i keytab datoteka. [Stranica o PAM-u](../software-information/pam-pluggable-authentication-modules.md) objašnjava rizike vezane za pravila autentifikacije.
{{#include ../../banners/hacktricks-training.md}}
