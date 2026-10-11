# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux mašina takođe može biti deo Active Directory okruženja.

Linux mašina u AD-u može **lokalno da čuva Kerberos materijal**: korisničke ccache datoteke, machine/service keytabs i tajne kojima upravlja SSSD. Ovi artefakti obično se mogu ponovo koristiti kao bilo koji drugi Kerberos akreditivi. Da biste pročitali većinu njih, moraćete da budete korisnik koji je vlasnik tiketa ili **root** na mašini.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumeracija

### Enumeracija AD-a sa Linuxa

Ako imate pristup AD-u sa Linuxa (ili bash-a u Windows-u), možete probati [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) za enumeraciju AD-a.

Možete pogledati i sledeću stranicu da biste saznali **druge načine za enumeraciju AD-a sa Linuxa**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA je open-source **alternativa** za Microsoft Windows **Active Directory**, namenjena prvenstveno **Unix** okruženjima. Objedinjuje kompletan **LDAP direktorijum** sa MIT **Kerberos** centrom za distribuciju ključeva, za upravljanje slično kao u Active Directory-ju. Koristi Dogtag **Certificate System** za upravljanje CA i RA sertifikatima i podržava **višefaktorsku** autentifikaciju, uključujući pametne kartice. SSSD je integrisan za Unix procese autentifikacije.<sup>[[14]](#references)[[15]](#references)</sup> Saznajte više o tome ovde:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefakti hosta pridruženog domenu

Pre nego što počnete da radite sa tiketima, utvrdite **kako je host pridružen AD-u** i **gde se Kerberos materijal zaista čuva**. Na modernim Linux hostovima to obično obavljaju `realmd` + `adcli` + `sssd`, a ne samo obične datoteke u `/tmp`.<sup>[[10]](#references)</sup>

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

Ovo vam brzo govori da li host veruje AD-u, da li SSSD kešira identitete ili tikete i da li su **machine/service keytabs** ili **KCM secrets** dostupni za zloupotrebu.<sup>[[4]](#references)[[10]](#references)</sup>

Tretirajte `/var/lib/sss/db/cache_*.ldb` odvojeno od Kerberos ccache datoteka i `/var/lib/sss/secrets/secrets.ldb`. Datoteke `cache_*.ldb` mogu sadržati verifikatore lozinki za offline upotrebu kada domen ima `cache_credentials = true` **i** kada se korisnik ranije autentifikovao na tom hostu. Obično su čitljive samo uz privilegovan pristup. Sama datoteka keša ili omogućena postavka ne dokazuju da postoji upotrebljiva, važeća lozinka; pre donošenja takvog zaključka proverite efektivnu postavku za domen i stvarno keširane identitete. Pogledajte [Red Hat's SSSD credential-cache documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/epub/configuring_authentication_and_authorization_in_rhel/overview-single-sign-on_introduction-to-system-authentication). Kada je reč o zasebnoj granici identiteta između Linuxa i AD-a, [mixed-vendor Kerberos name mapping](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/) je važan samo kada servis prihvati tiket i mapira njegov principal na odgovarajući Unix nalog.

Na hostu sa `ksu`, važeći Kerberos principal može da pristupi **lokalnom ciljnom nalogu**, uključujući root, samo ako taj nalog ovlašćuje principal. [MIT Kerberos documents](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/ksu.html) dokumentuje datoteke `.k5login` i `.k5users` u ciljnom home direktorijumu, kao i rezervno mapiranje imena kada nijedna od njih ne postoji. `.k5users` može i da ograniči komande za `ksu -e`; samo postojanje datoteke ne dokazuje pristup shell-u. Proverite konkretan ciljni nalog, vlasništvo i dozvole datoteka, čitljive unose za ovlašćivanje, dostupne Kerberos akreditive i efektivna pravila mapiranja. Ako root home direktorijum nije dostupan, stanje ovlašćenja ostaje nepoznato. Pasivno nabrajanje treba da prikaže ove putanje i dozvole, bez zahtevanja tiketa ili pokretanja `ksu`.

Zakazano pravljenje rezervne kopije može posredno da stvori granicu ovlašćenja `.k5login`. Ako nalog sa višim privilegijama rekurzivno kopira direktorijum koji može da menja korisnik sa nižim privilegijama u sopstveni home direktorijum, proverite da li kopiranje obuhvata skrivene datoteke, da li je odredišna putanja efektivni home direktorijum naloga i da li vlasništvo nad nastalom datotekom prihvata Kerberos servis za prijavu. Na primer, [rsync documents](https://download.samba.org/pub/rsync/rsync.1.html) navodi da `-a --no-owner` ostavlja nove odredišne datoteke u vlasništvu korisnika koji ih prima. [MIT Kerberos documents](https://web.mit.edu/kerberos/www/krb5-latest/doc/user/user_config/k5login.html) opisuje kako principal u `.k5login` datoteci tog korisnika može da ovlasti pristup. Potvrdite RunAs identitet zakazanog posla, pristup izvoru za upis, efektivne rsync opcije, prijavu sa omogućenim GSSAPI-jem i važeći tiket za navedeni principal; direktorijum u koji može da se upisuje ili sama rsync komanda u zakazanom poslu ne dokazuju da ovaj put postoji.

Čitljiva keytab datoteka takođe zahteva proveru za svaki principal posebno. Keytab koja sadrži principal čije ime upućuje na administraciju sama po sebi ne dokazuje administratorska prava: [KDC's `kadm5.acl` policy](https://web.mit.edu/Kerberos/www/krb5-1.22/doc/admin/conf_files/kadm5_acl.html) određuje dozvoljene operacije nad principalima. Pre nego što pristup keytab datoteci smatrate putem do root-a, zasebno potvrdite principal, efektivnu ACL politiku i lokalno ovlašćenje za `ksu` ili prijavu. Pasivna trijaža može da prikaže putanju keytab datoteke i dozvole bez korišćenja njenih ključeva ili povezivanja sa KDC-om.

## Rad sa tiketima

### Pass The Ticket

Na ovoj stranici ćete pronaći različita mesta na kojima možete **pronaći Kerberos tikete unutar Linux hosta**; na sledećoj stranici možete naučiti kako da ove CCache formate tiketa pretvorite u Kirbi (format koji treba da koristite u Windows-u), kao i kako da izvedete PTT napad:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Ako želite **Linux-specifične postupke za prikupljanje tiketa** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc` itd.), pogledajte namensku stranicu:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Ponovna upotreba CCACHE tiketa iz /tmp

CCACHE datoteke su binarni formati za **čuvanje Kerberos akreditiva**. `FILE:/tmp/krb5cc_%{uid}` je i dalje uobičajen, ali moderne Linux implementacije koriste i `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` ili `KCM:%{uid}`. Pre nego što pretpostavite da se tiketi nalaze u `/tmp`, proverite promenljivu okruženja **`KRB5CCNAME`** i postavku `default_ccache_name`.<sup>[[1]](#references)[[3]](#references)</sup>

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

### Ponovna upotreba CCACHE tiketa iz keyring-a

**Kerberos tiketi sačuvani u memoriji procesa mogu da se izvuku**, naročito kada je zaštita ptrace-a na mašini onemogućena (`/proc/sys/kernel/yama/ptrace_scope`). Koristan alat za ovu namenu dostupan je na [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), a omogućava izdvajanje tako što se ubacuje u sesije i izbacuje tikete u `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Da biste konfigurisali i koristili ovaj alat, pratite sledeće korake:

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

Ova procedura će pokušati da ubaci kod u različite sesije, a uspeh će označiti tako što će sačuvane izdvojene tikete smestiti u `/tmp`, koristeći konvenciju imenovanja `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Ponovna upotreba CCACHE tiketa iz SSSD KCM

SSSD održava kopiju baze podataka na putanji `/var/lib/sss/secrets/secrets.ldb`. Odgovarajući ključ se čuva kao skrivena datoteka na putanji `/var/lib/sss/secrets/.secrets.mkey`. Podrazumevano, ključ može da se čita samo ako imate **root** dozvole.<sup>[[4]](#references)</sup>

Pozivanje **`SSSDKCMExtractor`** sa parametrima --database i --key će parsirati bazu podataka i **dešifrovati tajne**.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

Extractor ispisuje sirove Kerberos JSON payload-e; pre pass-the-cache/pass-the-ticket operacija, konvertujte ih u upotrebljivu keš memoriju tiketa ili drugi format tiketa.<sup>[[4]](#references)</sup>

### Brza analiza keytab-a

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### Izdvajanje naloga iz /etc/krb5.keytab

Ključevi servisnih naloga, neophodni za servise koji rade sa root privilegijama, bezbedno se čuvaju u datotekama **`/etc/krb5.keytab`**. Ovi ključevi, koji služe kao lozinke za servise, zahtevaju strogu poverljivost.<sup>[[5]](#references)</sup>

Za pregled sadržaja keytab datoteke može se koristiti **`klist`**. Na Linuxu, `klist -k -K -e` ispisuje principal-e, brojeve verzija ključeva, tipove šifrovanja i sirovi materijal ključa. Ako je tip ključa **23 / RC4-HMAC**, vrednost ključa je ujedno i **NT hash** tog principal-a.<sup>[[6]](#references)[[17]](#references)</sup>

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

Za korisnike Linuxa, **`KeyTabExtract`** omogućava izdvajanje RC4 HMAC hash-a, koji se može iskoristiti za ponovnu upotrebu NTLM hash-a. Imajte na umu da je ovo korisno samo ako keytab i dalje sadrži materijal **etype 23 / RC4-HMAC**. U okruženjima koja koriste isključivo **AES**, možda nećete dobiti NT hash koji se može ponovo upotrebiti, ali se i dalje možete direktno autentifikovati pomoću keytab-a preko Kerberos-a.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

Na macOS-u, **`bifrost`** služi kao alat za analizu keytab datoteka.<sup>[[8]](#references)</sup>

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

Koristeći izdvojene informacije o nalozima i hash vrednostima, veze sa serverima mogu se uspostaviti pomoću alata kao što je **`NetExec`**.<sup>[[9]](#references)</sup>

```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```

### Ponovna upotreba mašinskog naloga iz `/etc/krb5.keytab`

Na sistemima pridruženim pomoću `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` obično sadrži **nalog računara** i jedan ili više **host/service principala**. Ako imate **root** pristup, nemojte ga samo ispisati: upotrebite jedan od principala navedenih pomoću `klist -k` da biste zatražili TGT i delovali kao sam Linux host.<sup>[[10]](#references)</sup>

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

Ovo je posebno korisno kada **objekat računara** ima delegirana prava u AD-u ili kada je host-u dozvoljeno da pribavlja druge tajne, kao što je **gMSA**.<sup>[[13]](#references)</sup>

### Ponovna upotreba ukradenog Kerberos materijala pomoću Linux-first AD alata

Kada imate važeći `ccache` ili upotrebljiv keytab, možete da radite direktno sa AD-om **iz Linux-a**, bez prethodnog konvertovanja svega u Windows formate. Mnogi savremeni alati izvorno prihvataju `KRB5CCNAME` / Kerberos autentifikaciju.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

Ovo je dobra veza između **Linux post-exploitation** i **zloupotrebe AD objekata**. Za same putanje zloupotrebe na nivou objekata pogledajte:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / artefakti Managed Service Account-a

Novije Linux implementacije mogu direktno da koriste **Managed Service Accounts** iz AD-a. U praksi to znači da nakon kompromitovanja Linux servera možete pronaći ne samo host keytab već i **keytab-ove specifične za servise**, generisane iz gMSA naloga. Uobičajena mesta za proveru su `/etc/gmsad.conf`, konfiguracione datoteke specifične za implementaciju i dodatne datoteke `*.keytab` u direktorijumu `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>

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

Ovo vam daje ponovo upotrebljiv Kerberos identitet za SPN-ove povezane sa tim gMSA **bez pristupa bilo kojoj Windows krajnjoj tački**.<sup>[[13]](#references)</sup> Za zloupotrebu gMSA/dMSA **na strani domena** nakon sticanja viših privilegija u AD-u, pogledajte:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Kako napasti Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Pristup AD-u pomoću upravljanog servisnog naloga – Direktna integracija RHEL sistema sa Active Directory-jem](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Promenljive okruženja za Kerberos – MIT Kerberos dokumentacija](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – MIT Kerberos dokumentacija](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: RC4-HMAC tipovi Kerberos šifrovanja koje koristi Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Korišćenje Kerberosa | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Otkrivanje domena identiteta i pridruživanje njima | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Korisnički vodič za bloodyAD](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [O projektu | FreeIPA dokumentacija](https://www.freeipa.org/About.html)
- [15] [Beleške o izdanju FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Dokumentacija Linux kernela](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – MIT Kerberos dokumentacija](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
