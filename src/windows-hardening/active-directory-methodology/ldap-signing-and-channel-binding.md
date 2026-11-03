# Utwardzanie LDAP Signing i Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Dlaczego to ważne

Ataki LDAP relay/MITM przekazują uwierzytelnianie do kontrolera domeny, aby uzyskać uwierzytelniony kontekst LDAP. [Omówienie zatruwania rozpoznawania nazw i relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) przedstawia szerszy przebieg ataku. Dwa powiązane mechanizmy ograniczają te ścieżki:

- **LDAP channel binding (CBT)** wiąże odpowiednie uwierzytelnianie z certyfikatem/kanałem serwera TLS używanym przez LDAPS, utrudniając relay między różnymi kanałami.
- **LDAP signing** wymaga ochrony integralności dla powiązań LDAP SASL. Nie zapewnia poufności; użyj TLS, gdy treść LDAP również wymaga szyfrowania.<sup>[[2]](#references)</sup>

**Szybkie sprawdzenie konfiguracji**: narzędzia takie jak `netexec ldap <dc> -u user -p pass` raportują wykryte ustawienia signing i channel binding. `(signing:None)` i `(channel binding:Never)` wskazują brak tych mechanizmów, ale powodzenie relay nadal zależy od przechwyconego typu uwierzytelniania, działania EPA, uprawnień konta, protokołu docelowego i zabezpieczeń przed relay. Gdy przekazana tożsamość ma wymagane uprawnienia, narzędzia takie jak KrbRelayUp mogą zapisać `msDS-AllowedToActOnBehalfOfOtherIdentity`, skonfigurować delegowanie ograniczone do zasobów (RBCD) i użyć uzyskanej ścieżki delegowania do podszycia się pod uprzywilejowaną tożsamość.<sup>[[4]](#references)</sup>

**Kontrolery domeny Server 2025** wprowadzają nowe GPO (**LDAP server signing requirements Enforcement**), które domyślnie wymaga **Require Signing**, jeśli pozostawiono je jako **Not Configured**. Aby uniknąć wymuszania tej zasady, należy jawnie ustawić ją na **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (tylko LDAPS)

- **Wymagania**:
  - Poprawka CVE-2017-8563 (2017) dodaje obsługę Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) dodaje telemetrię LDAPS CBT w trybie „what-if”.<sup>[[2]](#references)</sup>
- **GPO (kontrolery domeny)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (wartość domyślna, bez CBT)
  - `When Supported` (częściowe wymuszanie: klienci obsługujący CBT muszą podać prawidłowy token; klienci bez obsługi CBT nadal mogą nawiązać połączenie, a zdarzenia audytu są emitowane)
  - `Always` (wymuszanie: odrzuca powiązania LDAPS bez prawidłowego CBT)<sup>[[1]](#references)</sup>
- **Audyt**: ustaw **When Supported**, aby wykrywać:
  - **3074** – powiązanie LDAPS nie przeszłoby walidacji CBT, gdyby mechanizm był wymuszany.
  - **3075** – powiązanie LDAPS nie zawierało danych CBT i zostałoby odrzucone, gdyby mechanizm był wymuszany.
  - (Zdarzenie **3039** nadal sygnalizuje błędy CBT w starszych kompilacjach.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Wymuszanie**: ustaw **Always**, gdy klienci LDAPS zaczną wysyłać CBT; działa wyłącznie dla **LDAPS** (nie dla surowego portu 389).<sup>[[1]](#references)</sup>

`When Supported` to nie tylko tryb audytu: waliduje CBT dla klientów, którzy je obsługują, a jednocześnie zezwala na połączenia klientów bez obsługi CBT. [Dokumentacja zasad firmy Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) opisuje wartości domyślne zależne od wersji. LDAP signing dotyczy odpowiednich powiązań LDAP/389; channel binding dotyczy uwierzytelniania LDAP chronionego przez TLS.


## LDAP Signing

- **GPO klienta**: `Network security: LDAP client signing requirements` = `Require signing` (zamiast domyślnego `Negotiate signing` we współczesnym systemie Windows).<sup>[[1]](#references)</sup>
- **GPO kontrolera domeny**:
  - Starsza zasada: `Domain controller: LDAP server signing requirements` = `Require signing` (wartością domyślną jest `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: pozostaw starszą zasadę jako `None` i ustaw `LDAP server signing requirements Enforcement` = `Enabled` (`Not Configured` oznacza domyślne wymuszanie; ustaw `Disabled`, aby go uniknąć).<sup>[[1]](#references)</sup>
- **Zgodność**: zinwentaryzuj urządzenia i aplikacje spoza systemu Windows, które używają prostych powiązań lub niepodpisanych powiązań SASL. Firma Microsoft dokumentuje obsługę w utrzymywanych wersjach systemu Windows; deklaracje zgodności ze starszymi klientami należy weryfikować względem faktycznie używanego stosu klienta, zamiast sprowadzać je do progu wersji XP.<sup>[[2]](#references)</sup>

## Ścieżki relay i ponowne uwierzytelnianie podpisanym SASL

Jeśli wymagane jest **wyłącznie signing**, relay do LDAPS może nadal działać, gdy channel binding nie jest wymuszany: TLS zapewnia integralność transportu. Jeśli wymagane jest **wyłącznie channel binding**, zwykły LDAP nie ma kanału TLS, z którym można by go powiązać; relay może uwierzytelnić się przez TCP 389, a następnie użyć StartTLS do operacji wymagających TLS, pod warunkiem że przekazana tożsamość ma wymagane uprawnienia. Wymuszenie obu mechanizmów zamyka te typowe alternatywy, ale nie powstrzymało poniższej podatności na niezałatanych kontrolerach domeny.<sup>[[5]](#references)</sup>

### Dołączenie operacji LDAP po przekazanym Bind

Na podatnych kontrolerach domeny Windows Server 2016–2025 najpierw nawiąż **podpisane połączenie LDAP SASL NTLM** przez TCP 389 jako tożsamość X, używając poświadczeń, których klucz sesji znasz (lub anonimowego kontekstu NTLM SASL, jeśli jest akceptowany). Wymuś uwierzytelnienie tożsamości Y **przez SMB** do relay. Przekaż komunikaty NTLM NEGOTIATE od Y i CHALLENGE od kontrolera domeny przez żądania Bind GSS-SPNEGO w istniejącym połączeniu LDAP tożsamości X. Klient SMB systemu Windows ustawia `NTLMSSP_NEGOTIATE_SIGN`, więc wynikowe powiązanie LDAP wymaga podpisanej warstwy SASL; wymiana inicjowana przez HTTP/WebDAV zazwyczaj nie zawiera tej flagi i nie można jej tu użyć zamiennie.<sup>[[5]](#references)</sup>

Gdy Y wysyła NTLM AUTHENTICATE, umieść **dwie odrębne wiadomości LDAP w jednym rekordzie SASL z prefiksem długości**: BindRequest zawierający tę odpowiedź, a następnie ModifyRequest. Podpisz cały rekord znanym kluczem X. Podatny kontroler domeny weryfikuje rekord przy użyciu X, kończy Bind i zmienia autoryzację połączenia na Y, a następnie wykonuje pozostały ModifyRequest jako Y, nie weryfikując ponownie rekordu przy użyciu klucza Y. Nie ujawnia to hasła ani klucza sesji Y; późniejszy rekord podpisany przez X zostanie odrzucony. Zapis RBCD do `msDS-AllowedToActOnBehalfOfOtherIdentity` lub zapis shadow credentials do `msDS-KeyCredentialLink` nadal wymaga, aby Y miała uprawnienia do obiektu docelowego. Zobacz [RBCD](resource-based-constrained-delegation.md), [shadow credentials](acl-persistence-abuse/shadow-credentials.md) oraz [DCSync](dcsync.md) w przypadku przekazanego konta komputera kontrolera domeny.<sup>[[5]](#references)</sup>

To obejście dotyczy **zwykłego LDAP**, a nie obejścia channel binding dla LDAPS. W przypadku LDAPS TLS chroni połączenie, a system Windows nie ustanawia warstwy podpisywania NTLM SASL z kluczem X, wymaganej do tej metody umieszczania wielu operacji w jednym rekordzie. Jeśli TCP 389 jest niedostępny, technika nie przenosi się po prostu na TCP 636. Aktualizacje zabezpieczeń z października 2026 zapobiegają wykonaniu operacji z tego samego rekordu, odrzucając pozostałe dane po zmianie tożsamości połączenia przez Bind.<sup>[[5]](#references)</sup> KB5126646 to aktualizacja dla Windows Server 2025; inne podatne wydania Server mają inne numery KB.<sup>[[7]](#references)</sup>

Narzędzie badacza [LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo) opakowuje zmodyfikowane `ntlmrelayx.py` na potrzeby tego procesu. Wymaga źródła wymuszenia uwierzytelnienia przez **SMB**, przypiętej wersji drzewa Impacket udostępniającej API LDAP signing/security-context (Impacket 0.13.1 z PyPI nie wystarczy) oraz kontrolowanego przez atakującego konta do początkowego podpisanego bind. W przypadku zapisu RBCD podaj DN obiektu ofiary i SID kontrolowanego komputera delegującego; do innego dozwolonego zapisu użyj `-attribute` wraz z `-value` lub `-value-hex`. Sprawdź niezależny, podpisany odczyt zwrotny narzędzia; komunikat `FAILED` po stronie relay nie dowodzi, że ModifyRequest się nie powiódł.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

Wymuś uwierzytelnianie SMB osobno; zobacz [wymuszanie uprzywilejowanego uwierzytelniania NTLM](printers-spooler-service-abuse.md), gdzie opisano jeden z wektorów wymuszania, oraz [przegląd relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), gdzie opisano pozostałe. Polecenie narzędzia i jego implementację opisano w jego repozytorium.<sup>[[6]](#references)</sup>

## Wdrożenie z audytem na pierwszym miejscu (zalecane: ok. 30 dni)

1. Włącz diagnostykę interfejsu LDAP na każdym DC, aby rejestrować niepodpisane bindy (zdarzenie **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Ustaw w DC GPO `LDAP server channel binding token requirements` = **When Supported**, aby częściowo wymuszać CBT i zbierać telemetrię; najpierw sprawdź zgodność ze starszymi klientami.<sup>[[1]](#references)</sup>
3. Monitoruj zdarzenia Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – bindy unsigned/unsigned-allow (niezgodne z wymaganiami podpisywania).
   - **3074/3075** – bindy LDAPS, które zakończyłyby się niepowodzeniem lub pomijały CBT (wymaga KB4520412 w wersjach 2019/2022 oraz wykonania kroku 2 powyżej).
4. Wprowadzaj wymuszenia w osobnych zmianach:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC).
   - `LDAP client signing requirements` = **Require signing** (klienci).
   - `LDAP server signing requirements` = **Require signing** (DC) **lub** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec – LDAP Channel Binding i LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 – wymagania dotyczące LDAP channel binding i signing](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 – aktualizacja ograniczająca LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing wyłączone → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – Signed, Sealed, and Relayed, w stylu NTLM](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [Proof of concept LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo)
- [7] [Microsoft – informacje o wydaniach Windows Server](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
{{#include ../../banners/hacktricks-training.md}}
