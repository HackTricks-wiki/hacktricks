# Wzmacnianie zabezpieczeń LDAP Signing i Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Dlaczego to ważne

Ataki LDAP relay/MITM przekazują uwierzytelnianie do kontrolera domeny, aby uzyskać uwierzytelniony kontekst LDAP. Dwie powiązane kontrolki ograniczają te możliwości:

- **LDAP channel binding (CBT)** wiąże odpowiednie uwierzytelnianie z certyfikatem TLS serwera/kanałem używanym przez LDAPS, utrudniając relay między kanałami.
- **LDAP signing** wymaga ochrony integralności dla bindów LDAP SASL. Nie zapewnia poufności; użyj TLS, jeśli zawartość LDAP również wymaga szyfrowania.<sup>[[2]](#references)</sup>

**Szybka ocena konfiguracji**: narzędzia takie jak `netexec ldap <dc> -u user -p pass` raportują zaobserwowane ustawienia signing i channel binding. `(signing:None)` i `(channel binding:Never)` wskazują na brak tych zabezpieczeń, ale powodzenie relay nadal zależy od przechwyconego typu uwierzytelniania, działania EPA, uprawnień konta, protokołu docelowego i zabezpieczeń przed relay. Jeśli przekazany podmiot ma odpowiednie uprawnienia, narzędzia takie jak KrbRelayUp mogą zapisać `msDS-AllowedToActOnBehalfOfOtherIdentity`, skonfigurować delegowanie ograniczone do zasobów (RBCD) i wykorzystać uzyskaną ścieżkę delegowania do podszycia się pod uprzywilejowany podmiot.<sup>[[4]](#references)</sup>

**Kontrolery domeny Server 2025** wprowadzają nowe GPO (**LDAP server signing requirements Enforcement**), które domyślnie wymusza **Require Signing**, gdy pozostaje ustawione na **Not Configured**. Aby uniknąć wymuszania, należy jawnie ustawić tę zasadę na **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (tylko LDAPS)

- **Wymagania**:
  - Poprawka CVE-2017-8563 (2017) dodaje obsługę Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) dodaje telemetrię LDAPS CBT „what-if”.<sup>[[2]](#references)</sup>
- **GPO (kontrolery domeny)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (wartość domyślna, brak CBT)
  - `When Supported` (częściowe wymuszanie: klienci obsługujący CBT muszą dostarczyć prawidłowy token; klienci bez obsługi CBT nadal mogą nawiązać bind, a zdarzenia audytu są rejestrowane)
  - `Always` (wymuszanie: odrzuca bindy LDAPS bez prawidłowego CBT)<sup>[[1]](#references)</sup>
- **Audyt**: ustaw **When Supported**, aby wykrywać:
  - **3074** – bind LDAPS nie przeszedłby walidacji CBT, gdyby wymuszanie było włączone.
  - **3075** – bind LDAPS nie zawierał danych CBT i zostałby odrzucony, gdyby wymuszanie było włączone.
  - (Zdarzenie **3039** nadal sygnalizuje błędy CBT w starszych kompilacjach.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Wymuszanie**: ustaw **Always**, gdy klienci LDAPS zaczną wysyłać CBT; działa wyłącznie w przypadku **LDAPS** (nie surowego portu 389).<sup>[[1]](#references)</sup>

`When Supported` to nie tylko tryb audytu: weryfikuje CBT u klientów, którzy je obsługują, jednocześnie dopuszczając klientów bez obsługi CBT. [Dokumentacja zasad Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) opisuje zależne od wersji ustawienia domyślne. LDAP signing dotyczy odpowiednich bindów LDAP/389; channel binding dotyczy uwierzytelniania LDAP chronionego przez TLS.


## LDAP Signing

- **GPO klienta**: `Network security: LDAP client signing requirements` = `Require signing` (zamiast domyślnego `Negotiate signing` we współczesnym Windows).<sup>[[1]](#references)</sup>
- **GPO kontrolera domeny**:
  - Starsze wersje: `Domain controller: LDAP server signing requirements` = `Require signing` (wartością domyślną jest `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: pozostaw starszą zasadę na `None` i ustaw `LDAP server signing requirements Enforcement` = `Enabled` (`Not Configured` domyślnie oznacza wymuszanie; ustaw `Disabled`, aby go uniknąć).<sup>[[1]](#references)</sup>
- **Zgodność**: zinwentaryzuj urządzenia i aplikacje inne niż Windows, które używają prostych bindów lub niepodpisanych bindów SASL. Microsoft dokumentuje obsługę w utrzymywanych wersjach Windows; deklaracje zgodności ze starszymi klientami należy weryfikować w odniesieniu do faktycznie używanego stosu klienta, zamiast sprowadzać je do progu wersji XP.<sup>[[2]](#references)</sup>

## Wdrożenie z audytem na początku (zalecane: około 30 dni)

1. Włącz diagnostykę interfejsu LDAP na każdym kontrolerze domeny, aby rejestrować niepodpisane bindy (zdarzenie **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Ustaw w GPO kontrolera domeny `LDAP server channel binding token requirements` = **When Supported**, aby częściowo wymuszać CBT i zbierać dane telemetryczne; najpierw sprawdź zgodność ze starszymi klientami.<sup>[[1]](#references)</sup>
3. Monitoruj zdarzenia Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – powiązania unsigned/unsigned-allow (niezgodne z wymaganiami dotyczącymi signing).
   - **3074/3075** – powiązania LDAPS, które zakończyłyby się niepowodzeniem lub pomijałyby CBT (wymagają KB4520412 w wersjach 2019/2022 oraz wykonania powyższego kroku 2).
4. Wprowadzaj wymuszenie w osobnych zmianach:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (kontrolery domeny).
   - `LDAP client signing requirements` = **Require signing** (klienci).
   - `LDAP server signing requirements` = **Require signing** (kontrolery domeny) **lub** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [1] [TrustedSec – LDAP Channel Binding i LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 – wymagania dotyczące LDAP channel binding i signing](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 – aktualizacja ograniczająca LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (wyłączone LDAP signing → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
