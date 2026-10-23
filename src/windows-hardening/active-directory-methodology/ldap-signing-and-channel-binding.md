# Wzmacnianie zabezpieczeń LDAP Signing i Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Dlaczego to ważne

Ataki LDAP relay/MITM przekazują uwierzytelnianie do kontrolera domeny, aby uzyskać uwierzytelniony kontekst LDAP. [Przegląd zatruwania rozpoznawania nazw i ataków relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) opisuje szerszy przebieg ataku. Dwa powiązane mechanizmy ograniczają te ścieżki:

- **LDAP channel binding (CBT)** wiąże odpowiednie uwierzytelnianie z certyfikatem/kanałem serwera TLS używanym przez LDAPS, utrudniając relay między kanałami.
- **LDAP signing** wymaga ochrony integralności dla powiązań SASL LDAP. Nie zapewnia poufności; użyj TLS, jeśli zawartość LDAP również wymaga szyfrowania.<sup>[[2]](#references)</sup>

**Szybka ocena konfiguracji**: narzędzia takie jak `netexec ldap <dc> -u user -p pass` raportują wykryte ustawienia signing i channel binding. `(signing:None)` i `(channel binding:Never)` oznaczają brak tych zabezpieczeń, ale powodzenie relay nadal zależy od przechwyconego typu uwierzytelniania, działania EPA, uprawnień konta, protokołu docelowego i zabezpieczeń przed relay. Jeśli przekazany podmiot ma wymagane uprawnienia, narzędzia takie jak KrbRelayUp mogą zapisać `msDS-AllowedToActOnBehalfOfOtherIdentity`, skonfigurować delegowanie ograniczone do zasobów (RBCD) i użyć wynikowej ścieżki delegowania do podszycia się pod uprzywilejowany podmiot.<sup>[[4]](#references)</sup>

**Kontrolery domeny Server 2025** wprowadzają nowe GPO (**LDAP server signing requirements Enforcement**), które domyślnie wymaga **Require Signing**, gdy pozostawiono je jako **Not Configured**. Aby uniknąć wymuszania, należy jawnie ustawić tę zasadę na **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (tylko LDAPS)

- **Wymagania**:
  - Poprawka CVE-2017-8563 (2017) dodaje obsługę Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) dodaje telemetrię LDAPS CBT „what-if”.<sup>[[2]](#references)</sup>
- **GPO (kontrolery domeny)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (wartość domyślna, brak CBT)
  - `When Supported` (częściowe wymuszanie: klienci obsługujący CBT muszą dostarczyć prawidłowy token; klienci bez obsługi CBT nadal mogą się łączyć, a zdarzenia audytu są generowane)
  - `Always` (wymuszanie: odrzuca połączenia LDAPS bez prawidłowego CBT)<sup>[[1]](#references)</sup>
- **Audyt**: ustaw **When Supported**, aby wykrywać:
  - **3074** – połączenie LDAPS nie przeszłoby walidacji CBT, gdyby mechanizm był wymuszany.
  - **3075** – połączenie LDAPS nie zawierało danych CBT i zostałoby odrzucone, gdyby mechanizm był wymuszany.
  - (Zdarzenie **3039** nadal sygnalizuje błędy CBT w starszych kompilacjach.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Wymuszanie**: ustaw **Always**, gdy klienci LDAPS zaczną wysyłać CBT; działa wyłącznie dla **LDAPS** (nie dla surowego portu 389).<sup>[[1]](#references)</sup>

`When Supported` nie służy wyłącznie do audytu: weryfikuje CBT u obsługujących je klientów, jednocześnie dopuszczając klientów bez obsługi CBT. [Dokumentacja zasad firmy Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) opisuje wartości domyślne zależne od wersji. LDAP signing dotyczy odpowiednich połączeń LDAP/389; channel binding dotyczy uwierzytelniania LDAP chronionego przez TLS.


## LDAP Signing

- **GPO klienta**: `Network security: LDAP client signing requirements` = `Require signing` (zamiast domyślnego `Negotiate signing` w nowoczesnym systemie Windows).<sup>[[1]](#references)</sup>
- **GPO kontrolera domeny**:
  - Starsza zasada: `Domain controller: LDAP server signing requirements` = `Require signing` (wartość domyślna to `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: pozostaw starszą zasadę jako `None` i ustaw `LDAP server signing requirements Enforcement` = `Enabled` (`Not Configured` oznacza domyślne wymuszanie; ustaw `Disabled`, aby go uniknąć).<sup>[[1]](#references)</sup>
- **Zgodność**: zinwentaryzuj urządzenia i aplikacje spoza systemu Windows korzystające z prostych połączeń bind lub niepodpisanych połączeń SASL bind. Firma Microsoft dokumentuje obsługę w utrzymywanych wersjach systemu Windows; deklaracje dotyczące zgodności ze starszymi klientami należy weryfikować dla faktycznie używanego stosu klienckiego, zamiast sprowadzać je do progu wersji XP.<sup>[[2]](#references)</sup>

## Wdrożenie z audytem w pierwszej kolejności (zalecane około 30 dni)

1. Włącz diagnostykę interfejsu LDAP na każdym kontrolerze domeny, aby rejestrować niepodpisane połączenia bind (zdarzenie **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Ustaw w DC GPO `LDAP server channel binding token requirements` = **When Supported**, aby częściowo wymuszać CBT i zbierać dane telemetryczne; najpierw sprawdź zgodność ze starszymi klientami.<sup>[[1]](#references)</sup>
3. Monitoruj zdarzenia Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – powiązania bez podpisu lub z dozwolonym brakiem podpisu (niezgodność z wymaganiami dotyczącymi podpisywania).
   - **3074/3075** – powiązania LDAPS, które zakończyłyby się niepowodzeniem lub nie zawierałyby CBT (wymaga KB4520412 na systemach 2019/2022 oraz wykonania kroku 2 powyżej).
4. Wprowadzaj wymuszanie w osobnych zmianach:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC).
   - `LDAP client signing requirements` = **Require signing** (klienci).
   - `LDAP server signing requirements` = **Require signing** (DC) **lub** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec – wiązanie kanału LDAP i podpisywanie LDAP](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 – wymagania dotyczące wiązania kanału LDAP i podpisywania LDAP](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 – aktualizacja ograniczająca ataki LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (wyłączone podpisywanie LDAP → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
