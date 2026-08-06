# Hardening LDAP Signing i Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Dlaczego ma to znaczenie

LDAP relay/MITM pozwala atakującym przekazywać bindy do Domain Controllers w celu uzyskania uwierzytelnionych kontekstów. Dwie kontrolki po stronie serwera ograniczają te ścieżki:

- **LDAP Channel Binding (CBT)** wiąże bind LDAPS z konkretnym tunelem TLS, uniemożliwiając relaye/replaye między różnymi kanałami.
- **LDAP Signing** wymusza komunikaty LDAP chronione integralnością, zapobiegając manipulacjom i większości unsigned relayów.

**Szybka kontrola ofensywna**: narzędzia takie jak `netexec ldap <dc> -u user -p pass` wyświetlają konfigurację serwera. Jeśli widzisz `(signing:None)` i `(channel binding:Never)`, **relaye Kerberos/NTLM do LDAP** są możliwe (np. przy użyciu KrbRelayUp do zapisania `msDS-AllowedToActOnBehalfOfOtherIdentity` na potrzeby RBCD i impersonacji administratorów).<sup>[[4]](#references)</sup>

**DCs Server 2025** wprowadzają nowe GPO (**LDAP server signing requirements Enforcement**), które domyślnie ustawia **Require Signing**, gdy pozostaje **Not Configured**. Aby uniknąć wymuszania, należy jawnie ustawić tę politykę na **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (tylko LDAPS)

- **Wymagania**:
- Patch CVE-2017-8563 (2017) dodaje obsługę Extended Protection for Authentication.<sup>[[3]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (domyślnie, bez CBT)
- `When Supported` (audyt: generuje błędy, ale nie blokuje)
- `Always` (wymuszanie: odrzuca bindy LDAPS bez prawidłowego CBT)<sup>[[1]](#references)</sup>
- **Audyt**: ustaw **When Supported**, aby wykrywać:
- **3074** – bind LDAPS nie przeszedłby walidacji CBT, gdyby była wymuszana.
- **3075** – bind LDAPS nie zawierał danych CBT i zostałby odrzucony, gdyby CBT była wymuszana.
- (Zdarzenie **3039** nadal sygnalizuje błędy CBT na starszych buildach.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Wymuszanie**: ustaw **Always**, gdy klienci LDAPS wysyłają CBT; działa to wyłącznie dla **LDAPS** (nie dla surowego portu 389).<sup>[[1]](#references)</sup>


## LDAP Signing

- **GPO klienta**: `Network security: LDAP client signing requirements` = `Require signing` (w przeciwieństwie do domyślnego `Negotiate signing` na nowoczesnych systemach Windows).<sup>[[1]](#references)</sup>
- **GPO DC**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (domyślnie `None`).<sup>[[2]](#references)</sup>
- **Server 2025**: pozostaw legacy policy ustawioną na `None` i ustaw `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = domyślne wymuszanie; ustaw `Disabled`, aby go uniknąć).<sup>[[1]](#references)</sup>
- **Kompatybilność**: tylko Windows **XP SP3+** obsługuje LDAP signing; starsze systemy przestaną działać po włączeniu wymuszania.

## Wdrożenie najpierw audytu (zalecane około 30 dni)

1. Włącz diagnostykę interfejsu LDAP na każdym DC, aby rejestrować unsigned bindy (zdarzenie **2889**):<sup>[[1]](#references)</sup>
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Ustaw w DC GPO `LDAP server channel binding token requirements` = **When Supported**, aby rozpocząć telemetry CBT.<sup>[[1]](#references)</sup>
3. Monitoruj zdarzenia Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
- **2889** – bindy unsigned/unsigned-allow (niezgodne z wymaganiami signing).
- **3074/3075** – bindy LDAPS, które zakończyłyby się niepowodzeniem lub pominęłyby CBT (wymaga KB4520412 w wersjach 2019/2022 oraz wykonania kroku 2 powyżej).
4. Wymuś ustawienia w oddzielnych zmianach:<sup>[[1]](#references)</sup>
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **lub** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [1] [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
