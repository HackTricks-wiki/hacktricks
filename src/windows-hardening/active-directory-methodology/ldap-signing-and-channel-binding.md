# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Dlaczego to ważne

LDAP relay/MITM pozwala atakującym przekierowywać binds do Domain Controllers, aby uzyskać uwierzytelnione konteksty. Dwie kontrole po stronie serwera ograniczają te ścieżki:

- **LDAP Channel Binding (CBT)** wiąże LDAPS bind z konkretnym tunelem TLS, uniemożliwiając relaye/replaye przez różne kanały.
- **LDAP Signing** wymusza integralność wiadomości LDAP, zapobiegając manipulacji i większości niepodpisanych relayów.

**Server 2025 DCs** wprowadzają nowe GPO (**LDAP server signing requirements Enforcement**), które domyślnie ustawia **Require Signing** gdy pozostawione jest jako **Not Configured**. Aby uniknąć egzekwowania, musisz explicite ustawić tę politykę na **Disabled**.

## LDAP Channel Binding (LDAPS only)

- **Wymagania**:
- CVE-2017-8563 patch (2017) dodaje obsługę Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) dodaje LDAPS CBT „what-if” telemetry.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (domyślnie, brak CBT)
- `When Supported` (audyt: generuje błędy, nie blokuje)
- `Always` (wymuszanie: odrzuca LDAPS binds bez prawidłowego CBT)
- **Audyt**: ustaw **When Supported** aby ujawnić:
- **3074** – LDAPS bind nie przeszedłby walidacji CBT, gdyby wymuszono.
- **3075** – LDAPS bind pominął dane CBT i zostałby odrzucony, gdyby wymuszono.
- (Zdarzenie **3039** nadal sygnalizuje błędy CBT na starszych buildach.)
- **Wymuszanie**: ustaw **Always** gdy klienci LDAPS zaczynają wysyłać CBT; skuteczne tylko dla **LDAPS** (nie dla surowego 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` domyślnie na nowoczesnych Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (domyślnie `None`).
- **Server 2025**: pozostaw legacy policy na `None` i ustaw `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = domyślnie egzekwowane; ustaw `Disabled`, aby tego uniknąć).
- **Zgodność**: tylko Windows **XP SP3+** obsługuje LDAP signing; starsze systemy przestaną działać, gdy wymuszanie zostanie włączone.

## Audit-first rollout (recommended ~30 days)

1. Włącz diagnostykę interfejsu LDAP na każdym DC, aby logować niepodpisane binds (Zdarzenie **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Ustaw GPO DC `LDAP server channel binding token requirements` = **Gdy obsługiwane** aby rozpocząć telemetrię CBT.
3. Monitoruj zdarzenia Directory Service:
- **2889** – unsigned/unsigned-allow binds (brak wymaganego podpisywania).
- **3074/3075** – LDAPS binds które zakończyłyby się niepowodzeniem lub pominęłyby CBT (wymaga KB4520412 na 2019/2022 i kroku 2 powyżej).
4. Wymuś w oddzielnych zmianach:
- `LDAP server channel binding token requirements` = **Zawsze** (DCs).
- `LDAP client signing requirements` = **Wymagaj podpisywania** (clients).
- `LDAP server signing requirements` = **Wymagaj podpisywania** (DCs) **lub** (Server 2025) `LDAP server signing requirements Enforcement` = **Włączone**.

## Źródła

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)

{{#include ../../banners/hacktricks-training.md}}
