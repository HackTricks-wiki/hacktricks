# LDAP Signing & Channel Binding — wzmacnianie zabezpieczeń

{{#include ../../banners/hacktricks-training.md}}

## Dlaczego ma to znaczenie

LDAP relay/MITM pozwala atakującym przekierowywać binds do Domain Controllers, aby uzyskać uwierzytelnione konteksty. Dwa ustawienia po stronie serwera tłumią te ścieżki:

- **LDAP Channel Binding (CBT)** wiąże LDAPS bind z konkretnym tunelem TLS, łamiąc relaye/replaye między różnymi kanałami.
- **LDAP Signing** wymusza integralność wiadomości LDAP, zapobiegając manipulacjom i większości niepodpisanych relayów.

**Quick offensive check**: narzędzia takie jak `netexec ldap <dc> -u user -p pass` wypisują postawę serwera. Jeśli widzisz `(signing:None)` i `(channel binding:Never)`, Kerberos/NTLM **relays to LDAP** są możliwe (np. używając KrbRelayUp do zapisania `msDS-AllowedToActOnBehalfOfOtherIdentity` dla RBCD i podszycia się pod administratorów).

Server 2025 DCs wprowadzają nową GPO (**LDAP server signing requirements Enforcement**), która domyślnie ustawia **Require Signing** gdy pozostawiona jako **Not Configured**. Aby uniknąć egzekwowania, musisz jawnie ustawić tę politykę na **Disabled**.

## LDAP Channel Binding (LDAPS only)

- **Wymagania**:
- CVE-2017-8563 patch (2017) dodaje obsługę Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) dodaje LDAPS CBT „what-if” telemetry.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, no CBT)
- `When Supported` (audit: emits failures, does not block)
- `Always` (enforce: rejects LDAPS binds without valid CBT)
- **Audit**: ustaw **When Supported** aby ujawnić:
- **3074** – LDAPS bind nie przeszedłby walidacji CBT, gdyby egzekwowanie było włączone.
- **3075** – LDAPS bind pominął dane CBT i zostałby odrzucony, gdyby egzekwowanie było włączone.
- (Event **3039** nadal sygnalizuje błędy CBT na starszych buildach.)
- **Enforcement**: ustaw **Always** gdy klienci LDAPS zaczną wysyłać CBT; działa tylko na **LDAPS** (nie na surowym 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).
- **Server 2025**: pozostaw legacy policy jako `None` i ustaw `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = egzekwowane domyślnie; ustaw `Disabled`, aby tego uniknąć).
- **Compatibility**: tylko Windows **XP SP3+** obsługuje LDAP signing; starsze systemy przestaną działać po włączeniu egzekwowania.

## Wdrażanie z audytem w pierwszej kolejności (zalecane ~30 dni)

1. Włącz diagnostykę interfejsu LDAP na każdym DC, aby logować unsigned binds (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Ustaw DC GPO `LDAP server channel binding token requirements` = **When Supported**, aby rozpocząć telemetrykę CBT.
3. Monitoruj zdarzenia Directory Service:
- **2889** – unsigned/unsigned-allow binds (brak zgodności podpisywania).
- **3074/3075** – LDAPS binds, które zawiodłyby lub pominęły CBT (wymaga KB4520412 na 2019/2022 oraz kroku 2 powyżej).
4. Wprowadź wymuszanie w oddzielnych zmianach:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Źródła

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
