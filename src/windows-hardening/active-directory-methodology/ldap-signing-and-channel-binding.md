# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Dlaczego to ważne

LDAP relay/MITM pozwala atakującym przekazywać bindy do kontrolerów domeny, aby uzyskać uwierzytelnione konteksty. Dwie kontrole po stronie serwera tępią te ścieżki:

- **LDAP Channel Binding (CBT)** wiąże bind LDAPS z konkretnym tunelem TLS, uniemożliwiając relaye/replaye między różnymi kanałami.
- **LDAP Signing** wymusza integralność komunikatów LDAP, zapobiegając manipulacjom i większości niepodpisanych relayów.

**Quick offensive check**: narzędzia takie jak `netexec ldap <dc> -u user -p pass` wypisują postawę serwera. Jeśli zobaczysz `(signing:None)` i `(channel binding:Never)`, Kerberos/NTLM **relays to LDAP** są możliwe (np. używając KrbRelayUp do zapisania `msDS-AllowedToActOnBehalfOfOtherIdentity` dla RBCD i podszycia się pod administratorów).

**Server 2025 DCs** wprowadzają nowy GPO (**LDAP server signing requirements Enforcement**), który domyślnie ustawia **Require Signing** gdy pozostawiony jako **Not Configured**. Aby uniknąć wymuszania, musisz jawnie ustawić tę politykę na **Disabled**.

## LDAP Channel Binding (LDAPS tylko)

- **Requirements**:
- CVE-2017-8563 patch (2017) dodaje obsługę Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) dodaje LDAPS CBT “what-if” telemetry.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (domyślnie, brak CBT)
- `When Supported` (audyt: zgłasza błędy, nie blokuje)
- `Always` (wymuszanie: odrzuca LDAPS bindy bez prawidłowego CBT)
- **Audit**: ustaw **When Supported** żeby ujawnić:
- **3074** – LDAPS bind nie przeszedłby walidacji CBT, gdyby wymuszanie było aktywne.
- **3075** – LDAPS bind pominął dane CBT i zostałby odrzucony gdyby wymuszanie było aktywne.
- (Event **3039** nadal sygnalizuje błędy CBT na starszych buildach.)
- **Enforcement**: ustaw **Always** gdy klienci LDAPS zaczną wysyłać CBT; działa tylko na **LDAPS** (nie na surowym 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` — domyślnie w nowoczesnych Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).
- **Server 2025**: leave legacy policy at `None` and set `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = enforced by default; set `Disabled` to avoid it).
- **Compatibility**: only Windows **XP SP3+** supports LDAP signing; older systems will break when enforcement is enabled.

## Audit-first rollout (recommended ~30 days)

1. Włącz diagnostykę interfejsu LDAP na każdym DC, aby logować niepodpisane bindy (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Ustaw GPO DC `LDAP server channel binding token requirements` = **When Supported**, aby rozpocząć telemetrię CBT.
3. Monitoruj zdarzenia Directory Service:
- **2889** – unsigned/unsigned-allow binds (niezgodne z podpisywaniem).
- **3074/3075** – LDAPS binds, które zakończyłyby się niepowodzeniem lub pominęły CBT (wymaga KB4520412 na 2019/2022 oraz kroku 2 powyżej).
4. Wymuś w oddzielnych zmianach:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Źródła

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
