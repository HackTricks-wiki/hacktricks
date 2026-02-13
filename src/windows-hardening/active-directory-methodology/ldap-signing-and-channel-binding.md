# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Perché è importante

LDAP relay/MITM permette agli attacker di inoltrare binds verso i Domain Controller per ottenere contesti autenticati. Due controlli lato server mitigano questi vettori:

- **LDAP Channel Binding (CBT)** lega un LDAPS bind al tunnel TLS specifico, interrompendo relay/replay su canali diversi.
- **LDAP Signing** obbliga messaggi LDAP con integrità protetta, impedendo manomissioni e la maggior parte dei relay non firmati.

**Server 2025 DCs** introduce una nuova GPO (**LDAP server signing requirements Enforcement**) che di default imposta **Require Signing** quando lasciata **Not Configured**. Per evitare l'enforcement devi impostare esplicitamente quella policy su **Disabled**.

## LDAP Channel Binding (LDAPS only)

- **Requirements**:
- CVE-2017-8563 patch (2017) aggiunge il supporto per Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) aggiunge telemetria LDAPS CBT “what-if”.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, no CBT)
- `When Supported` (audit: emits failures, does not block)
- `Always` (enforce: rejects LDAPS binds without valid CBT)
- **Audit**: imposta **When Supported** per far emergere:
- **3074** – LDAPS bind would have failed CBT validation if enforced.
- **3075** – LDAPS bind omitted CBT data and would be rejected if enforced.
- (Evento **3039** segnala ancora CBT failures su build più vecchie.)
- **Enforcement**: imposta **Always** una volta che i LDAPS clients inviano CBTs; efficace solo su **LDAPS** (non su raw 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).
- **Server 2025**: lascia la policy legacy su `None` e imposta `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = enforced by default; imposta `Disabled` per evitarlo).
- **Compatibility**: solo Windows **XP SP3+** supporta LDAP signing; sistemi più vecchi si romperanno quando l'enforcement è abilitato.

## Audit-first rollout (recommended ~30 days)

1. Abilita la diagnostica dell'interfaccia LDAP su ogni DC per registrare unsigned binds (Evento **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Imposta la GPO DC `LDAP server channel binding token requirements` = **When Supported** per avviare la telemetria CBT.
3. Monitorare gli eventi di Directory Service:
- **2889** – unsigned/unsigned-allow binds (signing noncompliant).
- **3074/3075** – LDAPS binds che fallirebbero o ometterebbero CBT (richiede KB4520412 su 2019/2022 e il passo 2 sopra).
4. Applicare in modifiche separate:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Riferimenti

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)

{{#include ../../banners/hacktricks-training.md}}
