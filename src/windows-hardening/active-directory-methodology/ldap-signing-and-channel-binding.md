# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Perché è importante

LDAP relay/MITM permette agli attacker di inoltrare bind verso i Domain Controller per ottenere contesti autenticati. Due controlli lato server mitigano queste vie:

- **LDAP Channel Binding (CBT)** lega un LDAPS bind al tunnel TLS specifico, interrompendo relay/replay attraverso canali diversi.
- **LDAP Signing** forza messaggi LDAP con integrità protetta, prevenendo manomissioni e la maggior parte dei relay non firmati.

**Quick offensive check**: tools like `netexec ldap <dc> -u user -p pass` stampano la postura del server. Se vedi `(signing:None)` e `(channel binding:Never)`, Kerberos/NTLM **relays to LDAP** sono praticabili (es. usando KrbRelayUp per scrivere `msDS-AllowedToActOnBehalfOfOtherIdentity` per RBCD e impersonare amministratori).

I DC di Server 2025 introducono una nuova GPO (**LDAP server signing requirements Enforcement**) che di default imposta **Require Signing** quando lasciata **Not Configured**. Per evitare l'enforcement devi impostare esplicitamente quella policy su **Disabled**.

## LDAP Channel Binding (LDAPS only)

- **Requisiti**:
- La patch CVE-2017-8563 (2017) aggiunge il supporto Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) aggiunge telemetria "what-if" per LDAPS CBT.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, no CBT)
- `When Supported` (audit: emette errori, non blocca)
- `Always` (enforce: rifiuta LDAPS binds senza CBT valido)
- **Audit**: imposta **When Supported** per far emergere:
- **3074** – LDAPS bind avrebbe fallito la validazione CBT se forzato.
- **3075** – LDAPS bind ha omesso i dati CBT e sarebbe stato rifiutato se forzato.
- (Event **3039** segnala comunque i fallimenti CBT su build più vecchie.)
- **Enforcement**: imposta **Always** una volta che i client LDAPS inviano CBT; efficace solo su **LDAPS** (non sulla porta raw 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).
- **Server 2025**: lascia la policy legacy su `None` e imposta `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = applicata per default; imposta `Disabled` per evitarla).
- **Compatibility**: solo Windows **XP SP3+** supporta LDAP signing; sistemi più vecchi si romperanno quando l'enforcement è abilitato.

## Distribuzione orientata all'audit (consigliata ~30 giorni)

1. Abilita la diagnostica dell'interfaccia LDAP su ciascun DC per registrare i bind non firmati (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Impostare la GPO dei DC `LDAP server channel binding token requirements` = **When Supported** per avviare la telemetria CBT.
3. Monitorare gli eventi di Directory Service:
- **2889** – unsigned/unsigned-allow binds (signing noncompliant).
- **3074/3075** – LDAPS binds that would fail or omit CBT (requires KB4520412 on 2019/2022 and step 2 above).
4. Applicare in modifiche separate:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Riferimenti

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
