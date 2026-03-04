# Rafforzamento LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Perché è importante

LDAP relay/MITM permette agli aggressori di inoltrare bind verso i Domain Controllers per ottenere contesti autenticati. Due controlli lato server bloccano questi percorsi:

- **LDAP Channel Binding (CBT)** lega un LDAPS bind al tunnel TLS specifico, interrompendo relay/replay tra canali differenti.
- **LDAP Signing** impone messaggi LDAP protetti per integrità, impedendo manomissioni e la maggior parte dei relay non firmati.

**Controllo offensivo rapido**: strumenti come `netexec ldap <dc> -u user -p pass` stampano la postura del server. Se vedi `(signing:None)` e `(channel binding:Never)`, i Kerberos/NTLM relay verso LDAP sono fattibili (es. usando KrbRelayUp per scrivere `msDS-AllowedToActOnBehalfOfOtherIdentity` per RBCD e impersonare amministratori).

I DC Server 2025 introducono una nuova GPO (**LDAP server signing requirements Enforcement**) che per default imposta **Require Signing** quando rimane **Not Configured**. Per evitare l'enforcement devi impostare esplicitamente quella policy su **Disabled**.

## LDAP Channel Binding (solo LDAPS)

- **Requisiti**:
- La patch CVE-2017-8563 (2017) aggiunge il supporto per Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) aggiunge la telemetria “what-if” per LDAPS CBT.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (predefinito, nessun CBT)
- `When Supported` (audit: registra i fallimenti, non blocca)
- `Always` (enforce: rifiuta LDAPS bind senza CBT valido)
- **Audit**: imposta **When Supported** per evidenziare:
- **3074** – Un LDAPS bind avrebbe fallito la validazione CBT se fosse stato applicato.
- **3075** – Un LDAPS bind ha omesso i dati CBT e sarebbe stato rifiutato se applicato.
- (Event **3039** segnala ancora i fallimenti CBT su build più vecchie.)
- **Enforcement**: imposta **Always** una volta che i client LDAPS inviano CBT; efficace solo su **LDAPS** (non su 389 non cifrato).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` impostazione predefinita sulle versioni moderne di Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (il default è `None`).
- **Server 2025**: lascia la policy legacy su `None` e imposta `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = applicato per default; imposta `Disabled` per evitarlo).
- **Compatibilità**: solo Windows **XP SP3+** supporta LDAP signing; i sistemi più vecchi smetteranno di funzionare quando l'enforcement è abilitato.

## Implementazione in modalità audit (consigliata ~30 giorni)

1. Abilita la diagnostica dell'interfaccia LDAP su ogni DC per registrare i bind non firmati (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Impostare la GPO DC `LDAP server channel binding token requirements` = **When Supported** per avviare la telemetria CBT.
3. Monitorare gli eventi di Directory Service:
- **2889** – unsigned/unsigned-allow binds (firma non conforme).
- **3074/3075** – LDAPS binds che fallirebbero o ometterebbero CBT (richiede KB4520412 su 2019/2022 e il passaggio 2 sopra).
4. Applicare in modifiche separate:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (client).
- `LDAP server signing requirements` = **Require signing** (DCs) **o** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Riferimenti

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
