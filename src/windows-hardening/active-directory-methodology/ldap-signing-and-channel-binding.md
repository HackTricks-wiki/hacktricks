# Hardening di LDAP Signing e Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Perché è importante

LDAP relay/MITM consente agli attacker di inoltrare i bind ai Domain Controller per ottenere contesti autenticati. Due controlli lato server limitano questi percorsi:

- **LDAP Channel Binding (CBT)** associa un bind LDAPS al tunnel TLS specifico, interrompendo relay/replay tra canali diversi.
- **LDAP Signing** forza messaggi LDAP protetti tramite integrità, impedendo la manomissione e la maggior parte dei relay non firmati.

**Controllo offensivo rapido**: strumenti come `netexec ldap <dc> -u user -p pass` mostrano il security posture del server. Se visualizzi `(signing:None)` e `(channel binding:Never)`, i **relay di Kerberos/NTLM verso LDAP** sono possibili, ad esempio usando KrbRelayUp per scrivere `msDS-AllowedToActOnBehalfOfOtherIdentity` per RBCD e impersonare gli amministratori.<sup>[[4]](#references)</sup>

I DC Server 2025 introducono una nuova GPO (**LDAP server signing requirements Enforcement**) che, se lasciata su **Not Configured**, imposta per impostazione predefinita **Require Signing**. Per evitare l'enforcement devi impostare esplicitamente tale policy su **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (solo LDAPS)

- **Requisiti**:
- La patch CVE-2017-8563 (2017) aggiunge il supporto a Extended Protection for Authentication.<sup>[[3]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (predefinito, nessun CBT)
- `When Supported` (audit: genera failure, ma non blocca)
- `Always` (enforce: rifiuta i bind LDAPS senza un CBT valido)<sup>[[1]](#references)</sup>
- **Audit**: imposta **When Supported** per individuare:
- **3074** – Il bind LDAPS sarebbe fallito nella validazione CBT se l'enforcement fosse attivo.
- **3075** – Il bind LDAPS non includeva dati CBT e sarebbe stato rifiutato se l'enforcement fosse attivo.
- (L'evento **3039** segnala comunque i failure CBT nelle build precedenti.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**: imposta **Always** quando i client LDAPS inviano i CBT; è efficace solo su **LDAPS** (non sulla porta raw 389).<sup>[[1]](#references)</sup>


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (rispetto a `Negotiate signing`, predefinito nelle versioni moderne di Windows).<sup>[[1]](#references)</sup>
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (il valore predefinito è `None`).<sup>[[2]](#references)</sup>
- **Server 2025**: lascia la policy legacy su `None` e imposta `LDAP server signing requirements Enforcement` = `Enabled` (`Not Configured` = enforced per impostazione predefinita; imposta `Disabled` per evitarlo).<sup>[[1]](#references)</sup>
- **Compatibilità**: solo Windows **XP SP3+** supporta LDAP signing; i sistemi più vecchi smetteranno di funzionare quando l'enforcement sarà abilitato.

## Rollout basato prima sull'audit (circa 30 giorni consigliati)

1. Abilita la diagnostica dell'interfaccia LDAP su ogni DC per registrare i bind non firmati (evento **2889**):<sup>[[1]](#references)</sup>
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Imposta la GPO del DC `LDAP server channel binding token requirements` = **When Supported** per iniziare la telemetria CBT.<sup>[[1]](#references)</sup>
3. Monitora gli eventi Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
- **2889** – bind unsigned/unsigned-allow (non conformi ai requisiti di signing).
- **3074/3075** – bind LDAPS che fallirebbero o ometterebbero il CBT (richiede KB4520412 su 2019/2022 e il passaggio 2 precedente).
4. Applica le modifiche separatamente:<sup>[[1]](#references)</sup>
- `LDAP server channel binding token requirements` = **Always** (DC).
- `LDAP client signing requirements` = **Require signing** (client).
- `LDAP server signing requirements` = **Require signing** (DC) **oppure** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Riferimenti

- [1] [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
