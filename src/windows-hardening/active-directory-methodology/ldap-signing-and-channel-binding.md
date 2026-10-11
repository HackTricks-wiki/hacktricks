# Rafforzamento di LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Perché è importante

Gli attacchi LDAP relay/MITM inoltrano l’autenticazione a un domain controller per ottenere un contesto LDAP autenticato. Due controlli correlati riducono queste possibilità:

- **LDAP channel binding (CBT)** associa l’autenticazione applicabile al certificato/canale TLS usato da LDAPS, ostacolando il relay tra canali diversi.
- **LDAP signing** richiede la protezione dell’integrità per i bind LDAP SASL. Non aggiunge riservatezza: usa TLS quando è necessario anche cifrare i contenuti LDAP.<sup>[[2]](#references)</sup>

**Controllo rapido della postura**: strumenti come `netexec ldap <dc> -u user -p pass` segnalano le policy di signing e channel binding rilevate. `(signing:None)` e `(channel binding:Never)` indicano l’assenza dei controlli, ma l’esito positivo di un relay dipende comunque dal tipo di autenticazione acquisita, dal comportamento di EPA, dai privilegi dell’account, dal protocollo di destinazione e dalle protezioni contro i relay. Quando il principal inoltrato dispone dei diritti necessari, strumenti come KrbRelayUp possono scrivere `msDS-AllowedToActOnBehalfOfOtherIdentity`, configurare la delega vincolata basata sulle risorse (RBCD) e usare il percorso di delega risultante per impersonare un principal privilegiato.<sup>[[4]](#references)</sup>

I **DC Server 2025** introducono una nuova GPO (**LDAP server signing requirements Enforcement**), che per impostazione predefinita applica **Require Signing** se lasciata su **Not Configured**. Per evitare l’applicazione della policy, è necessario impostarla esplicitamente su **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (solo LDAPS)

- **Requisiti**:
  - La patch CVE-2017-8563 (2017) aggiunge il supporto per Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) aggiunge la telemetria “what-if” di LDAPS CBT.<sup>[[2]](#references)</sup>
- **GPO (DC)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (predefinito, nessun CBT)
  - `When Supported` (applicazione parziale: i client compatibili con CBT devono fornire un token valido; i client senza supporto CBT possono comunque eseguire il bind e vengono generati eventi di audit)
  - `Always` (applicazione forzata: rifiuta i bind LDAPS senza un CBT valido)<sup>[[1]](#references)</sup>
- **Audit**: imposta **When Supported** per rilevare:
  - **3074** – il bind LDAPS non avrebbe superato la convalida CBT se l’applicazione fosse stata forzata.
  - **3075** – il bind LDAPS non includeva i dati CBT e sarebbe stato rifiutato se l’applicazione fosse stata forzata.
  - (L’evento **3039** continua a segnalare gli errori CBT nelle build precedenti.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Applicazione forzata**: imposta **Always** quando i client LDAPS inviano CBT; è efficace solo su **LDAPS** (non sulla porta 389 non cifrata).<sup>[[1]](#references)</sup>

`When Supported` non è una modalità di solo audit: convalida il CBT per i client compatibili, consentendo al contempo l’accesso ai client senza supporto CBT. La [documentazione Microsoft della policy](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) descrive i valori predefiniti, che variano in base alla versione. LDAP signing si applica ai bind interessati su LDAP/389; channel binding si applica all’autenticazione LDAP protetta da TLS.


## LDAP Signing

- **GPO client**: `Network security: LDAP client signing requirements` = `Require signing` (anziché `Negotiate signing`, predefinito nelle versioni moderne di Windows).<sup>[[1]](#references)</sup>
- **GPO DC**:
  - Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (il valore predefinito è `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: lascia la policy legacy su `None` e imposta `LDAP server signing requirements Enforcement` = `Enabled` (`Not Configured` applica la policy per impostazione predefinita; imposta `Disabled` per evitarlo).<sup>[[1]](#references)</sup>
- **Compatibilità**: censisci gli appliance e le applicazioni non Windows che usano bind semplici o bind SASL senza firma. Microsoft documenta il supporto nelle versioni di Windows ancora mantenute; le dichiarazioni di compatibilità con i client legacy vanno verificate rispetto allo stack client effettivo, anziché ricondurle a una versione soglia di XP.<sup>[[2]](#references)</sup>

## Implementazione con audit iniziale (circa 30 giorni, consigliata)

1. Abilita la diagnostica dell’interfaccia LDAP su ogni DC per registrare i bind senza firma (evento **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Imposta il GPO del DC `LDAP server channel binding token requirements` su **When Supported** per l’applicazione parziale di CBT e la telemetria; verifica prima la compatibilità con i client legacy.<sup>[[1]](#references)</sup>
3. Monitora gli eventi Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – bind non firmati/consentiti senza firma (non conformi ai requisiti di firma).
   - **3074/3075** – bind LDAPS che non andrebbero a buon fine o ometterebbero CBT (richiede KB4520412 su 2019/2022 e il passaggio 2 sopra).
4. Applica le modifiche separatamente:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC).
   - `LDAP client signing requirements` = **Require signing** (client).
   - `LDAP server signing requirements` = **Require signing** (DC) **oppure** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [1] [TrustedSec - LDAP Channel Binding e LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - requisiti di LDAP channel binding e signing](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - aggiornamento per la mitigazione di LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabilitato → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
