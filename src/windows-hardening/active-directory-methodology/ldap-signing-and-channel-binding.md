# Hardening di LDAP Signing e Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Perché è importante

Gli attacchi LDAP relay/MITM inoltrano l'autenticazione a un domain controller per ottenere un contesto LDAP autenticato. La [panoramica sul poisoning della risoluzione dei nomi e sul relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) illustra il flusso di lavoro più ampio. Due controlli correlati riducono queste possibilità:

- **LDAP channel binding (CBT)** associa l'autenticazione applicabile al certificato/canale TLS del server usato da LDAPS, ostacolando il relay tra canali diversi.
- **LDAP signing** richiede la protezione dell'integrità per i bind LDAP SASL. Non aggiunge riservatezza; usa TLS quando è necessario anche cifrare i contenuti LDAP.<sup>[[2]](#references)</sup>

**Controllo rapido della configurazione**: strumenti come `netexec ldap <dc> -u user -p pass` riportano i criteri di signing e channel binding rilevati. `(signing:None)` e `(channel binding:Never)` indicano l'assenza dei controlli, ma il successo di un relay dipende comunque dal tipo di autenticazione acquisita, dal comportamento di EPA, dai privilegi dell'account, dal protocollo di destinazione e dalle protezioni contro il relay. Quando il principal inoltrato dispone dei diritti necessari, strumenti come KrbRelayUp possono modificare `msDS-AllowedToActOnBehalfOfOtherIdentity`, configurare la delega vincolata basata sulle risorse (RBCD) e usare il percorso di delega risultante per impersonare un principal privilegiato.<sup>[[4]](#references)</sup>

I **DC Server 2025** introducono un nuovo GPO (**LDAP server signing requirements Enforcement**) che, se lasciato su **Not Configured**, imposta come predefinito **Require Signing**. Per evitare l'applicazione del criterio, è necessario impostarlo esplicitamente su **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (solo LDAPS)

- **Requisiti**:
  - La patch CVE-2017-8563 (2017) aggiunge il supporto per Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) aggiunge la telemetria “what-if” per LDAPS CBT.<sup>[[2]](#references)</sup>
- **GPO (DC)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (predefinito, nessun CBT)
  - `When Supported` (applicazione parziale: i client compatibili con CBT devono fornire un token valido; i client senza supporto CBT possono comunque eseguire il bind e vengono generati eventi di audit)
  - `Always` (applicazione obbligatoria: rifiuta i bind LDAPS senza un CBT valido)<sup>[[1]](#references)</sup>
- **Audit**: imposta **When Supported** per rilevare:
  - **3074** – Il bind LDAPS non avrebbe superato la convalida CBT se il criterio fosse stato applicato.
  - **3075** – Il bind LDAPS non includeva i dati CBT e sarebbe stato rifiutato se il criterio fosse stato applicato.
  - (L'evento **3039** continua a segnalare errori CBT nelle build meno recenti.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Applicazione**: imposta **Always** quando i client LDAPS inviano i CBT; è efficace solo su **LDAPS** (non sulla porta 389 non protetta da TLS).<sup>[[1]](#references)</sup>

`When Supported` non è una modalità di solo audit: convalida il CBT dei client compatibili e consente comunque l'accesso ai client senza supporto CBT. La [documentazione Microsoft sui criteri](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) descrive i valori predefiniti in base alla versione. LDAP signing si applica ai bind pertinenti su LDAP/389; il channel binding si applica all'autenticazione LDAP protetta da TLS.

## LDAP Signing

- **GPO client**: `Network security: LDAP client signing requirements` = `Require signing` (anziché il valore predefinito `Negotiate signing` nelle versioni moderne di Windows).<sup>[[1]](#references)</sup>
- **GPO DC**:
  - Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (il valore predefinito è `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: lascia il criterio legacy su `None` e imposta `LDAP server signing requirements Enforcement` = `Enabled` (con `Not Configured` il criterio viene applicato per impostazione predefinita; imposta `Disabled` per evitarne l'applicazione).<sup>[[1]](#references)</sup>
- **Compatibilità**: censisci gli apparati e le applicazioni non Windows che usano bind semplici o bind SASL senza firma. Microsoft documenta il supporto nelle versioni di Windows ancora mantenute; le dichiarazioni di compatibilità con i client legacy vanno verificate rispetto allo stack client effettivo, anziché ridurle a una soglia di versione di XP.<sup>[[2]](#references)</sup>

## Distribuzione con audit preliminare (consigliati circa 30 giorni)

1. Abilita la diagnostica dell'interfaccia LDAP su ogni DC per registrare i bind senza firma (evento **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Imposta `LDAP server channel binding token requirements` = **When Supported** nei GPO dei DC per applicare parzialmente CBT e raccogliere dati di telemetria; verifica prima la compatibilità con i client legacy.<sup>[[1]](#references)</sup>
3. Monitora gli eventi Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – bind non firmati/consentiti senza firma (non conformi ai requisiti di firma).
   - **3074/3075** – bind LDAPS che non riuscirebbero o ometterebbero CBT (richiede KB4520412 su 2019/2022 e il passaggio 2 sopra).
4. Applica le modifiche separatamente:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC).
   - `LDAP client signing requirements` = **Require signing** (client).
   - `LDAP server signing requirements` = **Require signing** (DC) **oppure** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - Binding del canale LDAP e firma LDAP](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Requisiti di binding del canale LDAP e firma LDAP](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Aggiornamento per la mitigazione dei relay LDAP](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (firma LDAP disabilitata → relay Kerberos → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
