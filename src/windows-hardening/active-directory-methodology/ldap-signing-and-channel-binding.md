# Hardening di LDAP Signing e Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Perché è importante

Gli attacchi LDAP relay/MITM inoltrano l'autenticazione a un domain controller per ottenere un contesto LDAP autenticato. La [panoramica sul poisoning della risoluzione dei nomi e sul relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) illustra il flusso di lavoro più ampio. Due controlli correlati riducono queste possibilità:

- **LDAP channel binding (CBT)** associa l'autenticazione pertinente al certificato TLS del server/canale usato da LDAPS, ostacolando il relay tra canali.
- **LDAP signing** richiede la protezione dell'integrità per i bind LDAP SASL. Non aggiunge riservatezza; usa TLS anche quando è necessario cifrare i contenuti LDAP.<sup>[[2]](#references)</sup>

**Verifica rapida dello stato**: strumenti come `netexec ldap <dc> -u user -p pass` riportano i criteri di signing e channel binding rilevati. `(signing:None)` e `(channel binding:Never)` indicano l'assenza dei controlli, ma il successo di un relay dipende comunque dal tipo di autenticazione acquisita, dal comportamento di EPA, dai privilegi dell'account, dal protocollo di destinazione e dalle protezioni anti-relay. Se il principal inoltrato dispone dei diritti necessari, strumenti come KrbRelayUp possono scrivere `msDS-AllowedToActOnBehalfOfOtherIdentity`, configurare la delega vincolata basata sulle risorse (RBCD) e usare il percorso di delega risultante per impersonare un principal privilegiato.<sup>[[4]](#references)</sup>

I **DC Server 2025** introducono un nuovo GPO (**LDAP server signing requirements Enforcement**) che, se lasciato su **Not Configured**, usa **Require Signing** come valore predefinito. Per evitare l'applicazione del criterio, è necessario impostarlo esplicitamente su **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (solo LDAPS)

- **Requisiti**:
  - La patch CVE-2017-8563 (2017) aggiunge il supporto per Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) aggiunge la telemetria LDAPS CBT “what-if”.<sup>[[2]](#references)</sup>
- **GPO (DC)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (predefinito, nessun CBT)
  - `When Supported` (applicazione parziale: i client compatibili con CBT devono fornire un token valido; i client senza supporto CBT possono comunque eseguire il bind e vengono generati eventi di audit)
  - `Always` (applicazione obbligatoria: rifiuta i bind LDAPS senza un CBT valido)<sup>[[1]](#references)</sup>
- **Audit**: imposta **When Supported** per rilevare:
  - **3074** – Il bind LDAPS non supererebbe la convalida CBT se il criterio fosse applicato.
  - **3075** – Il bind LDAPS non ha fornito i dati CBT e verrebbe rifiutato se il criterio fosse applicato.
  - (L'evento **3039** continua a segnalare gli errori CBT nelle build meno recenti.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Applicazione**: imposta **Always** quando i client LDAPS inviano CBT; è efficace solo su **LDAPS** (non sulla porta 389 non protetta).<sup>[[1]](#references)</sup>

`When Supported` non è una modalità di solo audit: convalida il CBT per i client compatibili, consentendo al contempo i client senza supporto CBT. La [documentazione dei criteri Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) descrive i valori predefiniti che variano in base alla versione. LDAP signing si applica ai bind pertinenti su LDAP/389; channel binding si applica all'autenticazione LDAP protetta da TLS.


## LDAP Signing

- **GPO client**: `Network security: LDAP client signing requirements` = `Require signing` (anziché il valore predefinito `Negotiate signing` nelle versioni moderne di Windows).<sup>[[1]](#references)</sup>
- **GPO DC**:
  - Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (il valore predefinito è `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: lascia il criterio legacy su `None` e imposta `LDAP server signing requirements Enforcement` = `Enabled` (`Not Configured` applica il criterio per impostazione predefinita; impostalo su `Disabled` per evitarlo).<sup>[[1]](#references)</sup>
- **Compatibilità**: fai l'inventario degli appliance e delle applicazioni non Windows che usano bind semplici o bind SASL non firmati. Microsoft documenta il supporto nelle versioni di Windows ancora sottoposte a manutenzione; le dichiarazioni di compatibilità con i client legacy vanno verificate in base allo stack client effettivo, anziché ricondurle a una soglia di versione XP.<sup>[[2]](#references)</sup>

## Percorsi di relay e riautenticazione SASL firmata

Se è richiesto **solo signing**, il relay verso LDAPS può ancora funzionare se il channel binding non è applicato: TLS fornisce l'integrità del trasporto. Se è richiesto **solo il channel binding**, LDAP semplice non dispone di un canale TLS a cui associarsi; un relay può autenticarsi su TCP 389 e poi usare StartTLS per le operazioni che richiedono TLS, purché l'identità inoltrata disponga dei diritti necessari. Applicare entrambi i controlli chiude queste alternative convenzionali, ma non ha impedito la vulnerabilità seguente sui domain controller non aggiornati.<sup>[[5]](#references)</sup>

### Accodare un'operazione LDAP dopo un Bind inoltrato

Sui domain controller Windows Server 2016–2025 vulnerabili, stabilisci prima una **connessione LDAP SASL NTLM firmata** su TCP 389 come identità X, usando credenziali di cui conosci la chiave di sessione (oppure un contesto NTLM SASL anonimo, se accettato). Induci l'identità Y ad autenticarsi **tramite SMB** al relay. Inoltra i messaggi NTLM NEGOTIATE di Y e CHALLENGE del DC tramite richieste GSS-SPNEGO Bind sulla connessione LDAP esistente di X. Il client SMB di Windows imposta `NTLMSSP_NEGOTIATE_SIGN`, quindi il bind LDAP risultante richiede un livello SASL firmato; uno scambio originato da HTTP/WebDAV generalmente non include quel flag e non è intercambiabile in questo caso.<sup>[[5]](#references)</sup>

Quando Y invia NTLM AUTHENTICATE, inserisci **due messaggi LDAP distinti in un unico record SASL preceduto dalla lunghezza**: una BindRequest contenente quella risposta, seguita da una ModifyRequest. Firma l'intero record con la chiave nota di X. Il DC vulnerabile convalida il record usando X, completa il Bind e cambia l'autorizzazione della connessione a Y, quindi esegue la ModifyRequest rimanente come Y senza riconvalidare il record con la chiave di Y. Questo non rivela la password o la chiave di sessione di Y; un record successivo firmato da X non va a buon fine. Una scrittura RBCD su `msDS-AllowedToActOnBehalfOfOtherIdentity` o una scrittura di shadow credential su `msDS-KeyCredentialLink` richiede comunque che Y disponga dell'autorizzazione sull'oggetto di destinazione. Vedi [RBCD](resource-based-constrained-delegation.md), [shadow credentials](acl-persistence-abuse/shadow-credentials.md) e, per un account computer DC inoltrato, [DCSync](dcsync.md).<sup>[[5]](#references)</sup>

È un bypass di **LDAP semplice**, non un bypass del channel binding LDAPS. Su LDAPS, TLS protegge la connessione e Windows non stabilisce il livello di signing SASL NTLM basato sulla chiave di X necessario per questo percorso di accodamento dei record. Se TCP 389 non è disponibile, la tecnica non si trasferisce semplicemente a TCP 636. Gli aggiornamenti di sicurezza di ottobre 2026 impediscono l'operazione nello stesso record scartando i dati rimanenti dopo che il Bind cambia l'identità della connessione.<sup>[[5]](#references)</sup> KB5126646 è l'aggiornamento per Windows Server 2025; le altre versioni Server interessate hanno numeri KB diversi.<sup>[[7]](#references)</sup>

[LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo) del ricercatore integra una versione modificata di `ntlmrelayx.py` per questo flusso di lavoro. Richiede una sorgente di coercion **SMB**, un tree Impacket specifico che esponga le API LDAP signing/security-context (Impacket 0.13.1 su PyPI non è sufficiente) e un account controllato dall'attaccante per il bind iniziale firmato. Per una scrittura RBCD, specifica il DN dell'oggetto vittima e il SID di un computer delegante controllato; usa `-attribute` con `-value` o `-value-hex` per un'altra scrittura consentita. Verifica la lettura di conferma indipendente firmata dello strumento, invece di considerare un messaggio `FAILED` lato relay come prova del fallimento della ModifyRequest.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

Innesca separatamente l'autenticazione SMB; consulta [forzare l'autenticazione NTLM con privilegi](printers-spooler-service-abuse.md) per un vettore di coercizione e la [panoramica del relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) per altri. Il comando e l'implementazione dello strumento sono documentati nel relativo repository.<sup>[[6]](#references)</sup>

## Implementazione graduale basata prima sull'audit (consigliati ~30 giorni)

1. Abilita la diagnostica dell'interfaccia LDAP su ogni DC per registrare i bind non firmati (evento **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Imposta la GPO del DC `LDAP server channel binding token requirements` su **When Supported** per applicare parzialmente il CBT e raccogliere dati di telemetria; verifica prima la compatibilità con i client legacy.<sup>[[1]](#references)</sup>
3. Monitora gli eventi Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – bind senza firma o con firma non obbligatoria (non conformi ai requisiti di firma).
   - **3074/3075** – bind LDAPS che fallirebbero o ometterebbero il CBT (richiede KB4520412 su Windows Server 2019/2022 e il passaggio 2 precedente).
4. Applica le seguenti impostazioni con modifiche separate:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC).
   - `LDAP client signing requirements` = **Require signing** (client).
   - `LDAP server signing requirements` = **Require signing** (DC) **oppure** (Windows Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - Binding del canale LDAP e firma LDAP](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Requisiti di binding del canale LDAP e firma LDAP](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Aggiornamento per la mitigazione del relay LDAP](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (firma LDAP disabilitata → relay Kerberos → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – Firmato, sigillato e inoltrato, in stile NTLM](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [Proof of concept di LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo)
- [7] [Microsoft – Informazioni sulle versioni di Windows Server](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
{{#include ../../banners/hacktricks-training.md}}
