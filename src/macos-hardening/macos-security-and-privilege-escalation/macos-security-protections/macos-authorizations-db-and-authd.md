# Database delle autorizzazioni di macOS e Authd

{{#include ../../../banners/hacktricks-training.md}}

## Database delle autorizzazioni

I servizi di autorizzazione del Security framework consentono agli helper con privilegi e ad altri componenti di valutare i diritti di autorizzazione denominati. Nelle versioni attuali di macOS, molte di queste regole vengono mantenute in `/var/db/auth.db` e valutate da `authd`; questo file e il relativo schema SQLite sono dettagli di implementazione e possono cambiare tra una release e l'altra.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Storicamente, i valori predefiniti di sistema sono stati inizializzati da `/System/Library/Security/authorization.plist`, mentre gli installer o i servizi con privilegi possono aggiungere diritti denominati. È preferibile utilizzare l'interfaccia supportata `security authorizationdb read|write|remove` invece di modificare direttamente il database.<sup>[[3]](#references)</sup>

La tabella `rules` osservata nella build documentata contiene le colonne seguenti. Considerala una mappa forense, non uno schema pubblico stabile:

- **id**: un identificatore univoco per ogni regola, incrementato automaticamente e utilizzato come chiave primaria.
- **name**: il nome univoco della regola, utilizzato per identificarla e referenziarla all'interno del sistema di autorizzazione.
- **type**: specifica il tipo di regola, limitato ai valori 1 o 2 per definire la relativa logica di autorizzazione.
- **class**: categorizza la regola in una classe specifica, assicurando che sia un intero positivo.
- Le classi comuni delle regole includono `allow`, `deny`, `user`, `rule` e `evaluate-mechanisms`. I meccanismi possono essere integrati nel sistema oppure plug-in di Security Agent in `/System/Library/CoreServices/SecurityAgentPlugins/` o `/Library/Security/SecurityAgentPlugins/`.<sup>[[2]](#references)</sup>
- **group**: indica il gruppo di utenti associato alla regola per l'autorizzazione basata sui gruppi.
- **kofn**: rappresenta il parametro "k-of-n", determinando quante sottoregole devono essere soddisfatte su un numero totale.
- **timeout**: definisce la durata in secondi prima della scadenza dell'autorizzazione concessa dalla regola.
- **flags**: contiene vari flag che modificano il comportamento e le caratteristiche della regola.
- **tries**: limita il numero di tentativi di autorizzazione consentiti per aumentare la sicurezza.
- **version**: tiene traccia della versione della regola per il controllo delle versioni e gli aggiornamenti.
- **created**: registra il timestamp di creazione della regola per finalità di auditing.
- **modified**: memorizza il timestamp dell'ultima modifica apportata alla regola.
- **hash**: contiene un valore hash della regola per garantirne l'integrità e rilevare eventuali manomissioni.
- **identifier**: fornisce un identificatore stringa univoco, ad esempio un UUID, per i riferimenti esterni alla regola.
- **requirement**: contiene dati serializzati che definiscono i requisiti e i meccanismi di autorizzazione specifici della regola.
- **comment**: offre una descrizione o un commento leggibile dall'uomo sulla regola, per documentazione e chiarezza.

### Esempio
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
La seguente regola decodificata illustra `authenticate-admin-nonshared` su una versione documentata di macOS:<sup>[[1]](#references)</sup>
```json
{
"allow-root": "false",
"authenticate-user": "true",
"class": "user",
"comment": "Authenticate as an administrator.",
"group": "admin",
"session-owner": "false",
"shared": "false",
"timeout": "30",
"tries": "10000",
"version": "1"
}
```
## Authd

`authd` è il servizio XPC che valuta le richieste di Authorization Services. Nelle versioni correnti di macOS il relativo bundle può essere esaminato in `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc`; il percorso è un dettaglio di implementazione e può variare tra le diverse release. Le release precedenti scrivevano in `/var/log/authd.log`; quelle correnti utilizzano principalmente il sistema di unified logging, che può essere interrogato con `log show`/`log stream` usando un process predicate per `authd`.<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

Lo strumento `security` espone diverse operazioni di Authorization Services. Un esempio storico invoca `AuthorizationExecuteWithPrivileges` con `security execute-with-privileges /bin/ls`. Apple ha dichiarato obsoleta questa API in macOS 10.7; gli helper privilegiati moderni dovrebbero utilizzare un helper gestito da launchd e l'autorizzazione tramite XPC.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

Nelle release che lo supportano ancora, questo utilizza `/usr/libexec/security_authtrampoline` e mostra una richiesta di autorizzazione prima di eseguire il comando come root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Panoramica dell'Authorization Right di macOS](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Apple Authorization Services Programming Guide (archivio)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [Pagina del manuale macOS `security(1)`](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Daemons and Services Programming Guide: Creazione di job launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Progetto open-source Security di Apple - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)
{{#include ../../../banners/hacktricks-training.md}}
