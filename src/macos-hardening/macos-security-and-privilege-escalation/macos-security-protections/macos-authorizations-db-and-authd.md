# DB delle autorizzazioni di macOS e Authd

{{#include ../../../banners/hacktricks-training.md}}

## **DB delle autorizzazioni**

Il database situato in `/var/db/auth.db` viene utilizzato per memorizzare i permessi necessari a eseguire operazioni sensibili. Queste operazioni vengono eseguite completamente nello **user space** e sono solitamente utilizzate dai servizi **XPC**, che devono verificare **se il client chiamante è autorizzato** a eseguire una determinata azione consultando questo database.

Inizialmente, questo database viene creato a partire dal contenuto di `/System/Library/Security/authorization.plist`. In seguito, alcuni servizi potrebbero aggiungere o modificare questo database per includere altri permessi.

Le regole sono memorizzate nella tabella `rules` del database e contengono le seguenti colonne:

- **id**: Un identificatore univoco per ogni regola, incrementato automaticamente e utilizzato come chiave primaria.
- **name**: Il nome univoco della regola, utilizzato per identificarla e farvi riferimento all'interno del sistema di autorizzazione.
- **type**: Specifica il tipo di regola, limitato ai valori 1 o 2 per definire la relativa logica di autorizzazione.
- **class**: Classifica la regola in una classe specifica, assicurandosi che sia un intero positivo.
- "allow" per consentire, "deny" per negare, "user" se la proprietà group indica un gruppo la cui appartenenza consente l'accesso, "rule" indica in un array una regola da soddisfare, "evaluate-mechanisms" seguito da un array `mechanisms` che contiene builtins oppure il nome di un bundle all'interno di `/System/Library/CoreServices/SecurityAgentPlugins/` o `/Library/Security//SecurityAgentPlugins`
- **group**: Indica il gruppo di utenti associato alla regola per l'autorizzazione basata sui gruppi.
- **kofn**: Rappresenta il parametro "k-of-n", determinando quante sottoregole devono essere soddisfatte su un numero totale.
- **timeout**: Definisce la durata, in secondi, prima della scadenza dell'autorizzazione concessa dalla regola.
- **flags**: Contiene vari flag che modificano il comportamento e le caratteristiche della regola.
- **tries**: Limita il numero di tentativi di autorizzazione consentiti per aumentare la sicurezza.
- **version**: Tiene traccia della versione della regola per il controllo delle versioni e gli aggiornamenti.
- **created**: Registra il timestamp di creazione della regola per scopi di auditing.
- **modified**: Memorizza il timestamp dell'ultima modifica apportata alla regola.
- **hash**: Contiene un valore hash della regola per garantirne l'integrità e rilevare eventuali manomissioni.
- **identifier**: Fornisce un identificatore stringa univoco, come un UUID, per riferimenti esterni alla regola.
- **requirement**: Contiene dati serializzati che definiscono i requisiti e i meccanismi specifici di autorizzazione della regola.
- **comment**: Offre una descrizione o un commento leggibile dall'utente sulla regola, per documentazione e chiarezza.

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
Inoltre, in [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) è possibile vedere il significato di `authenticate-admin-nonshared`:<sup>[[1]](#references)</sup>
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

È un daemon che riceve richieste per autorizzare i client a eseguire azioni sensibili. Funziona come un servizio XPC definito all'interno della cartella `XPCServices/` e utilizza `/var/log/authd.log` per scrivere i propri log.

Inoltre, utilizzando il security tool, è possibile testare molte API di `Security.framework`. Ad esempio, eseguire `AuthorizationExecuteWithPrivileges`: `security execute-with-privileges /bin/ls`

Questo eseguirà il fork e l'exec di `/usr/libexec/security_authtrampoline /bin/ls` come root, chiedendo tramite un prompt l'autorizzazione per eseguire ls come root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## Riferimenti

- [1] [authenticate-admin-nonshared - Panoramica dell'Authorization Right di macOS](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
