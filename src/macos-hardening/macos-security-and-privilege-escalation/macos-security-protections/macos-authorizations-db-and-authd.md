# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Athorizarions DB**

Il database situato in `/var/db/auth.db` è un database utilizzato per memorizzare i permessi per eseguire operazioni sensibili. Queste operazioni vengono eseguite completamente nello **spazio utente** e sono solitamente utilizzate dai **servizi XPC** che devono verificare **se il client chiamante è autorizzato** a eseguire determinate azioni controllando questo database.

Inizialmente, questo database viene creato dal contenuto di `/System/Library/Security/authorization.plist`. Successivamente, alcuni servizi potrebbero aggiungere o modificare questo database per aggiungere altri permessi.

Le regole sono memorizzate nella tabella `rules` all'interno del database e contengono le seguenti colonne:

- **id**: Un identificatore unico per ogni regola, automaticamente incrementato e che funge da chiave primaria.
- **name**: Il nome unico della regola utilizzato per identificarla e fare riferimento ad essa all'interno del sistema di autorizzazione.
- **type**: Specifica il tipo di regola, limitato ai valori 1 o 2 per definire la sua logica di autorizzazione.
- **class**: Categorizza la regola in una classe specifica, assicurandosi che sia un intero positivo.
- "allow" per consentire, "deny" per negare, "user" se la proprietà del gruppo indica un gruppo di cui l'appartenenza consente l'accesso, "rule" indica in un array una regola da soddisfare, "evaluate-mechanisms" seguito da un array `mechanisms` che sono o builtins o un nome di un bundle all'interno di `/System/Library/CoreServices/SecurityAgentPlugins/` o /Library/Security//SecurityAgentPlugins
- **group**: Indica il gruppo utente associato alla regola per l'autorizzazione basata su gruppi.
- **kofn**: Rappresenta il parametro "k-of-n", determinando quanti subregole devono essere soddisfatte su un numero totale.
- **timeout**: Definisce la durata in secondi prima che l'autorizzazione concessa dalla regola scada.
- **flags**: Contiene vari flag che modificano il comportamento e le caratteristiche della regola.
- **tries**: Limita il numero di tentativi di autorizzazione consentiti per migliorare la sicurezza.
- **version**: Tiene traccia della versione della regola per il controllo delle versioni e gli aggiornamenti.
- **created**: Registra il timestamp quando la regola è stata creata per scopi di auditing.
- **modified**: Memorizza il timestamp dell'ultima modifica apportata alla regola.
- **hash**: Contiene un valore hash della regola per garantire la sua integrità e rilevare manomissioni.
- **identifier**: Fornisce un identificatore stringa unico, come un UUID, per riferimenti esterni alla regola.
- **requirement**: Contiene dati serializzati che definiscono i requisiti specifici di autorizzazione e i meccanismi della regola.
- **comment**: Offre una descrizione o un commento leggibile dall'uomo sulla regola per documentazione e chiarezza.

### Example
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
Inoltre, in [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) è possibile vedere il significato di `authenticate-admin-nonshared`:
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

È un demone che riceverà richieste per autorizzare i client a eseguire azioni sensibili. Funziona come un servizio XPC definito all'interno della cartella `XPCServices/` e utilizza per scrivere i suoi log in `/var/log/authd.log`.

Inoltre, utilizzando lo strumento di sicurezza, è possibile testare molte API di `Security.framework`. Ad esempio, `AuthorizationExecuteWithPrivileges` eseguendo: `security execute-with-privileges /bin/ls`

Questo fork e exec `/usr/libexec/security_authtrampoline /bin/ls` come root, che chiederà permessi in un prompt per eseguire ls come root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

{{#include ../../../banners/hacktricks-training.md}}
