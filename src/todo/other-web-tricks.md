# Altri trucchi web

{{#include ../banners/hacktricks-training.md}}

### Intestazione Host

Diverse volte il back-end si fida dell'**intestazione Host** per eseguire alcune azioni. Ad esempio, potrebbe utilizzare il suo valore come **dominio per inviare un ripristino della password**. Quindi, quando ricevi un'email con un link per ripristinare la tua password, il dominio utilizzato è quello che hai inserito nell'intestazione Host. Poi, puoi richiedere il ripristino della password di altri utenti e cambiare il dominio in uno controllato da te per rubare i loro codici di ripristino della password. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

> [!WARNING]
> Nota che è possibile che non sia nemmeno necessario aspettare che l'utente clicchi sul link per ripristinare la password per ottenere il token, poiché anche **i filtri antispam o altri dispositivi/bot intermedi potrebbero cliccarci sopra per analizzarlo**.

### Booleani di sessione

A volte, quando completi correttamente alcune verifiche, il back-end **aggiunge semplicemente un booleano con il valore "True" a un attributo di sicurezza della tua sessione**. Poi, un endpoint diverso saprà se hai superato con successo quel controllo.\
Tuttavia, se **superi il controllo** e alla tua sessione viene concesso quel valore "True" nell'attributo di sicurezza, puoi provare ad **accedere ad altre risorse** che **dipendono dallo stesso attributo** ma a cui **non dovresti avere permessi** di accesso. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funzionalità di registrazione

Prova a registrarti come un utente già esistente. Prova anche a utilizzare caratteri equivalenti (punti, molti spazi e Unicode).

### Prendere il controllo delle email

Registrati con un'email, prima di confermarla cambia l'email, poi, se la nuova email di conferma viene inviata alla prima email registrata, puoi prendere il controllo di qualsiasi email. Oppure, se puoi abilitare la seconda email confermando la prima, puoi anche prendere il controllo di qualsiasi account.

### Accesso al servicedesk interno delle aziende che utilizzano Atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Metodo TRACE

Gli sviluppatori potrebbero dimenticare di disabilitare varie opzioni di debug nell'ambiente di produzione. Ad esempio, il metodo HTTP `TRACE` è progettato per scopi diagnostici. Se abilitato, il server web risponderà alle richieste che utilizzano il metodo `TRACE` restituendo nella risposta la richiesta esatta che è stata ricevuta. Questo comportamento è spesso innocuo, ma occasionalmente porta a divulgazione di informazioni, come il nome delle intestazioni di autenticazione interne che potrebbero essere aggiunte alle richieste da proxy inversi.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

{{#include ../banners/hacktricks-training.md}}
