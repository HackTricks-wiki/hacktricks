# Altri trucchi Web

{{#include ../banners/hacktricks-training.md}}

### Host header

In diversi casi il back-end si fida dell'**Host header** per eseguire alcune azioni. Ad esempio, potrebbe utilizzare il suo valore come **dominio a cui inviare il reset della password**. Quindi, quando ricevi un'email con un link per reimpostare la password, il dominio utilizzato è quello inserito nell'Host header. Dopodiché, puoi richiedere il reset della password di altri utenti e modificare il dominio impostandone uno sotto il tuo controllo per rubare i loro codici di reset della password. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Nota che potresti non dover nemmeno aspettare che l'utente faccia clic sul link di reset della password per ottenere il token, poiché potrebbe essere sufficiente che **i filtri antispam o altri dispositivi/bot intermedi facciano clic su di esso per analizzarlo**.

### Booleani della sessione

A volte, quando completi correttamente una verifica, il back-end **aggiunge semplicemente un booleano con valore "True" a un attributo di sicurezza della tua sessione**. In seguito, un endpoint diverso saprà se hai superato correttamente tale controllo.\
Tuttavia, se **superi il controllo** e alla tua sessione viene assegnato quel valore "True" nell'attributo di sicurezza, puoi provare ad **accedere ad altre risorse** che **dipendono dallo stesso attributo**, ma alle quali **non dovresti avere i permessi** di accesso. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Funzionalità di registrazione

Prova a registrarti come un utente già esistente. Prova anche a utilizzare caratteri equivalenti (punti, molti spazi e Unicode).

### Email per il takeover

Registra un'email, quindi, prima di confermarla, modifica l'email; se la nuova email di conferma viene inviata alla prima email registrata, puoi effettuare il takeover di qualsiasi email. Oppure, se puoi abilitare la seconda email confermando la prima, puoi anche effettuare il takeover di qualsiasi account.

### Accesso al servicedesk interno delle aziende che utilizzano atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### Metodo TRACE

Gli sviluppatori potrebbero dimenticare di disabilitare diverse opzioni di debug nell'ambiente di produzione. Ad esempio, il metodo HTTP `TRACE` è progettato per scopi diagnostici. Se abilitato, il web server risponderà alle richieste che utilizzano il metodo `TRACE` restituendo nella risposta la richiesta esatta ricevuta. Questo comportamento è spesso innocuo, ma occasionalmente porta alla divulgazione di informazioni, come il nome degli header di autenticazione interni che possono essere aggiunti alle richieste dai reverse proxy.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## Riferimenti

- [1] [How I was able to take over any user's account with Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
