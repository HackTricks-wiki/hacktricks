# Altri trucchi Web

{{#include ../banners/hacktricks-training.md}}

### Host header

Diverse volte il back-end si fida dell'**Host header** per eseguire alcune azioni. Ad esempio, potrebbe usare il suo valore come **dominio a cui inviare un password reset**. Quindi, quando ricevi un'email con un link per reimpostare la password, il dominio utilizzato è quello inserito nell'Host header.Then, puoi richiedere il password reset di altri utenti e modificare il dominio impostandone uno controllato da te per rubare i loro codici di password reset. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Nota che potresti non dover nemmeno aspettare che l'utente faccia clic sul link per reimpostare la password per ottenere il token, poiché è possibile che persino **i filtri antispam o altri dispositivi/bot intermedi facciano clic sul link per analizzarlo**.

### Booleani di sessione

A volte, quando completi correttamente una verifica, il back-end **aggiunge semplicemente un booleano con valore "True" a un attributo di sicurezza della tua sessione**. In seguito, un endpoint diverso saprà se hai superato correttamente il controllo.\
Tuttavia, se **superi il controllo** e alla tua sessione viene assegnato il valore "True" nell'attributo di sicurezza, puoi provare ad **accedere ad altre risorse** che **dipendono dallo stesso attributo**, ma alle quali **non dovresti avere i permessi** di accesso. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Funzionalità di registrazione

Prova a registrarti come un utente già esistente. Prova anche a usare caratteri equivalenti (punti, molti spazi e Unicode).

### Email per il takeover

Registra un'email, poi, prima di confermarla, modifica l'email; quindi, se la nuova email di conferma viene inviata al primo indirizzo email registrato, puoi effettuare il takeover di qualsiasi email. Oppure, se puoi abilitare la seconda email confermando la prima, puoi anche effettuare il takeover di qualsiasi account.

### Accesso al servicedesk interno delle aziende usando atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### Metodo TRACE

Gli sviluppatori potrebbero dimenticare di disabilitare varie opzioni di debug nell'ambiente di produzione. Ad esempio, il metodo HTTP `TRACE` è progettato per scopi diagnostici. Se abilitato, il web server risponderà alle richieste che utilizzano il metodo `TRACE` ripetendo nella risposta la richiesta esatta ricevuta. Questo comportamento è spesso innocuo, ma occasionalmente porta alla divulgazione di informazioni, come il nome degli header di autenticazione interni che potrebbero essere aggiunti alle richieste dai reverse proxy.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## Riferimenti

- [1] [How I was able to take over any user's account with Host Header injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
