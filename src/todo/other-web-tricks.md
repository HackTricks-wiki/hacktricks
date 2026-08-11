# Altri trucchi web

{{#include ../banners/hacktricks-training.md}}

## Host header

I back end a volte si fidano del campo HTTP `Host` quando costruiscono link assoluti. Se un'email di reimpostazione della password utilizza un host fornito dall'attaccante, richiedere un reset per una vittima può inviare un link contenente il token attraverso un dominio controllato dall'attaccante. Verifica anche i campi forwarded-host, la gestione di Host duplicati e i target delle richieste in formato assoluto a ogni passaggio attraverso i proxy.<sup>[[1]](#references)</sup>

> [!WARNING]
> Il clic dell'utente potrebbe non essere necessario: **gli scanner di sicurezza delle email, i servizi di anteprima o altri intermediari possono richiedere automaticamente il link controllato dall'attaccante**, divulgando il token di reset.

## Booleani di sessione

Alcune applicazioni registrano una verifica completata come valore booleano nella sessione, quindi consentono a un endpoint diverso di basarsi su quel flag. Dopo aver superato legittimamente il controllo per una risorsa, verifica se lo stesso flag autorizza erroneamente un utente, un oggetto o un workflow diverso. Si tratta di una vulnerabilità di autorizzazione/riutilizzo dello stato di secondo ordine, non semplicemente di un IDOR.<sup>[[2]](#references)</sup>

## Funzionalità di registrazione

Prova a registrarti come un utente già esistente. Prova anche a utilizzare caratteri equivalenti (punti, molti spazi e Unicode).

## Confusione dello stato durante il cambio email

Registra un indirizzo email e modificalo prima di confermarlo. Verifica se la conferma per il nuovo indirizzo viene inviata al vecchio indirizzo o se la conferma del vecchio token attiva il nuovo indirizzo. I token di conferma devono essere associati all'account esatto, all'indirizzo in attesa, allo scopo e allo stato corrente.

## Service desk Atlassian esposti


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

## Metodo TRACE

Il metodo HTTP `TRACE` richiede una restituzione della richiesta ricevuta per scopi diagnostici. L'RFC 9110 impone ai destinatari di omettere dal contenuto riflesso i campi sensibili, come credenziali e cookie, ma implementazioni non sicure o header aggiunti dagli intermediari possono comunque divulgare trasformazioni interne della richiesta. I browser impediscono le richieste TRACE generate dagli script, quindi il cross-site tracing storico dipende anche da un metodo separato per iniettare campi protetti.<sup>[[3]](#references)</sup>![Immagine che mostra una risposta TRACE](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Immagine per il post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [Come sono riuscito a prendere il controllo dell'account di qualsiasi utente con l'iniezione dell'header Host](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [Un vettore d'attacco meno noto: attacchi IDOR di secondo ordine](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)
- [3] [RFC 9110, sezione 9.3.8 — TRACE](https://www.rfc-editor.org/rfc/rfc9110.html#name-trace)
{{#include ../banners/hacktricks-training.md}}
