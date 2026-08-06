# Sensible Informationen aus einer Webanwendung stehlen

{{#include ../banners/hacktricks-training.md}}

Wenn du irgendwann eine **Webseite findest, die dir basierend auf deiner Session sensible Informationen anzeigt**: Vielleicht spiegelt sie Cookies wider oder gibt Kreditkartendaten oder andere sensible Informationen aus, kannst du versuchen, diese zu stehlen.\
Hier stelle ich die wichtigsten Möglichkeiten vor, mit denen du dies versuchen kannst:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): Wenn du CORS-Header umgehen kannst, kannst du die Informationen stehlen, indem du Ajax-Anfragen von einer bösartigen Seite ausführst.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): Wenn du eine XSS-Schwachstelle auf der Seite findest, kannst du sie möglicherweise ausnutzen, um die Informationen zu stehlen.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): Wenn du keine XSS-Tags injizieren kannst, kannst du die Informationen möglicherweise trotzdem mithilfe anderer regulärer HTML-Tags stehlen.
- [**Clickjaking**](../pentesting-web/clickjacking.md): Wenn kein Schutz gegen diesen Angriff vorhanden ist, kannst du den Benutzer möglicherweise dazu bringen, dir die sensiblen Daten zu senden (ein Beispiel findest du [hier](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).<sup>[[1]](#references)</sup>

## Referenzen

- [1] [Apache example servlet leads to Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)

{{#include ../banners/hacktricks-training.md}}
