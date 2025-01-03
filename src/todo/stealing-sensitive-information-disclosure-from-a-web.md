# Stehlen von sensiblen Informationen durch Offenlegung von einer Webseite

{{#include ../banners/hacktricks-training.md}}

Wenn Sie irgendwann eine **Webseite finden, die Ihnen basierend auf Ihrer Sitzung sensible Informationen präsentiert**: Vielleicht spiegelt sie Cookies wider, oder druckt Kreditkarteninformationen oder andere sensible Daten aus, könnten Sie versuchen, diese zu stehlen.\
Hier präsentiere ich Ihnen die Hauptmethoden, die Sie versuchen können, um dies zu erreichen:

- [**CORS-Umgehung**](../pentesting-web/cors-bypass.md): Wenn Sie CORS-Header umgehen können, werden Sie in der Lage sein, die Informationen durch eine Ajax-Anfrage an eine bösartige Seite zu stehlen.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/): Wenn Sie eine XSS-Sicherheitsanfälligkeit auf der Seite finden, könnten Sie in der Lage sein, diese auszunutzen, um die Informationen zu stehlen.
- [**Dangling Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): Wenn Sie keine XSS-Tags injizieren können, könnten Sie dennoch in der Lage sein, die Informationen mit anderen regulären HTML-Tags zu stehlen.
- [**Clickjacking**](../pentesting-web/clickjacking.md): Wenn es keinen Schutz gegen diesen Angriff gibt, könnten Sie den Benutzer dazu bringen, Ihnen die sensiblen Daten zu senden (ein Beispiel [hier](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{{#include ../banners/hacktricks-training.md}}
