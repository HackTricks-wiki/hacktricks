# Stehlen von sensiblen Informationen durch Offenlegung von einer Webseite

{{#include ../banners/hacktricks-training.md}}

Wenn Sie irgendwann eine **Webseite finden, die Ihnen sensible Informationen basierend auf Ihrer Sitzung präsentiert**: Vielleicht werden Cookies reflektiert, oder Kreditkarteninformationen oder andere sensible Daten angezeigt, könnten Sie versuchen, diese zu stehlen.\
Hier präsentiere ich Ihnen die Hauptmethoden, die Sie versuchen können, um dies zu erreichen:

- [**CORS-Bypass**](../pentesting-web/cors-bypass.md): Wenn Sie die CORS-Header umgehen können, werden Sie in der Lage sein, die Informationen durch eine Ajax-Anfrage an eine bösartige Seite zu stehlen.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): Wenn Sie eine XSS-Schwachstelle auf der Seite finden, könnten Sie in der Lage sein, diese auszunutzen, um die Informationen zu stehlen.
- [**Dangling Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): Wenn Sie keine XSS-Tags injizieren können, könnten Sie dennoch in der Lage sein, die Informationen mit anderen regulären HTML-Tags zu stehlen.
- [**Clickjacking**](../pentesting-web/clickjacking.md): Wenn es keinen Schutz gegen diesen Angriff gibt, könnten Sie den Benutzer dazu bringen, Ihnen die sensiblen Daten zu senden (ein Beispiel [hier](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{{#include ../banners/hacktricks-training.md}}
