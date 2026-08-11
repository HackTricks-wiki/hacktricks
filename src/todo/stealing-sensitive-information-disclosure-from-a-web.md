# Sensible Informationen von einer Web Page stehlen

{{#include ../banners/hacktricks-training.md}}

Wenn eine **Web Page sensible Informationen basierend auf der aktuellen Session anzeigt**—etwa Cookies, Account-Daten oder Kreditkartendetails—kann ein Angreifer versuchen, diese zu exfiltrieren. Zu den wichtigsten Techniken gehören:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): Eine CORS-Fehlkonfiguration kann es einem bösartigen Origin ermöglichen, sensible Responses über Cross-Origin-Requests zu lesen.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): Eine XSS-Schwachstelle im Target-Origin kann es eingeschleustem JavaScript ermöglichen, die Informationen zu lesen und zu exfiltrieren.
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): Wenn eine Script-Injection nicht verfügbar ist, können eingeschleuste HTML-Elemente dennoch sensible Inhalte erfassen.
- [**Clickjacking**](../pentesting-web/clickjacking.md): Wenn Framing-Schutzmaßnahmen fehlen, kann ein Angreifer einen Benutzer dazu bringen, mit der sensiblen Web Page zu interagieren. Die verlinkte Fallstudie demonstriert diese Technik.<sup>[[1]](#references)</sup>

## References

- [1] [Apache-Beispiel-Servlet führt zur Offenlegung von Informationen](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)
{{#include ../banners/hacktricks-training.md}}
