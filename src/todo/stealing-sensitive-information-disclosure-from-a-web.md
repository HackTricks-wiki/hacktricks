# Sottrarre informazioni sensibili da una pagina web

{{#include ../banners/hacktricks-training.md}}

Se una **pagina web visualizza informazioni sensibili in base alla sessione corrente**—come cookie, dati dell'account o dati della carta di credito—un attacker potrebbe tentare di esfiltrarle. Le tecniche principali includono:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): una configurazione errata di CORS potrebbe consentire a un'origine malevola di leggere risposte sensibili tramite richieste cross-origin.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): una vulnerabilità XSS nell'origine target potrebbe consentire al JavaScript iniettato di leggere ed esfiltrare le informazioni.
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): quando l'iniezione di script non è disponibile, gli elementi HTML iniettati potrebbero comunque catturare contenuti sensibili.
- [**Clickjacking**](../pentesting-web/clickjacking.md): se le protezioni contro il framing sono assenti, un attacker potrebbe indurre un utente a interagire con la pagina sensibile. Il case study collegato dimostra questa tecnica.<sup>[[1]](#references)</sup>

## References

- [1] [Apache example servlet porta alla divulgazione di informazioni](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)
{{#include ../banners/hacktricks-training.md}}
