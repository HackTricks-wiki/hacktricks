# Sottrarre la divulgazione di informazioni sensibili dal Web

{{#include ../banners/hacktricks-training.md}}

Se a un certo punto trovi una **pagina Web che presenta informazioni sensibili in base alla tua sessione**: potrebbe riflettere i cookie, oppure stampare dati di pagamento o dettagli CC o qualsiasi altra informazione sensibile, potresti provare a sottrarla.\
Qui presento i principali metodi che puoi provare a utilizzare:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): se riesci ad aggirare gli header CORS, potrai sottrarre le informazioni eseguendo una richiesta Ajax da una pagina dannosa.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): se trovi una vulnerabilità XSS nella pagina, potresti riuscire a sfruttarla per sottrarre le informazioni.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): se non puoi iniettare tag XSS, potresti comunque riuscire a sottrarre le informazioni utilizzando altri normali tag HTML.
- [**Clickjaking**](../pentesting-web/clickjacking.md): se non è presente alcuna protezione contro questo attacco, potresti riuscire a indurre l'utente a inviarti i dati sensibili (un esempio [qui](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).<sup>[[1]](#references)</sup>

## Riferimenti

- [1] [Un servlet di esempio Apache porta alla divulgazione di informazioni](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)

{{#include ../banners/hacktricks-training.md}}
