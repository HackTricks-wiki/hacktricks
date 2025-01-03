# Furto di Informazioni Sensibili da un Web

{{#include ./banners/hacktricks-training.md}}

Se a un certo punto trovi una **pagina web che ti presenta informazioni sensibili basate sulla tua sessione**: Potrebbe riflettere cookie, stampare dettagli della carta di credito o qualsiasi altra informazione sensibile, potresti provare a rubarla.\
Qui ti presento i principali modi per cercare di ottenerla:

- [**CORS bypass**](pentesting-web/cors-bypass.md): Se riesci a bypassare le intestazioni CORS, sarai in grado di rubare le informazioni effettuando una richiesta Ajax per una pagina malevola.
- [**XSS**](pentesting-web/xss-cross-site-scripting/): Se trovi una vulnerabilità XSS sulla pagina, potresti essere in grado di abusarne per rubare le informazioni.
- [**Danging Markup**](pentesting-web/dangling-markup-html-scriptless-injection/): Se non puoi iniettare tag XSS, potresti comunque essere in grado di rubare le informazioni utilizzando altri tag HTML regolari.
- [**Clickjaking**](pentesting-web/clickjacking.md): Se non c'è protezione contro questo attacco, potresti essere in grado di ingannare l'utente per inviarti i dati sensibili (un esempio [qui](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{{#include ./banners/hacktricks-training.md}}
