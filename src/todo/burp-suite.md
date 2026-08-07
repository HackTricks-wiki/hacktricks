# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Payload di base

- **Lista semplice:** Solo una lista contenente una voce per ogni riga
- **Runtime File:** Una lista letta durante il runtime (non caricata in memoria), utile per supportare liste di grandi dimensioni.
- **Modifica delle maiuscole/minuscole:** Applica alcune modifiche a una lista di stringhe (nessuna modifica, tutto in minuscolo, tutto in MAIUSCOLO, nome proprio - prima lettera maiuscola e il resto minuscolo-, Nome proprio -prima lettera maiuscola e il resto invariato-.
- **Numeri:** Genera numeri da X a Y usando un intervallo di Z oppure in modo casuale.
- **Brute Forcer:** Set di caratteri, lunghezza minima e massima.

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : Payload per eseguire comandi e recuperare l'output tramite richieste DNS a burpcollab.

{{#ref}}
https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e
{{#endref}}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

{{#include ../banners/hacktricks-training.md}}
