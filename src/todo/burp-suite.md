# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Tipi di payload di Intruder

Burp Intruder include i seguenti generatori e trasformazioni di payload integrati:<sup>[[1]](#references)</sup>

- **Simple list:** Utilizza un elenco configurato di stringhe come payload.
- **Runtime file:** Legge un payload per riga durante l'esecuzione. È utile per gli elenchi di grandi dimensioni perché Burp non carica l'intero file in memoria.
- **Case modification:** Genera il valore non modificato, le forme in minuscolo e maiuscolo, `Propername` (prima lettera maiuscola e resto minuscolo) oppure `ProperName` (prima lettera maiuscola e caratteri rimanenti invariati). Burp scarta i risultati duplicati.
- **Numbers:** Genera numeri sequenziali o casuali all'interno di un intervallo configurato.
- **Brute forcer:** Genera ogni permutazione per un set di caratteri e una lunghezza minima/massima scelti.

## Estensioni e strumenti complementari

- **Collabfiltrator** genera payload che eseguono comandi ed esfiltrano il relativo output tramite query DNS verso Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** esporta i risultati di Burp per utilizzarli in altri flussi di lavoro di reporting.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** converte le richieste HTTP in script in diversi linguaggi.<sup>[[4]](#references)</sup>

## References

- [1] [Documentazione di PortSwigger - Tipi di payload di Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
