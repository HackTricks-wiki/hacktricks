# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Tipi di payload di Intruder

- **Simple list:** Usa un elenco configurato di stringhe come payload.
- **Runtime file:** Legge un payload per riga durante l'esecuzione. È utile per gli elenchi di grandi dimensioni perché Burp non carica l'intero file in memoria.
- **Case modification:** Modifica la capitalizzazione di una stringa di input, ad esempio convertendola in minuscolo, maiuscolo, formato frase o formato titolo.
- **Numbers:** Genera numeri sequenziali o casuali all'interno di un intervallo configurato.
- **Brute forcer:** Genera ogni permutazione per un set di caratteri e una lunghezza minima/massima scelti.<sup>[[1]](#references)</sup>

## Estensioni e strumenti complementari

- **Collabfiltrator** genera payload che eseguono comandi ed esfiltrano il relativo output tramite query DNS verso Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** esporta i risultati di Burp per utilizzarli in altri workflow di reporting.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** converte le richieste HTTP in script scritti in diversi linguaggi.<sup>[[4]](#references)</sup>

## References

- [1] [Documentazione di PortSwigger - tipi di payload di Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
