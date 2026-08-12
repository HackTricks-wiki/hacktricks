# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione

Per informazioni di base sulla tecnologia iButton, consulta:

{{#ref}}
../ibutton.md
{{#endref}}

## Progettazione

Nell'immagine seguente, l'area **blu** mostra come posizionare un iButton fisico sui contatti del Flipper Zero per la lettura. L'area **verde** mostra quali contatti devono toccare un lettore durante l'emulazione.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Azioni

### Lettura

In modalità Lettura, il Flipper Zero attende che una chiave tocchi i suoi contatti, rileva il protocollo e visualizza il protocollo sopra l'ID della chiave. L'applicazione integrata supporta le chiavi di controllo accessi Dallas, Cyfral e Metakom.<sup>[[2]](#references)</sup>

### Aggiungi manualmente

Puoi inserire manualmente i dati delle chiavi per i protocolli Dallas, Cyfral e Metakom.<sup>[[2]](#references)</sup>

### Emula

Puoi emulare una chiave salvata, sia che sia stata letta da una chiave fisica sia che sia stata inserita manualmente.<sup>[[2]](#references)</sup>

> [!TIP]
> Se i contatti integrati non riescono a raggiungere il lettore, collega i contatti dati e massa tramite i pin GPIO.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Gestire le chiavi iButton con Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Documentazione di Flipper Zero - Lettura delle chiavi iButton](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}
