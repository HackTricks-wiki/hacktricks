# Crypto CTF - Varie

{{#include ../../banners/hacktricks-training.md}}

Questa sezione raccoglie tecniche presenti nelle challenge di crittografia che non rientrano facilmente nelle altre categorie.

## Linguaggi esoterici

### Tecnica

Usa questo flusso di lavoro quando una challenge richiede di eseguire un programma scritto in un linguaggio esoterico e decodificarne l'output.

Se una challenge ti fornisce codice che non sembra appartenere a un linguaggio standard:

- Identifica il linguaggio cercando un token o una sequenza di istruzioni distintivi.
- Usa un interprete online o un'immagine Docker.
- Se l'output è insolito, cerca eventuali livelli di codifica o compressione applicati dopo l'esecuzione.

Un utile indice di linguaggi è la wiki Esolang.<sup>[[1]](#references)</sup> Per i normali livelli di codifica e compressione, usa il [flusso di lavoro Crypto CTF](../ctf-workflow/). Se l'indizio è testo invisibile anziché sintassi eseguibile, consulta la [steganografia testuale](../../stego/text/).

### Esfiltrare lo stato preimpostato di un interprete

Se una challenge accetta codice sorgente in un linguaggio esoterico e lo esegue in un **interprete personalizzato**, esamina la memoria iniziale, lo stack e le istruzioni di output prima di considerare il codice sorgente un rompicapo di decodifica. Quando l'interprete precarica un segreto sullo stack di Befunge, un programma breve può estrarre e stampare i byte già presenti senza calcolarli. Questo richiede il controllo del codice sorgente eseguito e un opcode di output; non funziona con un normale interprete vuoto. In una challenge di Befunge, il codice qui sotto ha emesso ripetutamente caratteri di una flag precaricata sullo stack in ordine inverso.<sup>[[2]](#references)[[3]](#references)</sup>

```befunge
>,<
```

`>` avvia l'esecuzione verso destra, `,` estrae e stampa un carattere, e `<` rimanda il puntatore alle istruzioni a `,`. Verifica il comportamento dell'interprete personalizzato in caso di underflow e al raggiungimento del limite di istruzioni: l'implementazione citata si ferma quando lo stack è esaurito o dopo 1.024 istruzioni. Se il segreto non si trova direttamente sullo stack, esamina gli altri stati inizializzati e le istruzioni di output/lettura disponibili, invece di dare per scontata la semantica standard di Befunge.<sup>[[3]](#references)[[4]](#references)</sup>



## References

- [1] [Esolang, il wiki dei linguaggi di programmazione esoterici](https://esolangs.org/wiki/Main_Page)
- [2] [Writeup originale di WolvCTF 2024 Befuddled1](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/README.md)
- [3] [Codice sorgente dell'interprete di WolvCTF 2024 Befuddled1](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/befunge.py)
- [4] [Riferimento al linguaggio Befunge](https://esolangs.org/wiki/Befunge)
{{#include ../../banners/hacktricks-training.md}}
