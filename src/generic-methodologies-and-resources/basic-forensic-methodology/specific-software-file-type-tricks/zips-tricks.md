# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**Strumenti da riga di comando** per gestire **file zip** sono essenziali per diagnosticare, riparare e decifrare file zip. Ecco alcune utilità chiave:

- **`unzip`**: Rivela perché un file zip potrebbe non decomprimersi.
- **`zipdetails -v`**: Offre un'analisi dettagliata dei campi del formato del file zip.
- **`zipinfo`**: Elenca i contenuti di un file zip senza estrarli.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Tentano di riparare file zip corrotti.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uno strumento per il cracking a forza bruta delle password zip, efficace per password fino a circa 7 caratteri.

La [specifica del formato del file Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornisce dettagli completi sulla struttura e sugli standard dei file zip.

È cruciale notare che i file zip protetti da password **non criptano i nomi dei file o le dimensioni dei file** al loro interno, un difetto di sicurezza non condiviso con i file RAR o 7z che criptano queste informazioni. Inoltre, i file zip criptati con il metodo ZipCrypto più vecchio sono vulnerabili a un **attacco in chiaro** se è disponibile una copia non criptata di un file compresso. Questo attacco sfrutta il contenuto noto per decifrare la password del zip, una vulnerabilità dettagliata nell'[articolo di HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) e ulteriormente spiegata in [questo documento accademico](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Tuttavia, i file zip protetti con crittografia **AES-256** sono immuni a questo attacco in chiaro, dimostrando l'importanza di scegliere metodi di crittografia sicuri per dati sensibili.

## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

{{#include ../../../banners/hacktricks-training.md}}
