# Ricerca Ampia del Codice Sorgente

{{#include ../../banners/hacktricks-training.md}}

L'obiettivo di questa pagina è enumerare **le piattaforme che consentono di cercare codice** (letterale o regex) in migliaia/milioni di repo su una o più piattaforme.

Questo aiuta in diverse occasioni a **cercare informazioni trapelate** o per **modelli di vulnerabilità**.

- [**Sourcebot**](https://www.sourcebot.dev/): Strumento di ricerca del codice sorgente open source. Indicizza e cerca tra migliaia dei tuoi repo attraverso un'interfaccia web moderna.
- [**SourceGraph**](https://sourcegraph.com/search): Cerca in milioni di repo. Esiste una versione gratuita e una versione enterprise (con 15 giorni gratuiti). Supporta le regex.
- [**Github Search**](https://github.com/search): Cerca su Github. Supporta le regex.
- Forse è anche utile controllare [**Github Code Search**](https://cs.github.com/).
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): Cerca tra i progetti di Gitlab. Supporta le regex.
- [**SearchCode**](https://searchcode.com/): Cerca codice in milioni di progetti.

> [!WARNING]
> Quando cerchi perdite in un repo e esegui qualcosa come `git log -p`, non dimenticare che potrebbero esserci **altre branche con altri commit** contenenti segreti!

{{#include ../../banners/hacktricks-training.md}}
