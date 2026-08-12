# Numero di serie di macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

Non presumere che ogni Mac abbia un numero di serie decodificabile di 12 caratteri. Il vecchio formato di Apple codificava informazioni sulla produzione e sulla configurazione, ma Apple ha iniziato a introdurre numeri di serie randomizzati con i nuovi prodotti nel 2021. Il formato randomizzato non espone dettagli sulla produzione o sulla configurazione.<sup>[[1]](#references)</sup>

### Formato legacy a 12 caratteri

Per molti dispositivi prodotti dal 2010 fino alla transizione al formato randomizzato, il formato a 12 caratteri può ancora fornire indicazioni utili sull'inventario:<sup>[[3]](#references)</sup>

- I caratteri 1–3 identificano il luogo di produzione.
- I caratteri 4–5 codificano il semestre e la settimana di produzione.
- I caratteri 6–8 distinguono le unità prodotte nello stesso luogo e nello stesso periodo.
- I caratteri 9–12 identificano il modello o il codice di configurazione.

Ad esempio, `C02L13ECF8J2` segue questa struttura legacy. Le mappature delle fabbriche gestite dalla community includono prefissi come `FC`, `F`, `XA`, `XB`, `QP` e `G8` per località negli Stati Uniti; `RN` per il Messico; `CK` per Cork; `VM` per una sede Foxconn nella Repubblica Ceca; `SG` o `E` per Singapore; `MB` per la Malaysia; `PT` o `CY` per la Corea; e `EE`, `QT` o `UV` per Taiwan. Numerosi prefissi, tra cui `FK`, `F1`, `F2`, `W8`, `DL`, `DM`, `DN`, `YM`, `7J`, `1C`, `4H`, `WQ`, `F7`, `C0`, `C3` e `C7`, sono stati associati a stabilimenti cinesi; `RM` è stato associato a dispositivi ricondizionati.<sup>[[3]](#references)</sup>

I codici data del quarto carattere vanno da `C` (prima metà del 2010) a `Z` (seconda metà del 2019), dopodiché la sequenza viene riutilizzata. Per il quinto carattere, le cifre `1`–`9` rappresentano le settimane 1–9, mentre le lettere `C`–`Y`, escluse le vocali e `S`, rappresentano le settimane 10–27; aggiungi 26 quando il quarto carattere indica la seconda metà di un anno.<sup>[[3]](#references)</sup>

Queste mappature sono utili per il triage dei dispositivi legacy, ma non costituiscono una prova autorevole dell'origine, dell'età o dell'autenticità. Conferma il risultato tramite i dati di inventario di Apple.

Per un'identificazione affidabile, recupera il numero di serie dal dispositivo e utilizza la verifica della copertura o delle specifiche tecniche di Apple, invece di cercare di dedurre il modello dalla posizione dei caratteri.<sup>[[2]](#references)</sup>

### Recuperare il numero di serie

L'interfaccia grafica lo visualizza in **Menu Apple > Informazioni su questo Mac**.<sup>[[2]](#references)</sup> Da una shell, entrambi i comandi seguenti leggono il numero di serie della piattaforma:
```bash
system_profiler SPHardwareDataType | awk -F ': ' '/Serial Number/ {print $2}'
ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/ {print $4}'
```
Considera il numero di serie come un identificatore, non come un autenticatore: verifica il dispositivo tramite il workflow di inventario Apple o MDM pertinente prima di prendere decisioni sull'enrollment o sulla proprietà.

## References

- [1] [MacRumors - Apple avvia la transizione ai numeri di serie randomizzati](https://www.macrumors.com/2021/05/05/purple-iphone-12-randomized-serial-number/)
- [2] [Apple Support - Trova il nome del modello e il numero di serie del tuo Mac](https://support.apple.com/en-us/102767)
- [3] [Beetstech - Decodifica il significato di un numero di serie Apple](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)
{{#include ../../../banners/hacktricks-training.md}}
