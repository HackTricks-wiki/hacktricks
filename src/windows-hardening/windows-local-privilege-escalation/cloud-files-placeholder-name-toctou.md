# Double-Fetch di un buffer utente mappato tramite MDL in Windows

{{#include ../../banners/hacktricks-training.md}}

Un driver kernel di Windows genera un double-fetch quando convalida dati in pagine associate al chiamante e in seguito passa un puntatore a quelle stesse pagine a un'API sensibile alla sicurezza. Bloccare e mappare le pagine non rende immutabili i loro contenuti. CVE-2025-55680 in `cldflt.sys` illustra questo schema: il driver convalidava il nome relativo di un placeholder di Cloud Files, poi creava l'oggetto continuando a usare il buffer modificabile del chiamante.<sup>[[1]](#references)[[3]](#references)</sup>

`CfCreatePlaceholders()` crea file o directory all'interno di una sync root Cloud Files registrata. Nel percorso vulnerabile, modificare il nome dopo la convalida poteva reindirizzare la creazione con privilegi al di fuori di quella root.<sup>[[1]](#references)[[2]](#references)</sup>

## Perché bloccare le pagine non bloccava i dati

Il percorso vulnerabile `HsmpOpCreatePlaceholders()` allocava un MDL per il payload del chiamante, chiamava `ProbeForRead()` e `MmProbeAndLockPages()`, quindi mappava quelle pagine nello spazio degli indirizzi virtuali del kernel. Un MDL descrive e blocca le pagine fisiche affinché restino residenti. **Non** crea uno snapshot dei loro byte. La modalità utente può quindi modificare la stessa memoria fisica mentre il driver la legge tramite la mappatura di sistema.<sup>[[1]](#references)[[3]](#references)</sup>

Il percorso rilevante della richiesta e dell'utilizzo era:<sup>[[1]](#references)</sup>

1. `cldapi.dll` inviava il codice di controllo Cloud Files `0x903BC` con il tag `IO_REPARSE_TAG_CLOUD` (`0x9000001A`) e l'operazione di creazione del placeholder `0xC0000001`.
2. Ogni record del payload conteneva coppie offset/lunghezza a 16 bit per il nome relativo e l'identità del file. La maggior parte dei campi fissi veniva copiata in un record sullo stack, ma il nome a lunghezza variabile restava nelle pagine utente mappate.
3. Il driver scansionava il nome UTF-16 e rifiutava una barra rovesciata o due punti.
4. Poi creava una `UNICODE_STRING` il cui `Buffer` puntava ancora al payload mappato e la assegnava a `OBJECT_ATTRIBUTES.ObjectName`.
5. `FltCreateFileEx2()` leggeva nuovamente quel puntatore. Un writer concorrente poteva quindi far sì che la convalida vedesse una stringa e la creazione del file un'altra.

Si tratta di un **double-fetch** anche se entrambe le letture usano un indirizzo virtuale del kernel: il confine di sicurezza dipende dalla memoria sottostante, non dalla mappatura virtuale dereferenziata dal driver.<sup>[[1]](#references)</sup>

## Schema della race di Cloud Files

La strategia di exploit divulgata usava richieste ripetute, thread mutator e una junction per trasformare il double-fetch in un reindirizzamento del percorso:<sup>[[1]](#references)</sup>

1. Registrare una directory controllata dall'attaccante con `CfRegisterSyncRoot()` e creare al suo interno `JUSTASTRING` come junction verso una destinazione protetta.
2. Preparare un record di placeholder condiviso con il nome valido a componente singolo `JUSTASTRINGDnewfile.dll`.
3. Far alternare ai thread mutator il code unit UTF-16 `D` tra `D` e `\`. La seconda rappresentazione è `JUSTASTRING\newfile.dll`.
4. In parallelo, far inviare ripetutamente ai thread worker richieste di creazione del placeholder che fanno riferimento allo stesso payload, mentre un monitor controlla la destinazione protetta.
5. Un'iterazione riuscita convalida la rappresentazione priva di separatore, poi segue la junction quando la successiva operazione di creazione legge la rappresentazione contenente `\`.

La primitiva consente soltanto di creare file o directory protetti. Per ottenere l'esecuzione di codice servono ancora il controllo dei contenuti del file creato e un consumer con privilegi, ad esempio un bersaglio adatto al DLL side-loading. L'analisi originale usava questa classe di chain finale, ma non ha pubblicato il loader, il payload o un exploit autonomo completo.<sup>[[1]](#references)</sup>

Per tecniche complementari che ampliano intenzionalmente le race di lookup dei percorsi in Windows, vedi [Sfruttamento delle race condition del kernel tramite i percorsi lenti dell'Object Manager](kernel-race-condition-object-manager-slowdown.md).

## References

- [1] [Exodus Intelligence - Escalation dei privilegi TOCTOU nel minifilter Cloud Files di Microsoft Windows](https://blog.exodusintel.com/2025/10/20/microsoft-windows-cloud-files-minifilter-toctou-privilege-escalation/)
- [2] [Microsoft Learn - Funzione CfCreatePlaceholders](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfcreateplaceholders)
- [3] [Microsoft Learn - Funzione MmProbeAndLockPages](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)
{{#include ../../banners/hacktricks-training.md}}
