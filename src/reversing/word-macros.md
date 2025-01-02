# Word Macros

{{#include ../banners/hacktricks-training.md}}

### Junk Code

È molto comune trovare **codice spazzatura che non viene mai utilizzato** per rendere più difficile il reversing del macro.\
Ad esempio, nell'immagine seguente puoi vedere che un If che non sarà mai vero viene utilizzato per eseguire del codice spazzatura e inutile.

![](<../images/image (369).png>)

### Macro Forms

Utilizzando la funzione **GetObject** è possibile ottenere dati dai moduli del macro. Questo può essere usato per rendere difficile l'analisi. La seguente è una foto di un modulo macro utilizzato per **nascondere dati all'interno di caselle di testo** (una casella di testo può nascondere altre caselle di testo):

![](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
