# Macro di Word

{{#include ../banners/hacktricks-training.md}}

### Codice spazzatura

È molto comune trovare **codice spazzatura che non viene mai utilizzato** per rendere più difficile il reversing della macro.\
Ad esempio, nell'immagine seguente puoi vedere che viene utilizzato un `If` che non sarà mai vero per eseguire del codice spazzatura e inutile.

![Macro di Word - Codice spazzatura: Ad esempio, nell'immagine seguente puoi vedere che viene utilizzato un If che non sarà mai vero per eseguire del codice spazzatura e inutile](<../images/image (369).png>)

### Form delle macro

Utilizzando la funzione **GetObject** è possibile ottenere dati dai form della macro. Questo può essere utilizzato per rendere più difficile l'analisi. Di seguito è riportata un'immagine di un form di una macro utilizzato per **nascondere dati all'interno di caselle di testo** (una casella di testo può nascondere altre caselle di testo):

![Codice spazzatura - Form delle macro: Utilizzando la funzione GetObject è possibile ottenere dati dai form della macro. Questo può essere utilizzato per rendere più difficile l'analisi. Di seguito è riportata un'immagine di un...](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
