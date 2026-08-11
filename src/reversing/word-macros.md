# Word Macros

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Le Macro possono contenere **codice irraggiungibile o irrilevante** destinato a rallentare l'analisi. Identifica le condizioni costanti e traccia il comportamento raggiungibile prima di dedicare tempo al reversing di un branch. L'esempio seguente usa una condizione `If` che non può mai essere vera per nascondere Junk Code.

![Una macro di Word contenente un branch condizionale irraggiungibile con Junk Code](<../images/image (369).png>)

## Form dei Macro

Le VBA UserForms possono memorizzare dati in controlli come le caselle di testo. Poiché form, frame e pagine possono esporre ciascuno una collection `Controls`, gli analisti dovrebbero enumerare l'intera gerarchia dei controlli anziché affidarsi solamente a ciò che visualizza il form. L'esempio seguente memorizza dati nascosti in caselle di testo sovrapposte.<sup>[[1]](#references)</sup>

![Una UserForm di una macro con dati nascosti in caselle di testo sovrapposte](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Collection, controlli e oggetti (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
{{#include ../banners/hacktricks-training.md}}
