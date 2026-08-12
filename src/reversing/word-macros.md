# Macro di Word

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Le macro possono contenere **codice irraggiungibile o irrilevante** destinato a rallentare l'analisi. Identificate le condizioni costanti e tracciate il comportamento raggiungibile prima di dedicare tempo al reversing di un branch. L'esempio seguente usa una condizione `If` che non può mai essere vera per nascondere junk code.

![Una macro di Word contenente un branch condizionale irraggiungibile con junk code](<../images/image (369).png>)

## Form dei macro

Le VBA UserForms possono memorizzare dati in controlli come le caselle di testo. Poiché form, frame e pagine possono esporre ciascuno una raccolta `Controls`, gli analisti dovrebbero enumerare l'intera gerarchia dei controlli invece di basarsi solo su ciò che mostra la form. L'esempio seguente memorizza dati nascosti in caselle di testo sovrapposte.<sup>[[1]](#references)</sup>

Durante l'analisi dinamica, la funzione `GetObject` di VBA può recuperare un oggetto Automation da un file o collegarsi a un server Automation già in esecuzione. Le macro possono usare tale accesso agli oggetti per raggiungere dati non evidenti nel documento visibile; esaminate sia l'oggetto restituito sia l'albero dei controlli della UserForm.<sup>[[2]](#references)</sup>

![Una UserForm di una macro con dati nascosti in caselle di testo sovrapposte](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Raccolte, controlli e oggetti (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - Funzione `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../banners/hacktricks-training.md}}
