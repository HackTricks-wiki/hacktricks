# Makra Worda

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Makra mogą zawierać **nieosiągalny lub nieistotny kod**, którego celem jest spowolnienie analizy. Zidentyfikuj stałe warunki i prześledź osiągalne zachowanie, zanim poświęcisz czas na odwracanie konkretnej gałęzi. Poniższy przykład wykorzystuje warunek `If`, który nigdy nie może być prawdziwy, aby ukryć junk code.

![Makro Worda zawierające nieosiągalną gałąź warunkową z junk code](<../images/image (369).png>)

## Formy makr

VBA UserForms mogą przechowywać dane w kontrolkach, takich jak pola tekstowe. Ponieważ formularze, ramki i strony mogą udostępniać kolekcję `Controls`, analitycy powinni wyliczać całą hierarchię kontrolek, zamiast polegać wyłącznie na tym, co wyświetla formularz. Poniższy przykład przechowuje ukryte dane w nakładających się polach tekstowych.<sup>[[1]](#references)</sup>

Podczas analizy dynamicznej funkcja `GetObject` języka VBA może pobrać obiekt Automation z pliku lub połączyć się z już uruchomionym serwerem Automation. Makra mogą wykorzystywać ten dostęp do obiektu, aby uzyskać dostęp do danych, które nie są widoczne w dokumencie; sprawdź zarówno zwrócony obiekt, jak i drzewo kontrolek UserForm.<sup>[[2]](#references)</sup>

![Makro UserForm z danymi ukrytymi w nakładających się polach tekstowych](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Kolekcje, kontrolki i obiekty (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - Funkcja `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../banners/hacktricks-training.md}}
