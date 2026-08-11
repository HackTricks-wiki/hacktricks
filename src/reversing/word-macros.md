# Makra Worda

{{#include ../banners/hacktricks-training.md}}

## Kod śmieciowy

Makra mogą zawierać **nieosiągalny lub nieistotny kod**, którego celem jest spowolnienie analizy. Zidentyfikuj stałe warunki i prześledź osiągalne zachowanie, zanim poświęcisz czas na odwracanie gałęzi. Poniższy przykład używa warunku `If`, który nigdy nie może być prawdziwy, aby ukryć kod śmieciowy.

![Makro Worda zawierające nieosiągalną gałąź warunkową z kodem śmieciowym](<../images/image (369).png>)

## Formy makr

VBA UserForms mogą przechowywać dane w kontrolkach, takich jak pola tekstowe. Ponieważ formularze, ramki i strony mogą udostępniać kolekcję `Controls`, analitycy powinni wyliczać całą hierarchię kontrolek, zamiast polegać wyłącznie na tym, co wyświetla formularz. Poniższy przykład przechowuje ukryte dane w nakładających się na siebie polach tekstowych.<sup>[[1]](#references)</sup>

![UserForm makra z danymi ukrytymi w nakładających się na siebie polach tekstowych](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Kolekcje, kontrolki i obiekty (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
{{#include ../banners/hacktricks-training.md}}
