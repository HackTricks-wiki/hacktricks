# Macros do Word

{{#include ../banners/hacktricks-training.md}}

## Código inútil

As macros podem conter **código inalcançável ou irrelevante** destinado a dificultar a análise. Identifique condições constantes e rastreie o comportamento alcançável antes de gastar tempo fazendo reverse de uma ramificação. O exemplo abaixo usa uma condição `If` que nunca pode ser verdadeira para ocultar código inútil.

![Uma macro do Word contendo uma ramificação condicional inalcançável com código inútil](<../images/image (369).png>)

## Formulários de macro

VBA UserForms podem armazenar dados em controles, como caixas de texto. Como forms, frames e pages podem expor uma coleção `Controls`, os analistas devem enumerar toda a hierarquia de controles, em vez de depender apenas do que o form exibe. O exemplo abaixo armazena dados ocultos em caixas de texto sobrepostas.<sup>[[1]](#references)</sup>

![Um UserForm de macro com dados ocultos em caixas de texto sobrepostas](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Coleções, controles e objetos (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
{{#include ../banners/hacktricks-training.md}}
