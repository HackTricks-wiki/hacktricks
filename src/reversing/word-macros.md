# Macros do Word

{{#include ../banners/hacktricks-training.md}}

## Código inútil

As macros podem conter **código inalcançável ou irrelevante** destinado a dificultar a análise. Identifique condições constantes e rastreie o comportamento alcançável antes de gastar tempo revertendo um ramo. O exemplo abaixo usa uma condição `If` que nunca pode ser verdadeira para ocultar código inútil.

![Uma macro do Word contendo um ramo condicional inalcançável com código inútil](<../images/image (369).png>)

## Formulários de macro

Os UserForms do VBA podem armazenar dados em controles, como caixas de texto. Como formulários, frames e páginas podem expor uma coleção `Controls`, os analistas devem enumerar toda a hierarquia de controles em vez de depender apenas do que o formulário exibe. O exemplo abaixo armazena dados ocultos em caixas de texto sobrepostas.<sup>[[1]](#references)</sup>

Durante a análise dinâmica, a função `GetObject` do VBA pode recuperar um objeto de Automation de um arquivo ou se conectar a um servidor de Automation já em execução. As macros podem usar esse acesso ao objeto para alcançar dados que não são óbvios no documento visível; inspecione tanto o objeto retornado quanto a árvore de controles do UserForm.<sup>[[2]](#references)</sup>

![Um UserForm de macro com dados ocultos em caixas de texto sobrepostas](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Coleções, controles e objetos (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - Função `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../banners/hacktricks-training.md}}
