# Análise de arquivos do Office

{{#include ../../../banners/hacktricks-training.md}}

Para mais informações, consulte [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Este é apenas um resumo:<sup>[[2]](#references)</sup>

Documentos do Microsoft Office costumam aparecer em formatos legados, como RTF e DOC, XLS e PPT baseados em OLE/CFBF, ou nos formatos mais recentes **Office Open XML (OOXML)**, como DOCX, XLSX e PPTX. Documentos do Office podem conter conteúdo ativo, como macros, o que os torna vetores comuns de phishing e malware. Arquivos OOXML são contêineres ZIP cuja hierarquia de arquivos e conteúdo XML podem ser inspecionados descompactando-os.<sup>[[1]](#references)[[2]](#references)</sup>

São apresentados o comando para descompactar um documento e a estrutura resultante, a fim de explorar estruturas de arquivos OOXML. Técnicas para ocultar dados nesses arquivos foram documentadas, indicando a contínua inovação na ocultação de dados em desafios de CTF.<sup>[[2]](#references)</sup>

Para análise, **oletools** e **OfficeDissector** oferecem conjuntos abrangentes de ferramentas para examinar documentos OLE e OOXML. Essas ferramentas ajudam a identificar e analisar macros incorporadas, que muitas vezes servem como vetores para a distribuição de malware, geralmente baixando e executando payloads maliciosos adicionais. A análise de macros VBA pode ser feita sem o Microsoft Office usando o LibreOffice, que permite depurar com breakpoints e variáveis de observação.<sup>[[2]](#references)</sup>

A instalação e o uso do **oletools** são simples, e há comandos para instalá-lo via pip e extrair macros de documentos. No Word, as macros automáticas incluem `AutoExec` e `AutoOpen`, enquanto `Document_Open` é um procedimento de evento de abertura.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## Análise de macros VBA: código inútil e UserForms

## Código inútil

As macros podem conter **código inalcançável ou irrelevante** destinado a dificultar a análise. Identifique condições constantes e rastreie o comportamento alcançável antes de perder tempo analisando um ramo. O exemplo abaixo usa uma condição `If` que nunca pode ser verdadeira para ocultar código inútil.

![Uma macro do Word com um ramo condicional inalcançável contendo código inútil](<../../../images/image (369).png>)

## Formulários de macro

Os UserForms do VBA podem armazenar dados em controles, como caixas de texto. Como formulários, quadros e páginas podem expor uma coleção `Controls`, os analistas devem enumerar toda a hierarquia de controles, em vez de confiar apenas no que o formulário exibe. O exemplo abaixo armazena dados ocultos em caixas de texto sobrepostas.<sup>[[6]](#references)</sup>

Durante a análise dinâmica, a função `GetObject` do VBA pode recuperar um objeto Automation de um arquivo ou se conectar a um servidor Automation já em execução. As macros podem usar esse acesso a objetos para acessar dados que não são óbvios no documento visível; inspecione tanto o objeto retornado quanto a árvore de controles do UserForm.<sup>[[7]](#references)</sup>

![Um UserForm de macro com dados ocultos em caixas de texto sobrepostas](<../../../images/image (344).png>)

Para documentos do Office criptografados com senha, consulte o [fluxo de recuperação offline orientado por gramática](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

Para arquivos Revit RFA que usam OLE/CFBF, consulte [recomputação de ECC, gzip controlado e exploração de desserializador](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md); esse fluxo de exploração do parser é separado da triagem de documentos do Office.

## References

- [1] [Documentação de OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [Guia de campo de forense para CTFs](https://trailofbits.github.io/ctf/forensics/)
- [3] [Documentação do olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [Macros automáticas (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Evento Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn - Coleções, controles e objetos (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn - Função `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../../../banners/hacktricks-training.md}}
