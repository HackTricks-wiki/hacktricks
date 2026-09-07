# Análise de arquivos do Office

{{#include ../../../banners/hacktricks-training.md}}

Para obter mais informações, consulte [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Este é apenas um resumo:<sup>[[4]](#references)</sup>

Os documentos do Microsoft Office geralmente aparecem como formatos legados, como RTF e DOC, XLS e PPT baseados em OLE/CFBF, ou como formatos mais recentes **Office Open XML (OOXML)**, como DOCX, XLSX e PPTX. Os documentos do Office podem conter conteúdo ativo, como macros, tornando-os vetores comuns de phishing e malware. Os arquivos OOXML são contêineres ZIP cuja hierarquia de arquivos e conteúdo XML podem ser inspecionados descompactando-os.<sup>[[3]](#references)[[4]](#references)</sup>

Para explorar as estruturas de arquivos OOXML, são apresentados o comando para descompactar um documento e a estrutura de saída. Técnicas para ocultar dados nesses arquivos foram documentadas, indicando inovação contínua na ocultação de dados em desafios de CTF.<sup>[[4]](#references)</sup>

Para análise, **oletools** e **OfficeDissector** oferecem conjuntos abrangentes de ferramentas para examinar documentos OLE e OOXML. Essas ferramentas ajudam a identificar e analisar macros incorporadas, que frequentemente servem como vetores para a entrega de malware, normalmente baixando e executando payloads maliciosos adicionais. A análise de macros VBA pode ser realizada sem o Microsoft Office utilizando o Libre Office, que permite a depuração com breakpoints e variáveis de observação.<sup>[[4]](#references)</sup>

A instalação e o uso do **oletools** são simples, com comandos fornecidos para instalar via pip e extrair macros de documentos. No Word, as macros automáticas incluem `AutoExec` e `AutoOpen`, enquanto `Document_Open` é um procedimento de evento de abertura.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
Para documentos Office criptografados com senha, consulte o [grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Exploração de OLE Compound File: Autodesk Revit RFA – recomputação de ECC e gzip controlado

Os modelos RFA do Revit são armazenados como um [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (também conhecido como CFBF). O modelo serializado está em storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Estrutura principal de `Global\Latest` (observada no Revit 2025):

- Cabeçalho
- Payload comprimido com GZIP (o object graph serializado real)
- Padding com zeros
- Trailer de Error-Correcting Code (ECC)

O Revit repara automaticamente pequenas alterações no stream usando o trailer de ECC e rejeita streams que não correspondam ao ECC. Portanto, editar ingenuamente os bytes comprimidos não persistirá: suas alterações serão revertidas ou o arquivo será rejeitado. Para garantir controle byte a byte sobre o que o deserializer verá, você precisa:<sup>[[1]](#references)</sup>

- Recompactar com uma implementação de gzip compatível com o Revit (para que os bytes comprimidos produzidos/aceitos pelo Revit correspondam ao que ele espera).
- Recalcular o trailer de ECC sobre o stream preenchido com padding para que o Revit aceite o stream modificado sem repará-lo automaticamente.

Workflow prático para aplicar patches/fuzzing ao conteúdo RFA:<sup>[[1]](#references)</sup>

1) Expandir o documento OLE compound.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Edite `Global\Latest` seguindo as regras de gzip/ECC

- Desmonte `Global/Latest`: mantenha o cabeçalho, faça gunzip do payload, altere os bytes e, em seguida, faça gzip novamente usando parâmetros de deflate compatíveis com o Revit.
- Preserve o preenchimento com zeros e recalcule o trailer ECC para que os novos bytes sejam aceitos pelo Revit.
- Se precisar de uma reprodução determinística byte a byte, crie um wrapper mínimo em torno das DLLs do Revit para chamar os caminhos de gzip/gunzip e o cálculo de ECC (conforme demonstrado em pesquisas) ou reutilize qualquer helper disponível que replique essa semântica.

3) Recompile o documento composto OLE.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notas:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool grava storages/streams no sistema de arquivos, aplicando escaping aos caracteres inválidos em nomes NTFS; o caminho do stream desejado é exatamente `Global/Latest` na árvore de saída.
- Ao realizar ataques em massa por meio de plugins do ecossistema que buscam RFAs em cloud storage, certifique-se de que seu RFA corrigido passe primeiro pelas verificações de integridade do Revit localmente (gzip/ECC corretos) antes de tentar a injeção pela rede.

Insight de exploração (para orientar quais bytes colocar no payload gzip):<sup>[[1]](#references)</sup>

- O desserializador do Revit lê um índice de classe de 16 bits e constrói um objeto. Certos tipos não são polimórficos e não possuem vtables; abusar do tratamento do destrutor produz uma confusão de tipos na qual o engine executa uma chamada indireta por meio de um ponteiro controlado pelo atacante.
- Escolher `AString` (índice de classe `0x1F`) coloca um ponteiro de heap controlado pelo atacante no offset 0 do objeto. Durante o loop do destrutor, o Revit efetivamente executa:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Coloque múltiplos desses objetos no grafo serializado para que cada iteração do loop do destrutor execute um gadget (“weird machine”) e organize um stack pivot para uma cadeia ROP x64 convencional.

Veja os detalhes de construção de pivots/gadgets x64 do Windows aqui:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

e orientações gerais sobre ROP aqui:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Ferramentas:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) para expandir/reconstruir arquivos compostos OLE: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD para reverse/taint; desative o page heap com TTD para manter os traces compactos.
- Um proxy local (por exemplo, Fiddler) pode simular a entrega de supply chain substituindo RFAs no tráfego de plugins para testes.

## References

- [1] [Criando um exploit RCE completo a partir de um crash na análise de arquivos RFA do Autodesk Revit (blog da ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Documentação de arquivos compostos OLE (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Guia de campo de Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [Documentação do olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Evento Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
