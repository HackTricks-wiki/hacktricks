# Análise de arquivos Office

{{#include ../../../banners/hacktricks-training.md}}


Para mais informações veja [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Isto é apenas um resumo:

A Microsoft criou vários formatos de documentos Office, com dois tipos principais sendo **formatos OLE** (como RTF, DOC, XLS, PPT) e **formatos Office Open XML (OOXML)** (como DOCX, XLSX, PPTX). Esses formatos podem incluir macros, tornando-os alvos para phishing e malware. Arquivos OOXML são estruturados como containers zip, permitindo inspeção através do unzip, revelando a hierarquia de arquivos e pastas e o conteúdo dos arquivos XML.

Para explorar estruturas de arquivos OOXML, o comando para descompactar um documento e a estrutura de saída são mostrados. Técnicas para ocultar dados nesses arquivos foram documentadas, indicando inovação contínua na ocultação de dados em desafios CTF.

Para análise, **oletools** e **OfficeDissector** oferecem conjuntos completos de ferramentas para examinar documentos tanto OLE quanto OOXML. Essas ferramentas ajudam a identificar e analisar macros embutidas, que frequentemente servem como vetores para entrega de malware, tipicamente baixando e executando payloads maliciosos adicionais. A análise de macros VBA pode ser realizada sem Microsoft Office usando Libre Office, que permite depuração com breakpoints e watch variables.

A instalação e uso do **oletools** são simples, com comandos fornecidos para instalar via pip e extrair macros de documentos. A execução automática de macros é acionada por funções como `AutoOpen`, `AutoExec` ou `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Modelos RFA do Revit são armazenados como um [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). O modelo serializado fica sob storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Layout chave de `Global\Latest` (observado no Revit 2025):

- Cabeçalho
- Carga útil comprimida com GZIP (o grafo de objetos serializado)
- Preenchimento com zeros
- Trailer de Error-Correcting Code (ECC)

O Revit repara automaticamente pequenas perturbações no stream usando o trailer ECC e rejeita streams que não correspondem ao ECC. Portanto, editar de forma ingênua os bytes comprimidos não persistirá: suas alterações serão revertidas ou o arquivo será rejeitado. Para garantir controle preciso por byte sobre o que o desserializador vê, você deve:

- Recomprima usando uma implementação de gzip compatível com o Revit (para que os bytes comprimidos que o Revit produz/aceita correspondam ao que ele espera).
- Recalcule o trailer ECC sobre o stream preenchido para que o Revit aceite o stream modificado sem reparo automático.

Fluxo de trabalho prático para patching/fuzzing do conteúdo RFA:

1) Expanda o documento OLE Compound
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Editar Global\Latest com disciplina gzip/ECC

- Decompor `Global/Latest`: manter o header, gunzip o payload, modificar bytes e então gzip de volta usando parâmetros de deflate compatíveis com Revit.
- Preservar o zero-padding e recalcular o trailer ECC para que os novos bytes sejam aceitos pelo Revit.
- Se precisar de reprodução determinística byte-a-byte, construa um wrapper mínimo em torno das DLLs do Revit para invocar seus caminhos gzip/gunzip e a computação ECC (como demonstrado em pesquisas), ou reutilize qualquer helper disponível que replique essas semânticas.

3) Reconstruir o OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notas:

- CompoundFileTool escreve storages/streams no sistema de arquivos com escape para caracteres inválidos em nomes NTFS; o caminho do stream que você quer é exatamente `Global/Latest` na árvore de saída.
- Ao entregar ataques em massa via plugins do ecossistema que buscam RFAs de armazenamento em nuvem, garanta que seu RFA modificado passe nas verificações de integridade do Revit localmente primeiro (gzip/ECC corretos) antes de tentar a injeção na rede.

Exploitation insight (to guide what bytes to place in the gzip payload):

- O deserializador do Revit lê um índice de classe 16-bit e constrói um objeto. Certos tipos são não‑polimórficos e não possuem vtables; abusar do tratamento de destruidores gera uma confusão de tipos onde o engine executa uma chamada indireta através de um ponteiro controlado pelo atacante.
- Escolher `AString` (class index `0x1F`) coloca um ponteiro do heap controlado pelo atacante no offset 0 do objeto. Durante o destructor loop, Revit efetivamente executa:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Coloque múltiplos desses objetos no grafo serializado para que cada iteração do destructor loop execute um gadget (“weird machine”), e arranje um stack pivot para uma convencional x64 ROP chain.

Veja detalhes de pivot/gadget para Windows x64 aqui:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

e orientações gerais de ROP aqui:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Ferramentas:

- CompoundFileTool (OSS) para expandir/reconstruir OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD para reverse/taint; desative page heap com TTD para manter os traces compactos.
- Um proxy local (p.ex., Fiddler) pode simular a entrega supply-chain trocando RFAs no tráfego do plugin para testes.

## Referências

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
