# Office file analysis

{{#include ../../../banners/hacktricks-training.md}}


Para mais informações, veja [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Isto é apenas um resumo:

A Microsoft criou muitos formatos de documentos do Office, com dois tipos principais sendo **OLE formats** (como RTF, DOC, XLS, PPT) e **Office Open XML (OOXML) formats** (tais como DOCX, XLSX, PPTX). Esses formatos podem incluir macros, tornando-os alvos para phishing e malware. Arquivos OOXML são estruturados como contêineres zip, permitindo inspeção através do unzip, revelando a hierarquia de arquivos e pastas e o conteúdo dos arquivos XML.

Para explorar estruturas de arquivos OOXML, o comando para unzip de um documento e a estrutura de saída são apresentados. Técnicas para esconder dados nesses arquivos têm sido documentadas, indicando inovação contínua em ocultação de dados em desafios CTF.

Para análise, **oletools** e **OfficeDissector** oferecem conjuntos de ferramentas abrangentes para examinar tanto documentos OLE quanto OOXML. Essas ferramentas ajudam a identificar e analisar macros embutidos, que frequentemente servem como vetores para entrega de malware, tipicamente baixando e executando payloads maliciosos adicionais. A análise de VBA macros pode ser realizada sem Microsoft Office utilizando Libre Office, que permite debug com pontos de interrupção e variáveis de observação.

A instalação e uso de **oletools** são diretos, com comandos fornecidos para instalar via pip e extrair macros de documentos. A execução automática de macros é disparada por funções como `AutoOpen`, `AutoExec`, ou `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Exploração de OLE Compound File: Autodesk Revit RFA – recomputação de ECC e gzip controlado

Modelos Revit RFA são armazenados como um [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). O modelo serializado está sob storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Layout chave de `Global\Latest` (observado no Revit 2025):

- Cabeçalho
- Payload comprimido com GZIP (o grafo de objetos serializado real)
- Preenchimento com zeros
- Trailer do Error-Correcting Code (ECC)

O Revit irá auto-reparar pequenas perturbações no stream usando o trailer ECC e irá rejeitar streams que não corresponderem ao ECC. Portanto, editar ingenuamente os bytes comprimidos não persistirá: suas mudanças ou são revertidas ou o arquivo é rejeitado. Para garantir controle preciso por byte sobre o que o desserializador vê, você deve:

- Recompactar com uma implementação gzip compatível com Revit (para que os bytes comprimidos que o Revit produz/aceita coincidam com o que ele espera).
- Recomputar o trailer ECC sobre o stream preenchido para que o Revit aceite o stream modificado sem auto-repará-lo.

Fluxo prático para patching/fuzzing do conteúdo RFA:

1) Expanda o documento OLE compound
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Edit Global\Latest with gzip/ECC discipline

- Deconstruir `Global/Latest`: mantenha o header, gunzip o payload, mutar bytes e então gzip de volta usando parâmetros deflate compatíveis com Revit.
- Preservar zero-padding e recomputar o ECC trailer para que os novos bytes sejam aceitos pelo Revit.
- Se precisar de reprodução determinística byte-for-byte, construa um wrapper mínimo em torno das DLLs do Revit para invocar seus caminhos gzip/gunzip e a computação ECC (como demonstrado em research), ou reutilize qualquer helper disponível que replique essas semantics.

3) Reconstruir o documento composto OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notas:

- CompoundFileTool escreve storages/streams no sistema de arquivos com escaping para caracteres inválidos em nomes NTFS; o stream path que você quer é exatamente `Global/Latest` na árvore de saída.
- Ao entregar ataques em massa via ecosystem plugins que fetch RFAs from cloud storage, garanta que seu patched RFA passe Revit’s integrity checks localmente primeiro (gzip/ECC correct) antes de tentar network injection.

Exploitation insight (to guide what bytes to place in the gzip payload):

- O Revit deserializer lê um índice de classe de 16 bits e constrói um objeto. Certos tipos são non‑polymorphic e não têm vtables; abusar do tratamento de destructors gera uma type confusion onde o engine executa uma indirect call através de um attacker-controlled pointer.
- Escolher `AString` (class index `0x1F`) coloca um attacker-controlled heap pointer em object offset 0. Durante o destructor loop, Revit efetivamente executa:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Coloque múltiplos desses objetos no grafo serializado para que cada iteração do destructor loop execute um gadget (“weird machine”), e arranje um stack pivot em uma conventional x64 ROP chain.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Ferramentas:

- CompoundFileTool (OSS) para expandir/reconstruir OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD para reverse/taint; desative page heap com TTD para manter os rastreamentos compactos.
- Um proxy local (por exemplo, Fiddler) pode simular a entrega via supply-chain trocando RFAs no tráfego do plugin para testes.

## Referências

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
