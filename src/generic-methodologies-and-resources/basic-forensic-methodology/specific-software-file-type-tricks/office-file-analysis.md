# Análise de arquivos Office

{{#include ../../../banners/hacktricks-training.md}}


Para mais informações, consulte [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Isto é apenas um resumo:

A Microsoft criou muitos formatos de documentos do Office, com dois tipos principais sendo **OLE formats** (like RTF, DOC, XLS, PPT) e **Office Open XML (OOXML) formats** (such as DOCX, XLSX, PPTX). Esses formatos podem incluir macros, tornando-os alvos para phishing e malware. Arquivos OOXML são estruturados como containers zip, permitindo inspeção através do unzip, revelando a hierarquia de arquivos e pastas e o conteúdo dos arquivos XML.

Para explorar estruturas de arquivos OOXML, o comando para unzipar um documento e a estrutura de saída são fornecidos. Técnicas para esconder dados nesses arquivos têm sido documentadas, indicando inovação contínua em ocultação de dados dentro de desafios CTF.

Para análise, **oletools** e **OfficeDissector** oferecem conjuntos de ferramentas abrangentes para examinar documentos OLE e OOXML. Essas ferramentas ajudam a identificar e analisar macros embutidos, que frequentemente servem como vetores para entrega de malware, tipicamente fazendo download e executando payloads maliciosos adicionais. A análise de macros VBA pode ser realizada sem Microsoft Office usando Libre Office, que permite debugging com breakpoints e watch variables.

A instalação e uso do **oletools** é simples, com comandos fornecidos para instalar via pip e extrair macros de documentos. A execução automática de macros é acionada por funções como `AutoOpen`, `AutoExec`, ou `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA models are stored as an [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). The serialized model is under storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Key layout of `Global\Latest` (observed on Revit 2025):

- Header
- GZIP-compressed payload (the actual serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit will auto-repair small perturbations to the stream using the ECC trailer and will reject streams that don’t match the ECC. Therefore, de forma ingênua editar os bytes comprimidos não persistirá: suas alterações ou serão revertidas ou o arquivo será rejeitado. Para garantir controle exato por byte sobre o que o desserializador vê, você deve:

- Recompress with a Revit-compatible gzip implementation (so the compressed bytes Revit produces/accepts match what it expects).
- Recompute the ECC trailer over the padded stream so Revit will accept the modified stream without auto-repairing it.

Practical workflow for patching/fuzzing RFA contents:

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Editar Global\Latest com gzip/ECC discipline

- Deconstrua `Global/Latest`: mantenha o cabeçalho, gunzip o payload, modifique os bytes e então gzip de volta usando parâmetros de deflate compatíveis com Revit.
- Mantenha o zero-padding e recalcule o ECC trailer para que os novos bytes sejam aceitos pelo Revit.
- Se precisar de reprodução determinística byte-a-byte, construa um wrapper mínimo em torno das DLLs do Revit para invocar seus caminhos gzip/gunzip e o cálculo do ECC (como demonstrado na pesquisa), ou reutilize qualquer helper disponível que replique essas semânticas.

3) Reconstruir o documento composto OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
- CompoundFileTool writes storages/streams to the filesystem with escaping for characters invalid in NTFS names; the stream path you want is exactly `Global/Latest` in the output tree.
- When delivering mass attacks via ecosystem plugins that fetch RFAs from cloud storage, ensure your patched RFA passes Revit’s integrity checks locally first (gzip/ECC correct) before attempting network injection.

Exploitation insight (to guide what bytes to place in the gzip payload):

- O deserializer do Revit lê um índice de classe de 16 bits e constrói um objeto. Certos tipos são não‑polimórficos e não possuem vtables; abusar do manuseio do destructor produz uma type confusion onde o engine executa uma chamada indireta através de um ponteiro controlado pelo atacante.
- Picking `AString` (class index `0x1F`) places an attacker-controlled heap pointer at object offset 0. During the destructor loop, Revit effectively executes:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Coloque múltiplos objetos desse tipo no grafo serializado para que cada iteração do destructor loop execute um gadget (“weird machine”), e arranje um stack pivot para uma cadeia ROP x64 convencional.

Veja detalhes de Windows x64 pivot/gadget building aqui:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

e orientações gerais de ROP aqui:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Ferramentas:

- CompoundFileTool (OSS) para expandir/reconstruir OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD para reverse/taint; desative page heap com TTD para manter os traces compactos.
- Um proxy local (p.ex., Fiddler) pode simular supply-chain delivery trocando RFAs no plugin traffic para testes.

## Referências

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
