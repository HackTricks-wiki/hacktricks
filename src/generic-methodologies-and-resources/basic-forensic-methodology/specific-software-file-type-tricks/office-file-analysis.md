# Análise de arquivos do Office

{{#include ../../../banners/hacktricks-training.md}}


Para obter mais informações, consulte [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Este é apenas um resumo:<sup>[[4]](#references)</sup>

A Microsoft criou vários formatos de documentos do Office, sendo os dois principais os formatos **OLE** (como RTF, DOC, XLS, PPT) e os formatos **Office Open XML (OOXML)** (como DOCX, XLSX, PPTX). Esses formatos podem incluir macros, tornando-os alvos de phishing e malware. Os arquivos OOXML são estruturados como contêineres zip, permitindo sua inspeção por meio da descompactação, revelando a hierarquia de arquivos e pastas e o conteúdo dos arquivos XML.

Para explorar as estruturas de arquivos OOXML, são apresentados o comando para descompactar um documento e a estrutura de saída. Técnicas para ocultar dados nesses arquivos foram documentadas, indicando uma inovação contínua na ocultação de dados em desafios de CTF.

Para análise, **oletools** e **OfficeDissector** oferecem conjuntos abrangentes de ferramentas para examinar documentos OLE e OOXML. Essas ferramentas ajudam a identificar e analisar macros incorporadas, que frequentemente servem como vetores para a entrega de malware, normalmente baixando e executando payloads maliciosos adicionais. A análise de macros VBA pode ser realizada sem o Microsoft Office utilizando o Libre Office, que permite a depuração com breakpoints e variáveis de observação.

A instalação e o uso de **oletools** são simples, com comandos fornecidos para a instalação via pip e a extração de macros de documentos. A execução automática de macros é acionada por funções como `AutoOpen`, `AutoExec` ou `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Exploração de OLE Compound File: Autodesk Revit RFA – recomputação de ECC e gzip controlado

Os modelos RFA do Revit são armazenados como um [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (também chamado CFBF). O modelo serializado está em storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Layout principal de `Global\Latest` (observado no Revit 2025):

- Cabeçalho
- Payload comprimido com GZIP (o object graph serializado real)
- Padding de zeros
- Trailer de Error-Correcting Code (ECC)

O Revit repara automaticamente pequenas alterações no stream usando o trailer ECC e rejeita streams que não correspondem ao ECC. Portanto, editar ingenuamente os bytes comprimidos não persistirá: suas alterações serão revertidas ou o arquivo será rejeitado. Para garantir controle byte a byte sobre o que o deserializer recebe, você deve:

- Recomprimir com uma implementação de gzip compatível com o Revit (para que os bytes comprimidos produzidos/aceitos pelo Revit correspondam ao que ele espera).
- Recomputar o trailer ECC sobre o stream preenchido com padding para que o Revit aceite o stream modificado sem repará-lo automaticamente.

Fluxo de trabalho prático para aplicar patches/fuzzing em conteúdos RFA:<sup>[[1]](#references)</sup>

1) Expanda o documento OLE compound
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Edite `Global\Latest` seguindo as regras de gzip/ECC

- Desconstrua `Global/Latest`: mantenha o cabeçalho, use gunzip no payload, altere os bytes e, em seguida, use gzip novamente com os parâmetros de deflate compatíveis com o Revit.
- Preserve o preenchimento com zeros e recalcule o trailer ECC para que os novos bytes sejam aceitos pelo Revit.
- Se precisar de uma reprodução determinística byte a byte, crie um wrapper mínimo em torno das DLLs do Revit para invocar os caminhos de gzip/gunzip e o cálculo de ECC (conforme demonstrado em pesquisas) ou reutilize qualquer helper disponível que replique essas semânticas.

3) Reconstrua o documento composto OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)</sup>

- CompoundFileTool grava storages/streams no filesystem, usando escaping para caracteres inválidos em nomes NTFS; o caminho do stream desejado é exatamente `Global/Latest` na árvore de saída.
- Ao realizar ataques em massa por meio de plugins do ecossistema que obtêm RFAs de cloud storage, certifique-se de que seu RFA corrigido passe primeiro pelas verificações de integridade do Revit localmente (gzip/ECC corretos) antes de tentar a injeção pela rede.

Insight de Exploitation (para orientar quais bytes colocar no payload gzip):<sup>[[1]](#references)</sup>

- O desserializador do Revit lê um índice de classe de 16 bits e constrói um objeto. Certos tipos não são polimórficos e não possuem vtables; abusar do tratamento do destrutor gera uma confusão de tipos na qual o engine executa uma chamada indireta por meio de um ponteiro controlado pelo atacante.
- Escolher `AString` (índice de classe `0x1F`) coloca um ponteiro de heap controlado pelo atacante no offset 0 do objeto. Durante o loop do destrutor, o Revit efetivamente executa:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Coloque vários desses objetos no grafo serializado para que cada iteração do loop do destrutor execute um gadget (“weird machine”) e organize um stack pivot para uma cadeia ROP x64 convencional.

Consulte os detalhes sobre pivot/gadget building em Windows x64 aqui:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

e orientações gerais sobre ROP aqui:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Ferramentas:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) para expandir/reconstruir arquivos compound OLE: https://github.com/thezdi/CompoundFileTool<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD para reverse/taint; desative o page heap com TTD para manter os traces compactos.
- Um proxy local (por exemplo, Fiddler) pode simular a entrega de supply-chain substituindo RFAs no tráfego do plugin para testes.

## Referências

- [1] [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
