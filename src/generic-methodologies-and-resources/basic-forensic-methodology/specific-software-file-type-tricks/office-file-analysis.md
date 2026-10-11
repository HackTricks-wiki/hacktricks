# Análise de arquivos do Office

{{#include ../../../banners/hacktricks-training.md}}

Para mais informações, consulte [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Este é apenas um resumo:<sup>[[4]](#references)</sup>

Documentos do Microsoft Office aparecem com frequência em formatos legados, como RTF e DOC, XLS e PPT baseados em OLE/CFBF, ou em formatos mais recentes **Office Open XML (OOXML)**, como DOCX, XLSX e PPTX. Documentos do Office podem conter conteúdo ativo, como macros, o que os torna vetores comuns de phishing e malware. Arquivos OOXML são contêineres ZIP cuja hierarquia de arquivos e conteúdo XML podem ser inspecionados descompactando-os.<sup>[[3]](#references)[[4]](#references)</sup>

Para explorar estruturas de arquivos OOXML, são apresentados o comando para descompactar um documento e a estrutura de saída. Técnicas para ocultar dados nesses arquivos foram documentadas, indicando inovação contínua na ocultação de dados em desafios de CTF.<sup>[[4]](#references)</sup>

Para análise, **oletools** e **OfficeDissector** oferecem conjuntos abrangentes de ferramentas para examinar documentos OLE e OOXML. Essas ferramentas ajudam a identificar e analisar macros incorporadas, que frequentemente servem como vetores para distribuição de malware, normalmente baixando e executando payloads maliciosos adicionais. A análise de macros VBA pode ser feita sem o Microsoft Office usando o LibreOffice, que permite depuração com breakpoints e variáveis de observação.<sup>[[4]](#references)</sup>

A instalação e o uso do **oletools** são simples, e há comandos para instalá-lo via pip e extrair macros de documentos. No Word, as macros automáticas incluem `AutoExec` e `AutoOpen`, enquanto `Document_Open` é um procedimento de evento de abertura.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

Para documentos do Office criptografados com senha, consulte o [fluxo de recuperação offline orientado por gramática](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Exploração de OLE Compound File: Autodesk Revit RFA – recomputação de ECC e gzip controlado

Os modelos Revit RFA são armazenados como um [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (também chamado CFBF). O modelo serializado fica em um storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Layout principal de `Global\Latest` (observado no Revit 2025):

- Cabeçalho
- Payload comprimido com GZIP (o grafo de objetos serializado propriamente dito)
- Preenchimento com zeros
- Trailer de código de correção de erros (ECC)

O Revit repara automaticamente pequenas alterações no stream usando o trailer ECC e rejeita streams que não correspondem ao ECC. Portanto, editar os bytes comprimidos de forma ingênua não fará com que as alterações persistam: elas serão revertidas ou o arquivo será rejeitado. Para garantir controle byte a byte sobre o que o desserializador recebe, é necessário:<sup>[[1]](#references)</sup>

- Recomprimir usando uma implementação de gzip compatível com o Revit (para que os bytes comprimidos produzidos/aceitos pelo Revit correspondam ao que ele espera).
- Recalcular o trailer ECC sobre o stream preenchido, para que o Revit aceite o stream modificado sem repará-lo automaticamente.

Fluxo de trabalho prático para aplicar patches/testar por fuzzing o conteúdo de RFA:<sup>[[1]](#references)</sup>

1) Expandir o documento composto OLE.<sup>[[2]](#references)</sup>

```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```

2) Edite `Global/Latest` seguindo as regras de gzip/ECC

- Desmonte `Global/Latest`: mantenha o cabeçalho, descompacte o payload com gunzip, altere os bytes e compacte novamente com gzip usando parâmetros deflate compatíveis com o Revit.
- Preserve o preenchimento com zeros e recalcule o trailer ECC para que o Revit aceite os novos bytes.
- Se precisar de uma reprodução determinística byte a byte, crie um wrapper mínimo em torno das DLLs do Revit para invocar os caminhos de gzip/gunzip e o cálculo de ECC (conforme demonstrado na pesquisa) ou reutilize um helper disponível que replique essas semânticas.

3) Reconstrua o documento composto OLE.<sup>[[2]](#references)</sup>

```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```

Notas:<sup>[[1]](#references)[[2]](#references)</sup>

- O CompoundFileTool grava storages/streams no sistema de arquivos, escapando caracteres inválidos em nomes do NTFS; o caminho do stream desejado é exatamente `Global/Latest` na árvore de saída.
- Ao entregar ataques em massa por meio de plugins do ecossistema que buscam RFAs no armazenamento em nuvem, verifique primeiro se o RFA corrigido passa localmente pelas verificações de integridade do Revit (gzip/ECC corretos), antes de tentar a injeção na rede.

Insight de exploração (para orientar quais bytes colocar no payload gzip):<sup>[[1]](#references)</sup>

- O desserializador do Revit lê um índice de classe de 16 bits e constrói um objeto. Alguns tipos não são polimórficos e não têm vtables; abusar do tratamento do destrutor gera uma type confusion, fazendo com que o engine execute uma chamada indireta por meio de um ponteiro controlado pelo atacante.
- Escolher `AString` (índice de classe `0x1F`) coloca um ponteiro de heap controlado pelo atacante no offset 0 do objeto. Durante o loop do destrutor, o Revit efetivamente executa:

```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```

- Coloque vários desses objetos no grafo serializado para que cada iteração do loop do destrutor execute um gadget (“weird machine”) e organize um stack pivot para uma cadeia ROP x64 convencional.

Veja aqui os detalhes sobre pivot/gadget em Windows x64:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

e aqui as orientações gerais sobre ROP:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Ferramentas:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) para expandir/reconstruir arquivos compostos OLE: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD para engenharia reversa/taint; desative o page heap com TTD para manter os traces compactos.
- Um proxy local (por exemplo, Fiddler) pode simular a entrega pela cadeia de suprimentos, substituindo RFAs no tráfego do plugin durante os testes.

## References

- [1] [Criando um exploit RCE completo a partir de um crash na análise de arquivos RFA do Autodesk Revit (blog da ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Documentação de arquivos compostos OLE (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Guia de campo de CTF de forense](https://trailofbits.github.io/ctf/forensics/)
- [5] [Documentação do olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Macros automáticas (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Evento Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
