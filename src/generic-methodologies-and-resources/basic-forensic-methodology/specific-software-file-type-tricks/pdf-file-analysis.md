# Análise de arquivos PDF

{{#include ../../../banners/hacktricks-training.md}}

**Para mais detalhes, consulte:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

O formato PDF é conhecido por sua complexidade e pelo potencial de ocultar dados, tornando-se um foco comum em desafios de forensics de CTF. Ele combina elementos de texto simples com objetos binários, que podem ser comprimidos ou criptografados, e pode incluir scripts em linguagens como JavaScript ou Flash. Para entender a estrutura de um PDF, é possível consultar o [material introdutório](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) de Didier Stevens ou usar ferramentas como um editor de texto ou um editor específico para PDF, como o Origami.

Para explorar ou manipular PDFs em profundidade, estão disponíveis ferramentas como [qpdf](https://github.com/qpdf/qpdf) e [Origami](https://github.com/mobmewireless/origami-pdf). Dados ocultos em PDFs podem estar escondidos em:

- Camadas invisíveis
- Formato de metadados XMP da Adobe
- Gerações incrementais
- Texto com a mesma cor do plano de fundo
- Texto atrás de imagens ou imagens sobrepostas
- Comentários não exibidos

Para análises personalizadas de PDF, bibliotecas Python como o [PeepDF](https://github.com/jesparza/peepdf) podem ser usadas para criar scripts de parsing específicos. Além disso, o potencial dos PDFs para armazenar dados ocultos é tão amplo que recursos como o guia da NSA sobre riscos e contramedidas em PDFs, embora não esteja mais hospedado em seu local original, ainda oferecem informações valiosas. Uma [cópia do guia](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) e uma coleção de [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) de Ange Albertini podem fornecer material adicional sobre o assunto.

## Construtos maliciosos comuns

Attackers frequentemente abusam de objetos e ações específicos de PDF que são executados automaticamente quando o documento é aberto ou quando há interação com ele. Palavras-chave que vale a pena procurar:

* **/OpenAction, /AA** – ações automáticas executadas na abertura ou em eventos específicos.
* **/JS, /JavaScript** – JavaScript incorporado (frequentemente ofuscado ou dividido entre objetos).
* **/Launch, /SubmitForm, /URI, /GoToE** – launchers de processos externos / URLs.
* **/RichMedia, /Flash, /3D** – objetos multimídia que podem ocultar payloads.
* **/EmbeddedFile /Filespec** – anexos de arquivos (EXE, DLL, OLE etc.).
* **/ObjStm, /XFA, /AcroForm** – object streams ou formulários frequentemente abusados para ocultar shell-code.
* **Atualizações incrementais** – vários marcadores %%EOF ou um offset **/Prev** muito grande podem indicar dados anexados após a assinatura para contornar o AV.

Quando algum dos tokens anteriores aparece junto com strings suspeitas (powershell, cmd.exe, calc.exe, base64 etc.), o PDF merece uma análise mais aprofundada.

---

## Guia rápido de análise estática
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – decompress/inspect the object tree
pdf-parser.py -f suspicious.pdf                # interactive
pdf-parser.py -a suspicious.pdf                # automatic report

# Search for JavaScript and pretty-print it
pdf-parser.py -search "/JS" -raw suspicious.pdf | js-beautify -

# Dump embedded files
peepdf "open suspicious.pdf" "objects embeddedfile" "extract 15 16 17" -o dumps/

# Remove passwords / encryptions before processing with other tools
qpdf --password='secret' --decrypt suspicious.pdf clean.pdf

# Lint the file with a Go verifier (checks structure violations)
pdfcpu validate -mode strict clean.pdf
```
Additional useful projects (actively maintained 2023-2025):
* **pdfcpu** – biblioteca/CLI Go capaz de fazer *lint*, *decrypt*, *extract*, *compress* e *sanitize* de PDFs.
* **pdf-inspector** – visualizador baseado em navegador que renderiza o grafo de objetos e os streams.
* **PyMuPDF (fitz)** – engine Python scriptable que pode renderizar páginas com segurança em imagens para detonar JavaScript incorporado em um sandbox reforçado.

---

## Técnicas de ataque recentes (2023-2025)

* **MalDoc in PDF polyglot (2023)** – a JPCERT/CC observou agentes de ameaça anexando um documento Word baseado em MHT com macros VBA após o **%%EOF** final, produzindo um arquivo que é simultaneamente um PDF válido e um DOC válido. Mecanismos AV que analisam apenas a camada PDF não detectam a macro. As palavras-chave estáticas do PDF permanecem limpas, mas `file` ainda exibe `%PDF`. Trate qualquer PDF que também contenha a string `<w:WordDocument>` como altamente suspeito.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversários abusam do recurso de atualização incremental para inserir um segundo **/Catalog** com um `/OpenAction` malicioso, mantendo assinada a primeira revisão benigna. Ferramentas que inspecionam apenas a primeira tabela xref são contornadas.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – uma função vulnerável de **CoolType.dll** pode ser alcançada por meio de fontes CIDType2 incorporadas, permitindo execução remota de código com os privilégios do usuário assim que um documento criado de forma maliciosa é aberto. Corrigido no APSB24-29, em maio de 2024.<sup>[[3]](#references)</sup>

---

## Modelo rápido de regra YARA
```yara
rule Suspicious_PDF_AutoExec {
meta:
description = "Generic detection of PDFs with auto-exec actions and JS"
author      = "HackTricks"
last_update = "2025-07-20"
strings:
$pdf_magic = { 25 50 44 46 }          // %PDF
$aa        = "/AA" ascii nocase
$openact   = "/OpenAction" ascii nocase
$js        = "/JS" ascii nocase
condition:
$pdf_magic at 0 and ( all of ($aa, $openact) or ($openact and $js) )
}
```
---

## Dicas defensivas

1. **Aplique patches rapidamente** – mantenha o Acrobat/Reader no Continuous track mais recente; a maioria das cadeias de RCE observadas in the wild explora vulnerabilidades n-day corrigidas meses antes.
2. **Remova active content no gateway** – use `pdfcpu sanitize` ou `qpdf --qdf --remove-unreferenced` para remover JavaScript, arquivos incorporados e ações de inicialização dos PDFs recebidos.
3. **Content Disarm & Reconstruction (CDR)** – converta PDFs em imagens (ou PDF/A) em um host sandbox para preservar a fidelidade visual enquanto descarta objetos ativos.
4. **Bloqueie recursos raramente usados** – as configurações empresariais de “Enhanced Security” no Reader permitem desativar JavaScript, multimídia e renderização 3D.
5. **Educação dos usuários** – social engineering (iscas com faturas e currículos) continua sendo o vetor inicial; ensine os funcionários a encaminhar anexos suspeitos para o IR.

## Referências

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Bypass de detecção ao incorporar um arquivo Word malicioso em um arquivo PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Atualização de segurança disponível para Adobe Acrobat e Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)

{{#include ../../../banners/hacktricks-training.md}}
