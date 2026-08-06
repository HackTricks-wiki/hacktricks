# Análise de arquivos PDF

{{#include ../../../banners/hacktricks-training.md}}

**Para mais detalhes, consulte:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

O formato PDF é conhecido por sua complexidade e pelo potencial de ocultar dados, tornando-se um foco frequente em desafios de forensics de CTF. Ele combina elementos de texto simples com objetos binários, que podem ser comprimidos ou criptografados, e pode incluir scripts em linguagens como JavaScript ou Flash. Para entender a estrutura de um PDF, é possível consultar o [material introdutório](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) de Didier Stevens ou usar ferramentas como um editor de texto ou um editor específico para PDF, como o Origami.

Para uma exploração aprofundada ou manipulação de PDFs, estão disponíveis ferramentas como [qpdf](https://github.com/qpdf/qpdf) e [Origami](https://github.com/mobmewireless/origami-pdf). Dados ocultos em PDFs podem estar escondidos em:

- Camadas invisíveis
- Formato de metadados XMP da Adobe
- Gerações incrementais
- Texto com a mesma cor do plano de fundo
- Texto atrás de imagens ou imagens sobrepostas
- Comentários não exibidos

Para análises personalizadas de PDF, bibliotecas Python como [PeepDF](https://github.com/jesparza/peepdf) podem ser usadas para criar scripts de parsing sob medida. Além disso, o potencial dos PDFs para armazenar dados ocultos é tão amplo que recursos como o guia da NSA sobre riscos e contramedidas de PDF, embora não esteja mais hospedado em sua localização original, ainda oferecem informações valiosas. Uma [cópia do guia](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) e uma coleção de [tricks de formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) de Ange Albertini podem fornecer material adicional sobre o assunto.<sup>[[4]](#references)[[5]](#references)</sup>

## Construtos maliciosos comuns

Atacantes frequentemente abusam de objetos e ações específicas de PDF que são executados automaticamente quando o documento é aberto ou quando há interação com ele. Vale procurar pelas seguintes keywords:

* **/OpenAction, /AA** – ações automáticas executadas ao abrir ou em eventos específicos.
* **/JS, /JavaScript** – JavaScript incorporado (frequentemente ofuscado ou dividido entre objetos).
* **/Launch, /SubmitForm, /URI, /GoToE** – launchers de processos externos / URLs.
* **/RichMedia, /Flash, /3D** – objetos multimídia que podem ocultar payloads.
* **/EmbeddedFile /Filespec** – anexos de arquivos (EXE, DLL, OLE etc.).
* **/ObjStm, /XFA, /AcroForm** – object streams ou formulários frequentemente abusados para ocultar shell-code.
* **Atualizações incrementais** – vários marcadores `%%EOF` ou um offset **/Prev** muito grande podem indicar dados anexados após a assinatura para contornar o AV.

Quando qualquer um dos tokens anteriores aparecer junto com strings suspeitas (powershell, cmd.exe, calc.exe, base64 etc.), o PDF merece uma análise mais aprofundada.

---

## Cheat-sheet de análise estática
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
Projetos adicionais úteis (mantidos ativamente em 2023-2025):
* **pdfcpu** – biblioteca/CLI Go capaz de fazer *lint*, *decrypt*, *extract*, *compress* e *sanitize* de PDFs.
* **pdf-inspector** – visualizador baseado em navegador que renderiza o grafo de objetos e os streams.
* **PyMuPDF (fitz)** – engine Python scriptable que pode renderizar páginas com segurança para imagens e detonar JavaScript incorporado em um sandbox reforçado.

---

## Técnicas de ataque recentes (2023-2025)

* **MalDoc in PDF polyglot (2023)** – a JPCERT/CC observou threat actors anexando um documento Word baseado em MHT com macros VBA após o **%%EOF** final, produzindo um arquivo que é simultaneamente um PDF válido e um DOC válido. Mecanismos de AV que analisam apenas a camada PDF não detectam a macro. As keywords estáticas do PDF permanecem limpas, mas `file` ainda exibe `%PDF`. Trate qualquer PDF que também contenha a string `<w:WordDocument>` como altamente suspeito.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversários abusam do recurso de atualização incremental para inserir um segundo **/Catalog** com um `/OpenAction` malicioso, mantendo assinada a primeira revisão benigna. Ferramentas que inspecionam apenas a primeira tabela xref são contornadas.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – uma função vulnerável da **CoolType.dll** pode ser alcançada a partir de fontes CIDType2 incorporadas, permitindo execução remota de código com os privilégios do usuário assim que um documento criado para esse fim é aberto. Corrigido no APSB24-29, em maio de 2024.<sup>[[3]](#references)</sup>

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

## Dicas de defesa

1. **Aplique patches rapidamente** – mantenha o Acrobat/Reader na versão mais recente do canal Continuous; a maioria das cadeias de RCE observadas em ataques reais explora vulnerabilidades n-day corrigidas meses antes.
2. **Remova conteúdo ativo no gateway** – use `pdfcpu sanitize` ou `qpdf --qdf --remove-unreferenced` para remover JavaScript, arquivos incorporados e ações de inicialização dos PDFs recebidos.
3. **Content Disarm & Reconstruction (CDR)** – converta PDFs em imagens (ou PDF/A) em um host sandbox para preservar a fidelidade visual e descartar objetos ativos.
4. **Bloqueie recursos raramente usados** – as configurações corporativas de “Enhanced Security” no Reader permitem desativar JavaScript, multimídia e renderização 3D.
5. **Educação dos usuários** – a engenharia social (iscas com faturas e currículos) continua sendo o vetor inicial; ensine os funcionários a encaminhar anexos suspeitos para a equipe de IR.

## Referências

- [1] [Guia de campo de Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Bypass de detecção por meio da incorporação de um arquivo Word malicioso em um arquivo PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Boletim de segurança da Adobe – Atualização de segurança disponível para Adobe Acrobat e Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - cópia do guia](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - truques do formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)

{{#include ../../../banners/hacktricks-training.md}}
