# Análise de arquivos PDF

**Para mais detalhes, consulte:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

O formato PDF é conhecido por sua complexidade e pelo potencial de ocultar dados, tornando-se um foco de desafios de forensics em CTF. Ele combina elementos de texto simples com objetos binários, que podem ser comprimidos ou criptografados, e pode incluir scripts em linguagens como JavaScript ou Flash. Para entender a estrutura de PDFs, é possível consultar o [material introdutório](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) de Didier Stevens ou usar ferramentas como um editor de texto ou um editor específico para PDF, como o Origami.

Para uma exploração ou manipulação aprofundada de PDFs, estão disponíveis ferramentas como [qpdf](https://github.com/qpdf/qpdf) e [Origami](https://github.com/mobmewireless/origami-pdf). Dados ocultos em PDFs podem estar escondidos em:

- Camadas invisíveis
- Formato de metadata XMP da Adobe
- Gerações incrementais
- Texto com a mesma cor do plano de fundo
- Texto atrás de imagens ou imagens sobrepostas
- Comentários não exibidos

Para análises personalizadas de PDFs, bibliotecas Python como o [PeepDF](https://github.com/jesparza/peepdf) podem ser usadas para criar scripts de parsing sob medida. Além disso, o potencial dos PDFs para armazenar dados ocultos é tão amplo que recursos como o guia da NSA sobre riscos e contramedidas em PDFs, embora não esteja mais hospedado em seu local original, ainda oferecem informações valiosas. Uma [cópia do guia](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) e uma coleção de [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) de Ange Albertini podem fornecer material adicional sobre o assunto.<sup>[[4]](#references)[[5]](#references)</sup>

## Construtos maliciosos comuns

Attackers frequentemente abusam de objetos e ações específicos de PDF que são executados automaticamente quando o documento é aberto ou quando há interação com ele. Vale procurar pelas seguintes keywords:

* **/OpenAction, /AA** – ações automáticas executadas na abertura ou em eventos específicos.
* **/JS, /JavaScript** – JavaScript incorporado (frequentemente ofuscado ou dividido entre objetos).
* **/Launch, /SubmitForm, /URI, /GoToE** – launchers de processos externos / URLs.
* **/RichMedia, /Flash, /3D** – objetos multimídia que podem ocultar payloads.
* **/EmbeddedFile /Filespec** – anexos de arquivos (EXE, DLL, OLE etc.).
* **/ObjStm, /XFA, /AcroForm** – streams de objetos ou formulários comumente abusados para ocultar shell-code.
* **Atualizações incrementais** – vários marcadores %%EOF ou um offset **/Prev** muito grande podem indicar dados anexados após a assinatura para contornar o AV.

Quando algum dos tokens anteriores aparecer junto com strings suspeitas (powershell, cmd.exe, calc.exe, base64 etc.), o PDF merece uma análise mais aprofundada.

---

## Guia rápido de análise estática

Os exemplos abaixo usam as interfaces de linha de comando documentadas do `pdf-parser.py`, qpdf e pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – pass supported streams through their declared filters
pdf-parser.py -f suspicious.pdf
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
* **pdfcpu** – biblioteca/CLI em Go capaz de validar, descriptografar, extrair, otimizar e manipular PDFs.<sup>[[9]](#references)</sup>
* **pdf-inspector** – visualizador baseado em navegador que renderiza o grafo de objetos e os streams.
* **PyMuPDF** – bindings scriptáveis de Python para inspecionar PDFs e renderizar páginas como imagens rasterizadas. Trate o parser/renderer como uma attack surface de arquivos não confiáveis e execute-o dentro de um ambiente de análise devidamente isolado.<sup>[[8]](#references)</sup>

---

## Técnicas de ataque recentes (2023-2025)

* **MalDoc in PDF polyglot (2023)** – a JPCERT/CC relatou uma técnica que anexa um arquivo MHT criado pelo Word, com macros VBA, a um PDF, mantendo o PDF magic e permitindo também a abertura no Word. Ferramentas de análise exclusivas para PDF, sandboxes ou antivírus podem não detectar a macro porque o comportamento malicioso ocorre quando o arquivo é aberto como Word; procure o marcador `<w:WordDocument>` junto com outros indicadores de MHT.<sup>[[2]](#references)</sup>
* **Shadow attacks on signed PDFs** – attackers podem inserir conteúdo oculto em um PDF antes de ele ser assinado e, em seguida, anexar uma incremental update que altera as referências do catalog ou dos objetos, fazendo com que os visualizadores exibam o conteúdo oculto enquanto a assinatura original permanece válida. A técnica pode escapar de visualizadores que classificam essas atualizações como inofensivas.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – a Adobe classifica essa vulnerabilidade crítica como um use-after-free que pode levar à execução arbitrária de código; o APSB24-29 foi publicado em 14 de maio de 2024.<sup>[[3]](#references)</sup>

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

1. **Aplique patches rapidamente** – mantenha o Acrobat/Reader no canal Continuous mais recente; a maioria das cadeias de RCE observadas na natureza explora vulnerabilidades n-day corrigidas meses antes.
2. **Remova conteúdo ativo no gateway** – use um sanitizer desenvolvido especificamente para esse fim e controlado por políticas, ou um produto CDR que remova explicitamente JavaScript, arquivos incorporados, ações de inicialização, formulários e conteúdo multimídia. `qpdf --qdf` facilita a inspeção dos objetos PDF, enquanto o pdfcpu oferece recursos de validação e manipulação; nenhum dos dois comandos, isoladamente, comprova que o conteúdo ativo foi removido.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – converta PDFs em imagens (ou PDF/A) em um host sandbox para preservar a fidelidade visual e descartar objetos ativos.
4. **Bloqueie recursos raramente usados** – as configurações corporativas de “Enhanced Security” no Reader permitem desativar JavaScript, conteúdo multimídia e renderização 3D.
5. **Educação dos usuários** – a engenharia social (iscas com faturas e currículos) continua sendo o vetor inicial; ensine os funcionários a encaminhar anexos suspeitos para a equipe de IR.

## References

- [1] [Guia de campo de Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Bypass de detecção ao incorporar um arquivo Word malicioso em um arquivo PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Boletim de segurança da Adobe – Atualização de segurança disponível para Adobe Acrobat e Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - cópia do guia](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - truques do formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: Ocultando e substituindo conteúdo em PDFs assinados](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [Tutorial do PyMuPDF](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Opções de linha de comando do qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
