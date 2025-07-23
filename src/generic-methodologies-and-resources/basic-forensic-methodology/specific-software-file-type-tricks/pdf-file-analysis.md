# Análise de Arquivos PDF

{{#include ../../../banners/hacktricks-training.md}}

**Para mais detalhes, consulte:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

O formato PDF é conhecido por sua complexidade e potencial para ocultar dados, tornando-se um ponto focal para desafios de forense em CTF. Ele combina elementos de texto simples com objetos binários, que podem ser comprimidos ou criptografados, e pode incluir scripts em linguagens como JavaScript ou Flash. Para entender a estrutura do PDF, pode-se consultar o [material introdutório de Didier Stevens](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/), ou usar ferramentas como um editor de texto ou um editor específico de PDF, como o Origami.

Para exploração ou manipulação aprofundada de PDFs, ferramentas como [qpdf](https://github.com/qpdf/qpdf) e [Origami](https://github.com/mobmewireless/origami-pdf) estão disponíveis. Dados ocultos dentro de PDFs podem estar escondidos em:

- Camadas invisíveis
- Formato de metadados XMP da Adobe
- Gerações incrementais
- Texto com a mesma cor do fundo
- Texto atrás de imagens ou imagens sobrepostas
- Comentários não exibidos

Para análise personalizada de PDF, bibliotecas Python como [PeepDF](https://github.com/jesparza/peepdf) podem ser usadas para criar scripts de parsing sob medida. Além disso, o potencial do PDF para armazenamento de dados ocultos é tão vasto que recursos como o guia da NSA sobre riscos e contramedidas de PDF, embora não esteja mais hospedado em sua localização original, ainda oferecem insights valiosos. Uma [cópia do guia](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) e uma coleção de [truques do formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) de Ange Albertini podem fornecer mais leitura sobre o assunto.

## Estruturas Maliciosas Comuns

Os atacantes frequentemente abusam de objetos e ações específicas do PDF que são executadas automaticamente quando o documento é aberto ou interagido. Palavras-chave que valem a pena serem procuradas:

* **/OpenAction, /AA** – ações automáticas executadas ao abrir ou em eventos específicos.
* **/JS, /JavaScript** – JavaScript embutido (frequentemente ofuscado ou dividido entre objetos).
* **/Launch, /SubmitForm, /URI, /GoToE** – lançadores de processos externos / URL.
* **/RichMedia, /Flash, /3D** – objetos multimídia que podem ocultar cargas úteis.
* **/EmbeddedFile /Filespec** – anexos de arquivos (EXE, DLL, OLE, etc.).
* **/ObjStm, /XFA, /AcroForm** – fluxos de objetos ou formulários comumente abusados para ocultar shell-code.
* **Atualizações incrementais** – múltiplos marcadores %%EOF ou um **/Prev** muito grande podem indicar dados anexados após a assinatura para contornar AV.

Quando qualquer um dos tokens anteriores aparece junto com strings suspeitas (powershell, cmd.exe, calc.exe, base64, etc.), o PDF merece uma análise mais profunda.

---

## Folha de dicas de análise estática
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
Projetos adicionais úteis (mantidos ativamente 2023-2025):
* **pdfcpu** – Biblioteca/CLI Go capaz de *lint*, *decrypt*, *extract*, *compress* e *sanitize* PDFs.
* **pdf-inspector** – Visualizador baseado em navegador que renderiza o gráfico de objetos e streams.
* **PyMuPDF (fitz)** – Motor Python scriptável que pode renderizar páginas em imagens de forma segura para detonar JS embutido em um sandbox reforçado.

---

## Técnicas de ataque recentes (2023-2025)

* **MalDoc em PDF polyglot (2023)** – JPCERT/CC observou atores de ameaça anexando um documento Word baseado em MHT com macros VBA após o final **%%EOF**, produzindo um arquivo que é tanto um PDF válido quanto um DOC válido. Motores AV que analisam apenas a camada PDF perdem a macro. Palavras-chave estáticas de PDF estão limpas, mas `file` ainda imprime `%PDF`. Trate qualquer PDF que também contenha a string `<w:WordDocument>` como altamente suspeito.
* **Atualizações incrementais de sombra (2024)** – adversários abusam do recurso de atualização incremental para inserir um segundo **/Catalog** com `/OpenAction` malicioso enquanto mantêm a primeira revisão benigna assinada. Ferramentas que inspecionam apenas a primeira tabela xref são contornadas.
* **Cadeia UAF de análise de fonte – CVE-2024-30284 (Acrobat/Reader)** – uma função vulnerável **CoolType.dll** pode ser acessada a partir de fontes CIDType2 embutidas, permitindo execução remota de código com os privilégios do usuário uma vez que um documento elaborado é aberto. Corrigido em APSB24-29, maio de 2024.

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

1. **Atualize rapidamente** – mantenha o Acrobat/Reader na versão mais recente; a maioria das cadeias de RCE observadas na natureza aproveita vulnerabilidades n-day corrigidas meses antes.
2. **Remova conteúdo ativo no gateway** – use `pdfcpu sanitize` ou `qpdf --qdf --remove-unreferenced` para eliminar JavaScript, arquivos incorporados e ações de lançamento de PDFs recebidos.
3. **Desarmamento e Reconstrução de Conteúdo (CDR)** – converta PDFs em imagens (ou PDF/A) em um host sandbox para preservar a fidelidade visual enquanto descarta objetos ativos.
4. **Bloqueie recursos raramente usados** – as configurações de “Segurança Aprimorada” da empresa no Reader permitem desativar JavaScript, multimídia e renderização 3D.
5. **Educação do usuário** – engenharia social (isca de fatura e currículo) continua sendo o vetor inicial; ensine os funcionários a encaminhar anexos suspeitos para a IR.

## Referências

* JPCERT/CC – “MalDoc em PDF – Bypass de detecção ao incorporar um arquivo Word malicioso em um arquivo PDF” (Ago 2023)
* Adobe – Atualização de segurança para Acrobat e Reader (APSB24-29, Mai 2024)


{{#include ../../../banners/hacktricks-training.md}}
