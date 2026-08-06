# Analiza plików PDF

{{#include ../../../banners/hacktricks-training.md}}

**Szczegółowe informacje znajdziesz tutaj:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

Format PDF jest znany ze swojej złożoności i możliwości ukrywania danych, co czyni go częstym przedmiotem wyzwań forensics w CTF. Łączy elementy zwykłego tekstu z obiektami binarnymi, które mogą być skompresowane lub zaszyfrowane, a także może zawierać skrypty w językach takich jak JavaScript lub Flash. Aby zrozumieć strukturę PDF, można zapoznać się z [materiałem wprowadzającym](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) Didiera Stevensa albo użyć narzędzi takich jak edytor tekstu lub edytor przeznaczony do plików PDF, np. Origami.

Do szczegółowego badania lub modyfikowania plików PDF dostępne są narzędzia takie jak [qpdf](https://github.com/qpdf/qpdf) i [Origami](https://github.com/mobmewireless/origami-pdf). Ukryte dane w plikach PDF mogą znajdować się w:

- Niewidocznych warstwach
- Formacie metadanych XMP firmy Adobe
- Generacjach przyrostowych
- Tekście w tym samym kolorze co tło
- Tekście znajdującym się za obrazami lub nakładających się obrazach
- Niewyświetlanych komentarzach

Do niestandardowej analizy plików PDF można użyć bibliotek Python, takich jak [PeepDF](https://github.com/jesparza/peepdf), aby tworzyć dedykowane skrypty do parsowania. Możliwości ukrywania danych w plikach PDF są tak rozległe, że nawet materiały takie jak przewodnik NSA dotyczący zagrożeń i środków zaradczych dla PDF, choć nie jest już hostowany w pierwotnej lokalizacji, nadal dostarczają cennych informacji. [Kopia przewodnika](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) oraz zbiór [tricków dotyczących formatu PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) autorstwa Ange Albertiniego mogą stanowić dodatkowe materiały do lektury.

## Common Malicious Constructs

Atakujący często nadużywają określonych obiektów i akcji PDF, które są automatycznie wykonywane po otwarciu dokumentu lub wejściu z nim w interakcję. Warto wyszukiwać następujące słowa kluczowe:

* **/OpenAction, /AA** – automatyczne akcje wykonywane przy otwarciu lub w odpowiedzi na określone zdarzenia.
* **/JS, /JavaScript** – osadzony JavaScript (często zaciemniony lub podzielony między wiele obiektów).
* **/Launch, /SubmitForm, /URI, /GoToE** – mechanizmy uruchamiające zewnętrzne procesy lub adresy URL.
* **/RichMedia, /Flash, /3D** – obiekty multimedialne, w których można ukryć payloady.
* **/EmbeddedFile /Filespec** – załączniki plików (EXE, DLL, OLE itd.).
* **/ObjStm, /XFA, /AcroForm** – strumienie obiektów lub formularze często wykorzystywane do ukrywania shell-code.
* **Aktualizacje przyrostowe** – wiele znaczników %%EOF lub bardzo duży offset **/Prev** może wskazywać na dane dołączone po podpisaniu w celu ominięcia AV.

Gdy którykolwiek z powyższych tokenów występuje razem z podejrzanymi ciągami (powershell, cmd.exe, calc.exe, base64 itd.), plik PDF zasługuje na dokładniejszą analizę.

---

## Ściąga do analizy statycznej
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
Dodatkowe przydatne projekty (aktywnie utrzymywane w latach 2023–2025):
* **pdfcpu** – biblioteka/CLI w Go umożliwiająca *lintowanie*, *deszyfrowanie*, *ekstrakcję*, *kompresję* i *sanityzację* plików PDF.
* **pdf-inspector** – wizualizator działający w przeglądarce, który renderuje graf obiektów i streamy.
* **PyMuPDF (fitz)** – skryptowalny silnik Python, który może bezpiecznie renderować strony do obrazów, aby uruchamiać osadzony JS w utwardzonym sandboxie.

---

## Najnowsze techniki ataków (2023–2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC zaobserwował threat actors dołączających dokument Word oparty na MHT, zawierający makra VBA, za końcowym **%%EOF**, tworząc plik będący jednocześnie prawidłowym PDF-em i prawidłowym DOC. Silniki AV analizujące wyłącznie warstwę PDF pomijają makro. Statyczne keywords PDF są czyste, ale `file` nadal wyświetla `%PDF`. Każdy PDF zawierający również ciąg znaków `<w:WordDocument>` należy traktować jako wysoce podejrzany.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversaries wykorzystują funkcję incremental update do wstawienia drugiego **/Catalog** ze złośliwym `/OpenAction`, zachowując jednocześnie podpisaną, benign pierwszą rewizję. Narzędzia sprawdzające wyłącznie pierwszą tabelę xref są omijane.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – podatna funkcja **CoolType.dll** może zostać osiągnięta za pośrednictwem osadzonych fontów CIDType2, umożliwiając remote code execution z uprawnieniami użytkownika po otwarciu spreparowanego dokumentu. Załatano w APSB24-29 w maju 2024 r.<sup>[[3]](#references)</sup>

---

## Szablon szybkiej reguły YARA
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

## Wskazówki dotyczące obrony

1. **Szybko instaluj poprawki** – utrzymuj Acrobat/Reader na najnowszym kanale Continuous; większość łańcuchów RCE obserwowanych w środowisku naturalnym wykorzystuje luki typu n-day, które zostały załatane kilka miesięcy wcześniej.
2. **Usuwaj aktywną zawartość na gatewayu** – używaj `pdfcpu sanitize` lub `qpdf --qdf --remove-unreferenced`, aby usuwać JavaScript, osadzone pliki i akcje uruchamiania z przychodzących plików PDF.
3. **Content Disarm & Reconstruction (CDR)** – konwertuj pliki PDF do obrazów (lub PDF/A) na hoście sandboxowym, aby zachować wierność wizualną i jednocześnie usuwać aktywne obiekty.
4. **Blokuj rzadko używane funkcje** – ustawienia „Enhanced Security” w Readerze pozwalają wyłączyć JavaScript, multimedia i renderowanie 3D.
5. **Edukacja użytkowników** – social engineering (przynęty w postaci faktur i CV) nadal pozostaje początkowym wektorem ataku; ucz pracowników przekazywania podejrzanych załączników do zespołu IR.

## Referencje

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – obejście detekcji poprzez osadzenie złośliwego pliku Word w pliku PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – dostępna aktualizacja bezpieczeństwa dla Adobe Acrobat i Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)

{{#include ../../../banners/hacktricks-training.md}}
