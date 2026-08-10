# Analiza plików PDF

**Więcej informacji znajdziesz tutaj:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Format PDF jest znany ze swojej złożoności i możliwości ukrywania danych, co czyni go częstym celem wyzwań CTF z zakresu forensics. Łączy elementy tekstowe z obiektami binarnymi, które mogą być skompresowane lub zaszyfrowane, a także może zawierać skrypty w językach takich jak JavaScript lub Flash. Aby zrozumieć strukturę PDF, można zapoznać się z [materiałem wprowadzającym](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) Didiera Stevensa albo użyć narzędzi takich jak edytor tekstu lub specjalistyczny edytor PDF, np. Origami.

Do szczegółowej analizy lub modyfikowania plików PDF dostępne są narzędzia takie jak [qpdf](https://github.com/qpdf/qpdf) i [Origami](https://github.com/mobmewireless/origami-pdf). Ukryte dane w plikach PDF mogą znajdować się w:

- Niewidocznych warstwach
- Formacie metadanych XMP firmy Adobe
- Generacjach przyrostowych
- Tekście w tym samym kolorze co tło
- Tekście znajdującym się za obrazami lub nakładającymi się obrazami
- Niewyświetlanych komentarzach

Do niestandardowej analizy plików PDF można użyć bibliotek Python, takich jak [PeepDF](https://github.com/jesparza/peepdf), aby tworzyć niestandardowe skrypty parsujące. Ponadto możliwości ukrywania danych w plikach PDF są tak szerokie, że materiały takie jak przewodnik NSA dotyczący zagrożeń i środków zaradczych dla PDF, choć nie jest już hostowany w swojej pierwotnej lokalizacji, nadal dostarczają cennych informacji. [Kopia przewodnika](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) oraz zbiór [trików dotyczących formatu PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) autorstwa Ange Albertiniego mogą posłużyć jako dalsze materiały do lektury na ten temat.<sup>[[4]](#references)[[5]](#references)</sup>

## Common Malicious Constructs

Atakujący często nadużywają określonych obiektów i akcji PDF, które są automatycznie wykonywane po otwarciu dokumentu lub wejściu z nim w interakcję. Warto wyszukiwać następujące słowa kluczowe:

* **/OpenAction, /AA** – automatyczne akcje wykonywane przy otwarciu lub w reakcji na określone zdarzenia.
* **/JS, /JavaScript** – osadzony JavaScript (często obfuskowany lub podzielony między obiekty).
* **/Launch, /SubmitForm, /URI, /GoToE** – mechanizmy uruchamiania zewnętrznych procesów / adresów URL.
* **/RichMedia, /Flash, /3D** – obiekty multimedialne, które mogą ukrywać payloady.
* **/EmbeddedFile /Filespec** – załączniki plików (EXE, DLL, OLE itd.).
* **/ObjStm, /XFA, /AcroForm** – strumienie obiektów lub formularze często wykorzystywane do ukrywania shell-code.
* **Aktualizacje przyrostowe** – wiele znaczników %%EOF lub bardzo duży offset **/Prev** może wskazywać na dane dołączone po podpisaniu w celu ominięcia AV.

Gdy którykolwiek z powyższych tokenów występuje razem z podejrzanymi ciągami znaków (powershell, cmd.exe, calc.exe, base64 itd.), plik PDF wymaga dokładniejszej analizy.

---

## Ściągawka do analizy statycznej

Poniższe przykłady korzystają z udokumentowanych interfejsów wiersza poleceń `pdf-parser.py`, qpdf i pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
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
Dodatkowe przydatne projekty (aktywnie utrzymywane w latach 2023–2025):
* **pdfcpu** – biblioteka/CLI w Go umożliwiająca walidowanie, odszyfrowywanie, ekstrakcję, optymalizację i modyfikowanie plików PDF.<sup>[[9]](#references)</sup>
* **pdf-inspector** – wizualizator działający w przeglądarce, który renderuje graf obiektów i strumienie.
* **PyMuPDF** – możliwe do skryptowania Python bindings do inspekcji plików PDF i renderowania stron do obrazów rastrowych. Parser/renderer należy traktować jako attack surface w przypadku niezaufanych plików i uruchamiać go w odpowiednio odizolowanym środowisku analitycznym.<sup>[[8]](#references)</sup>

---

## Najnowsze techniki ataków (2023–2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC poinformował o technice, która dołącza plik MHT utworzony przez Worda i zawierający makra VBA do pliku PDF, zachowując magiczne bajty PDF, a jednocześnie umożliwiając otwarcie pliku w Wordzie. Narzędzia do analizy wyłącznie plików PDF, sandboxy lub antywirusy mogą nie wykryć makra, ponieważ złośliwe działanie występuje po otwarciu pliku w Wordzie; należy szukać znacznika `<w:WordDocument>` wraz z innymi wskaźnikami MHT.<sup>[[2]](#references)</sup>
* **Shadow attacks on signed PDFs** – atakujący mogą umieścić ukrytą zawartość w pliku PDF przed jego podpisaniem, a następnie dołączyć incremental update, który zmienia odwołania do katalogu lub obiektów, tak aby przeglądarki wyświetlały ukrytą zawartość, podczas gdy oryginalny podpis pozostaje ważny. Technika ta może omijać zabezpieczenia przeglądarek, które klasyfikują takie aktualizacje jako nieszkodliwe.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe ocenia tę krytyczną lukę jako use-after-free, która może prowadzić do wykonania dowolnego kodu; APSB24-29 opublikowano 14 maja 2024 r.<sup>[[3]](#references)</sup>

---

## Szybki szablon reguły YARA
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

## Wskazówki dotyczące ochrony

1. **Szybko instaluj poprawki** – utrzymuj Acrobat/Reader na najnowszym kanale Continuous; większość łańcuchów RCE obserwowanych w środowisku naturalnym wykorzystuje podatności n-day, które zostały załatane kilka miesięcy wcześniej.
2. **Usuwaj aktywną zawartość na gatewayu** – używaj specjalizowanego, kontrolowanego przez polityki sanitizera lub produktu CDR, który jawnie usuwa JavaScript, osadzone pliki, akcje uruchamiania, formularze i multimedia. `qpdf --qdf` ułatwia inspekcję obiektów PDF, a pdfcpu udostępnia funkcje walidacji i modyfikacji; żadna z tych komend użyta samodzielnie nie stanowi dowodu, że aktywna zawartość została usunięta.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – konwertuj pliki PDF do obrazów (lub PDF/A) na hoście sandboxowym, aby zachować wierność wizualną i jednocześnie usunąć aktywne obiekty.
4. **Blokuj rzadko używane funkcje** – ustawienia „Enhanced Security” w Readerze dla środowisk enterprise umożliwiają wyłączenie JavaScript, multimediów i renderowania 3D.
5. **Edukacja użytkowników** – inżynieria społeczna (przynęty w postaci faktur i CV) nadal pozostaje początkowym wektorem ataku; naucz pracowników przekazywania podejrzanych załączników do zespołu IR.

## References

- [1] [Przewodnik terenowy Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – omijanie detekcji poprzez osadzenie złośliwego pliku Word w pliku PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Biuletyn bezpieczeństwa Adobe – dostępna aktualizacja zabezpieczeń dla Adobe Acrobat i Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - kopia przewodnika](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - sztuczki dotyczące formatu PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: ukrywanie i zastępowanie treści w podpisanych plikach PDF](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [Samouczek PyMuPDF](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Opcje wiersza poleceń qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
