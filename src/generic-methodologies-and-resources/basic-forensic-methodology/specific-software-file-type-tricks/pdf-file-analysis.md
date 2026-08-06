# Analiza plików PDF

{{#include ../../../banners/hacktricks-training.md}}

**Więcej szczegółów znajdziesz tutaj:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

Format PDF jest znany ze swojej złożoności i możliwości ukrywania danych, co sprawia, że jest częstym przedmiotem wyzwań z zakresu CTF forensics. Łączy elementy tekstowe z obiektami binarnymi, które mogą być skompresowane lub zaszyfrowane, a także może zawierać skrypty w językach takich jak JavaScript lub Flash. Aby zrozumieć strukturę PDF, można zapoznać się z [materiałami wprowadzającymi](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) Didiera Stevensa albo użyć narzędzi takich jak edytor tekstu lub edytor przeznaczony do plików PDF, np. Origami.

Do szczegółowej analizy lub modyfikowania plików PDF można użyć narzędzi takich jak [qpdf](https://github.com/qpdf/qpdf) i [Origami](https://github.com/mobmewireless/origami-pdf). Ukryte dane w plikach PDF mogą znajdować się w:

- Niewidocznych warstwach
- Formacie metadanych XMP firmy Adobe
- Przyrostowych generacjach
- Tekście w kolorze takim samym jak tło
- Tekście znajdującym się za obrazami lub nachodzącymi na siebie obrazami
- Niewyświetlanych komentarzach

Do niestandardowej analizy PDF można użyć bibliotek Pythona, takich jak [PeepDF](https://github.com/jesparza/peepdf), aby tworzyć dedykowane skrypty do parsowania. Co więcej, możliwości ukrywania danych w plikach PDF są tak rozległe, że zasoby takie jak przewodnik NSA dotyczący zagrożeń i środków zaradczych związanych z PDF, mimo że nie jest już hostowany w pierwotnej lokalizacji, nadal dostarczają cennych informacji. [Kopia przewodnika](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) oraz zbiór [trików dotyczących formatu PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) autorstwa Ange Albertiniego mogą posłużyć jako dalsze materiały do lektury.<sup>[[4]](#references)[[5]](#references)</sup>

## Typowe złośliwe konstrukcje

Atakujący często nadużywają określonych obiektów i akcji PDF, które są automatycznie wykonywane po otwarciu dokumentu lub wejściu z nim w interakcję. Warto wyszukiwać następujące słowa kluczowe:

* **/OpenAction, /AA** – automatyczne akcje wykonywane przy otwarciu lub podczas określonych zdarzeń.
* **/JS, /JavaScript** – osadzony JavaScript (często zaciemniony lub podzielony między obiekty).
* **/Launch, /SubmitForm, /URI, /GoToE** – mechanizmy uruchamiania zewnętrznych procesów / URL.
* **/RichMedia, /Flash, /3D** – obiekty multimedialne, które mogą ukrywać payloady.
* **/EmbeddedFile /Filespec** – załączniki plików (EXE, DLL, OLE itd.).
* **/ObjStm, /XFA, /AcroForm** – strumienie obiektów lub formularze często wykorzystywane do ukrywania shell-code.
* **Aktualizacje przyrostowe** – wiele znaczników %%EOF lub bardzo duży offset **/Prev** może wskazywać na dane dołączone po podpisaniu dokumentu w celu obejścia AV.

Gdy którykolwiek z powyższych tokenów występuje wraz z podejrzanymi ciągami (powershell, cmd.exe, calc.exe, base64 itd.), plik PDF wymaga dokładniejszej analizy.

---

## Ściągawka do analizy statycznej
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
Additional useful projects (aktywnie utrzymywane w latach 2023-2025):
* **pdfcpu** – biblioteka/CLI w Go umożliwiająca *lintowanie*, *odszyfrowywanie*, *ekstrakcję*, *kompresję* i *sanityzację* plików PDF.
* **pdf-inspector** – oparty na przeglądarce wizualizer renderujący graf obiektów i streamy.
* **PyMuPDF (fitz)** – skryptowalny silnik Python, który może bezpiecznie renderować strony do obrazów, aby uruchamiać osadzony JS w utwardzonym sandboxie.

---

## Recent attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC zaobserwował threat actors dołączających dokument Word oparty na MHT, zawierający makra VBA, po końcowym **%%EOF**, tworząc plik będący jednocześnie prawidłowym PDF i prawidłowym DOC. Silniki AV analizujące tylko warstwę PDF pomijają makro. Statyczne keywords PDF są czyste, ale `file` nadal wyświetla `%PDF`. Każdy PDF zawierający również ciąg `<w:WordDocument>` należy uznać za wysoce podejrzany.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversaries wykorzystują funkcję aktualizacji inkrementalnych do wstawienia drugiego **/Catalog** ze złośliwym `/OpenAction`, zachowując jednocześnie prawidłowo podpisaną pierwszą rewizję. Narzędzia analizujące tylko pierwszą tabelę xref są omijane.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – podatna funkcja **CoolType.dll** może zostać osiągnięta z osadzonych fontów CIDType2, umożliwiając remote code execution z uprawnieniami użytkownika po otwarciu spreparowanego dokumentu. Luka została załatana w APSB24-29 w maju 2024 r.<sup>[[3]](#references)</sup>

---

## YARA quick rule template
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

1. **Szybkie instalowanie poprawek** – utrzymuj Acrobat/Reader na najnowszym kanale Continuous; większość łańcuchów RCE obserwowanych w środowisku naturalnym wykorzystuje luki typu n-day, które zostały załatane kilka miesięcy wcześniej.
2. **Usuwanie aktywnej zawartości na gatewayu** – użyj `pdfcpu sanitize` lub `qpdf --qdf --remove-unreferenced`, aby usunąć JavaScript, osadzone pliki i akcje uruchamiania z przychodzących plików PDF.
3. **Content Disarm & Reconstruction (CDR)** – konwertuj pliki PDF do obrazów (lub PDF/A) na hoście sandbox, aby zachować wierność wizualną, jednocześnie usuwając aktywne obiekty.
4. **Blokowanie rzadko używanych funkcji** – ustawienia „Enhanced Security” w wersji enterprise programu Reader pozwalają wyłączyć JavaScript, multimedia i renderowanie 3D.
5. **Edukacja użytkowników** – social engineering (przynęty w postaci faktur i CV) nadal pozostaje początkowym wektorem; naucz pracowników przekazywać podejrzane załączniki do zespołu IR.

## Referencje

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Security update available for Adobe Acrobat and Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - copy of the guide](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)

{{#include ../../../banners/hacktricks-training.md}}
