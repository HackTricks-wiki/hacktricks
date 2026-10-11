# Analiza plików PDF

{{#include ../../../banners/hacktricks-training.md}}

**Więcej informacji:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Format PDF słynie ze swojej złożoności i możliwości ukrywania danych, dlatego często pojawia się w wyzwaniach CTF z zakresu informatyki śledczej. Łączy elementy zwykłego tekstu z obiektami binarnymi, które mogą być skompresowane lub zaszyfrowane, a także może zawierać skrypty w językach takich jak JavaScript czy Flash. Aby poznać strukturę PDF, można zapoznać się z [materiałami wprowadzającymi](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) Didiera Stevensa lub użyć edytora tekstu albo specjalistycznego edytora PDF, takiego jak Origami.

Do dokładniejszego badania lub modyfikowania plików PDF można użyć narzędzi takich jak [qpdf](https://github.com/qpdf/qpdf) i [Origami](https://github.com/mobmewireless/origami-pdf). Ukryte dane w plikach PDF mogą znajdować się w:

- Niewidocznych warstwach
- Formacie metadanych XMP firmy Adobe
- Przyrostowych generacjach
- Tekście w kolorze tła
- Tekście za obrazami lub obrazach nakładających się na siebie
- Niewyświetlanych komentarzach

Do niestandardowej analizy plików PDF można wykorzystać biblioteki Pythona, takie jak [PeepDF](https://github.com/jesparza/peepdf), i tworzyć własne skrypty do parsowania. Możliwości ukrywania danych w plikach PDF są tak szerokie, że materiały takie jak poradnik NSA dotyczący zagrożeń związanych z PDF i środków zaradczych — mimo że nie jest już dostępny w pierwotnej lokalizacji — nadal zawierają cenne wskazówki. Więcej informacji można znaleźć w [kopii poradnika](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) oraz w zbiorze [sztuczek dotyczących formatu PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) autorstwa Ange Albertiniego.<sup>[[4]](#references)[[5]](#references)</sup>

## Typowe złośliwe konstrukcje

Atakujący często wykorzystują określone obiekty i akcje PDF, które są wykonywane automatycznie po otwarciu dokumentu lub wykonaniu w nim określonej czynności. Warto szukać następujących słów kluczowych:

* **/OpenAction, /AA** – akcje wykonywane automatycznie przy otwarciu dokumentu lub po wystąpieniu określonych zdarzeń.
* **/JS, /JavaScript** – osadzony JavaScript (często zaciemniony lub podzielony między obiekty).
* **/Launch, /SubmitForm, /URI, /GoToE** – mechanizmy uruchamiania zewnętrznych procesów lub adresów URL.
* **/RichMedia, /Flash, /3D** – obiekty multimedialne, które mogą ukrywać payloady.
* **/EmbeddedFile /Filespec** – załączniki (EXE, DLL, OLE itp.).
* **/ObjStm, /XFA, /AcroForm** – strumienie obiektów lub formularze, które są często wykorzystywane do ukrywania shellcode'u.
* **Aktualizacje przyrostowe** – wiele znaczników %%EOF lub bardzo duże przesunięcie **/Prev** mogą wskazywać na dane dopisane po podpisaniu dokumentu w celu obejścia AV.

Jeśli któremukolwiek z powyższych tokenów towarzyszą podejrzane ciągi znaków (powershell, cmd.exe, calc.exe, base64 itp.), plik PDF wymaga dokładniejszej analizy.

---

## Ściągawka do analizy statycznej

Poniższe przykłady korzystają z udokumentowanych interfejsów wiersza poleceń narzędzi `pdf-parser.py`, qpdf i pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>

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

Pikselizacja obrazu w PDF nie usuwa jego oryginalnych pikseli. Jeśli czytelny dokument wydaje się w ten sposób ukrywać dane uwierzytelniające, wyodrębnij osadzony obraz do autoryzowanej analizy offline; wynik zależy od obrazu i odpowiedniego materiału referencyjnego, a odzyskanie danych wizualnych nie jest gwarantowane. Odzyskane hasło nadal wymaga osobnej weryfikacji względem konta, którego uprawnienia mają znaczenie. Nie uwzględniaj rutynowego wyodrębniania PDF-ów ani odzyskiwania obrazu w skanowaniu hostów.

Dodatkowe przydatne projekty (aktywnie utrzymywane w latach 2023–2025):
* **pdfcpu** – biblioteka/CLI dla Go umożliwiająca walidowanie, odszyfrowywanie, wyodrębnianie, optymalizowanie i modyfikowanie plików PDF.<sup>[[9]](#references)</sup>
* **pdf-inspector** – działający w przeglądarce wizualizator, który renderuje graf obiektów i strumienie.
* **PyMuPDF** – skryptowalne powiązania z Pythonem do inspekcji plików PDF i renderowania stron do obrazów rastrowych. Traktuj parser/renderer jako powierzchnię ataku w przypadku niezaufanych plików i uruchamiaj go w odpowiednio izolowanym środowisku analitycznym.<sup>[[8]](#references)</sup>

---

## Najnowsze techniki ataków (2023–2025)

* **Poliglot MalDoc in PDF (2023)** – JPCERT/CC opisał technikę, która dołącza do pliku PDF utworzony w Wordzie plik MHT z makrami VBA, zachowując sygnaturę pliku PDF, a jednocześnie umożliwiając otwarcie go w Wordzie. Narzędzia do analizy wyłącznie PDF-ów, sandboxy lub antywirusy mogą nie wykryć makra, ponieważ szkodliwe działanie następuje po otwarciu pliku jako dokumentu Word; szukaj znacznika `<w:WordDocument>` wraz z innymi wskaźnikami MHT.<sup>[[2]](#references)</sup>
* **Ataki Shadow na podpisane pliki PDF** – atakujący mogą umieścić ukrytą zawartość w pliku PDF przed jego podpisaniem, a następnie dodać aktualizację przyrostową, która zmienia odniesienia do katalogu lub obiektów, tak aby przeglądarki wyświetlały ukrytą zawartość, podczas gdy oryginalny podpis pozostaje prawidłowy. Technika ta może omijać zabezpieczenia przeglądarek, które klasyfikują takie aktualizacje jako nieszkodliwe.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe ocenia tę krytyczną podatność typu use-after-free jako mogącą prowadzić do wykonania dowolnego kodu; biuletyn APSB24-29 opublikowano 14 maja 2024 r.<sup>[[3]](#references)</sup>

---

## Podstawowy szablon reguły YARA

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

1. **Szybko instaluj poprawki** – używaj najnowszej wersji Acrobat/Reader z kanału Continuous; większość zaobserwowanych w środowisku naturalnym łańcuchów RCE wykorzystuje podatności n-day, które naprawiono wiele miesięcy wcześniej.
2. **Usuwaj aktywną zawartość na bramie** – używaj specjalizowanego, kontrolowanego zasadami narzędzia do sanityzacji lub produktu CDR, który jawnie usuwa JavaScript, osadzone pliki, akcje uruchamiania, formularze i multimedia. `qpdf --qdf` ułatwia inspekcję obiektów PDF, a pdfcpu udostępnia funkcje walidacji i modyfikacji; samo użycie któregokolwiek z tych narzędzi nie dowodzi, że aktywna zawartość została usunięta.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – konwertuj pliki PDF na obrazy (lub PDF/A) na hoście sandboxowym, aby zachować zgodność wizualną i odrzucić aktywne obiekty.
4. **Blokuj rzadko używane funkcje** – ustawienia „Enhanced Security” w wersji Reader dla przedsiębiorstw pozwalają wyłączyć JavaScript, multimedia i renderowanie 3D.
5. **Edukacja użytkowników** – socjotechnika (przynęty w postaci faktur i CV) nadal jest początkowym wektorem; naucz pracowników przekazywać podejrzane załączniki do zespołu IR.

## References

- [1] [Przewodnik terenowy CTF z informatyki śledczej](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – obejście wykrywania przez osadzenie złośliwego pliku Word w pliku PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Biuletyn bezpieczeństwa Adobe – dostępna aktualizacja zabezpieczeń dla Adobe Acrobat i Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - kopia przewodnika](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - sztuczki dotyczące formatu PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Ataki Shadow: ukrywanie i zastępowanie zawartości w podpisanych plikach PDF](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [Samouczek PyMuPDF](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Opcje wiersza poleceń qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
