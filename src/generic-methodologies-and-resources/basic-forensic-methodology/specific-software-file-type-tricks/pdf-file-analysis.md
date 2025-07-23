# Analiza plików PDF

{{#include ../../../banners/hacktricks-training.md}}

**Aby uzyskać więcej szczegółów, sprawdź:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

Format PDF jest znany ze swojej złożoności i potencjału do ukrywania danych, co czyni go punktem centralnym dla wyzwań w zakresie forensyki CTF. Łączy elementy tekstowe z obiektami binarnymi, które mogą być skompresowane lub zaszyfrowane, i mogą zawierać skrypty w językach takich jak JavaScript lub Flash. Aby zrozumieć strukturę PDF, można odwołać się do [materiałów wprowadzających Didier'a Stevens'a](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/), lub użyć narzędzi takich jak edytor tekstu lub edytor specyficzny dla PDF, taki jak Origami.

Do dogłębnej eksploracji lub manipulacji plikami PDF dostępne są narzędzia takie jak [qpdf](https://github.com/qpdf/qpdf) i [Origami](https://github.com/mobmewireless/origami-pdf). Ukryte dane w plikach PDF mogą być ukryte w:

- Niewidocznych warstwach
- Formacie metadanych XMP od Adobe
- Inkrementalnych generacjach
- Tekście w tym samym kolorze co tło
- Tekście za obrazami lub nakładających się obrazach
- Niewyświetlanych komentarzach

Do niestandardowej analizy PDF można użyć bibliotek Pythona, takich jak [PeepDF](https://github.com/jesparza/peepdf), aby stworzyć własne skrypty do parsowania. Ponadto potencjał PDF do przechowywania ukrytych danych jest tak ogromny, że zasoby takie jak przewodnik NSA dotyczący ryzyk i przeciwdziałań związanych z PDF, chociaż już niehostowany w pierwotnej lokalizacji, nadal oferują cenne informacje. [Kopia przewodnika](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) oraz zbiór [sztuczek formatu PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) autorstwa Ange Albertini mogą dostarczyć dalszej lektury na ten temat.

## Powszechne złośliwe konstrukcje

Napastnicy często nadużywają określonych obiektów PDF i akcji, które automatycznie wykonują się po otwarciu dokumentu lub interakcji z nim. Słowa kluczowe, na które warto zwrócić uwagę:

* **/OpenAction, /AA** – automatyczne akcje wykonywane przy otwarciu lub przy określonych zdarzeniach.
* **/JS, /JavaScript** – osadzony JavaScript (często z obfuskacją lub podzielony na obiekty).
* **/Launch, /SubmitForm, /URI, /GoToE** – uruchamiacze procesów zewnętrznych / URL.
* **/RichMedia, /Flash, /3D** – obiekty multimedialne, które mogą ukrywać ładunki.
* **/EmbeddedFile /Filespec** – załączniki plików (EXE, DLL, OLE itp.).
* **/ObjStm, /XFA, /AcroForm** – strumienie obiektów lub formularze powszechnie nadużywane do ukrywania shell-code.
* **Inkrementalne aktualizacje** – wiele znaczników %%EOF lub bardzo duży offset **/Prev** mogą wskazywać na dane dodane po podpisaniu, aby obejść AV.

Gdy jakiekolwiek z powyższych tokenów pojawiają się razem z podejrzanymi ciągami (powershell, cmd.exe, calc.exe, base64 itp.), PDF zasługuje na głębszą analizę.

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
Dodatkowe przydatne projekty (aktywnie rozwijane 2023-2025):
* **pdfcpu** – biblioteka/CLI w Go zdolna do *lintowania*, *deszyfrowania*, *ekstrakcji*, *kompresji* i *sanitizacji* plików PDF.
* **pdf-inspector** – wizualizator oparty na przeglądarce, który renderuje graf obiektów i strumienie.
* **PyMuPDF (fitz)** – skryptowalny silnik Pythona, który może bezpiecznie renderować strony do obrazów, aby detonować osadzone JS w wzmocnionym piaskownicy.

---

## Ostatnie techniki ataków (2023-2025)

* **MalDoc w PDF polyglot (2023)** – JPCERT/CC zaobserwowało, że aktorzy zagrożeń dołączają dokument Word oparty na MHT z makrami VBA po końcowym **%%EOF**, tworząc plik, który jest zarówno ważnym PDF, jak i ważnym DOC. Silniki AV analizujące tylko warstwę PDF pomijają makro. Statyczne słowa kluczowe PDF są czyste, ale `file` nadal drukuje `%PDF`. Traktuj każdy PDF, który zawiera również ciąg `<w:WordDocument>`, jako wysoce podejrzany.
* **Cienie-inkrementalne aktualizacje (2024)** – przeciwnicy nadużywają funkcji inkrementalnej aktualizacji, aby wstawić drugi **/Catalog** z złośliwym `/OpenAction`, jednocześnie zachowując podpisaną pierwszą wersję. Narzędzia, które sprawdzają tylko pierwszą tabelę xref, są omijane.
* **Łańcuch UAF analizy czcionek – CVE-2024-30284 (Acrobat/Reader)** – podatna funkcja **CoolType.dll** może być osiągnięta z osadzonych czcionek CIDType2, co pozwala na zdalne wykonanie kodu z uprawnieniami użytkownika po otwarciu spreparowanego dokumentu. Poprawione w APSB24-29, maj 2024.

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

## Wskazówki defensywne

1. **Szybkie łatanie** – utrzymuj Acrobat/Reader na najnowszym torze ciągłym; większość łańcuchów RCE obserwowanych w dzikiej przyrodzie wykorzystuje luki n-dniowe naprawione miesiące wcześniej.
2. **Usuwanie aktywnej zawartości na bramie** – użyj `pdfcpu sanitize` lub `qpdf --qdf --remove-unreferenced`, aby usunąć JavaScript, osadzone pliki i akcje uruchamiające z przychodzących plików PDF.
3. **Rozbrojenie i rekonstrukcja zawartości (CDR)** – konwertuj pliki PDF na obrazy (lub PDF/A) na hoście w piaskownicy, aby zachować wierność wizualną, jednocześnie odrzucając aktywne obiekty.
4. **Blokowanie rzadko używanych funkcji** – ustawienia „Zwiększonego bezpieczeństwa” w Readerze pozwalają na wyłączenie JavaScript, multimediów i renderowania 3D.
5. **Edukacja użytkowników** – inżynieria społeczna (pułapki na faktury i CV) pozostaje początkowym wektorem; ucz pracowników, aby przesyłali podejrzane załączniki do IR.

## Odniesienia

* JPCERT/CC – “MalDoc w PDF – Ominięcie wykrywania przez osadzenie złośliwego pliku Word w pliku PDF” (sierpień 2023)
* Adobe – Aktualizacja zabezpieczeń dla Acrobata i Reader (APSB24-29, maj 2024)

{{#include ../../../banners/hacktricks-training.md}}
