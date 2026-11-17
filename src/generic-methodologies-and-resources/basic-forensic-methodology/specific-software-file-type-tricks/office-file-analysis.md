# Analiza plików Office

{{#include ../../../banners/hacktricks-training.md}}

Więcej informacji znajdziesz pod adresem [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Poniżej znajduje się tylko podsumowanie:<sup>[[2]](#references)</sup>

Dokumenty Microsoft Office często występują w starszych formatach, takich jak RTF i DOC, XLS oraz PPT oparte na OLE/CFBF, albo w nowszych formatach **Office Open XML (OOXML)**, takich jak DOCX, XLSX i PPTX. Dokumenty Office mogą zawierać aktywną zawartość, na przykład makra, dlatego często są wykorzystywane do phishingu i przenoszenia malware. Pliki OOXML są archiwami ZIP, których hierarchię plików i zawartość XML można sprawdzić po rozpakowaniu.<sup>[[1]](#references)[[2]](#references)</sup>

Opisano polecenie służące do rozpakowania dokumentu oraz uzyskaną strukturę plików OOXML. Udokumentowano również techniki ukrywania danych w tych plikach, co wskazuje na ciągłe opracowywanie nowych metod ukrywania danych w wyzwaniach CTF.<sup>[[2]](#references)</sup>

Do analizy **oletools** i **OfficeDissector** oferują kompleksowe zestawy narzędzi do badania dokumentów OLE i OOXML. Pomagają wykrywać i analizować osadzone makra, które często służą do dostarczania malware, zwykle pobierającego i uruchamiającego kolejne złośliwe payloady. Makra VBA można analizować bez Microsoft Office, korzystając z Libre Office, które umożliwia debugowanie z użyciem breakpointów i zmiennych obserwowanych.<sup>[[2]](#references)</sup>

Instalacja i używanie **oletools** są proste. Podano polecenia instalacji za pomocą pip oraz wyodrębniania makr z dokumentów. W Wordzie makra automatyczne obejmują `AutoExec` i `AutoOpen`, natomiast `Document_Open` jest procedurą obsługi zdarzenia otwarcia.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## Analiza makr VBA: kod-wypełniacz i UserForms

## Kod-wypełniacz

Makra mogą zawierać **nieosiągalny lub nieistotny kod**, którego celem jest spowolnienie analizy. Zidentyfikuj warunki stałe i prześledź osiągalne działanie, zanim poświęcisz czas na odwracanie gałęzi. Poniższy przykład wykorzystuje warunek `If`, który nigdy nie może być prawdziwy, aby ukryć kod-wypełniacz.

![Makro Word zawierające nieosiągalną gałąź warunkową z kodem-wypełniaczem](<../../../images/image (369).png>)

## Formularze makr

UserForms w VBA mogą przechowywać dane w kontrolkach, takich jak pola tekstowe. Ponieważ formularze, ramki i strony mogą udostępniać kolekcję `Controls`, analitycy powinni wyliczyć całą hierarchię kontrolek, zamiast polegać wyłącznie na tym, co wyświetla formularz. Poniższy przykład przechowuje ukryte dane w nakładających się na siebie polach tekstowych.<sup>[[6]](#references)</sup>

Podczas analizy dynamicznej funkcja `GetObject` w VBA może pobrać obiekt Automation z pliku lub połączyć się z już działającym serwerem Automation. Makra mogą wykorzystywać dostęp do tych obiektów, aby dotrzeć do danych, które nie są widoczne w dokumencie; sprawdź zarówno zwrócony obiekt, jak i drzewo kontrolek UserForm.<sup>[[7]](#references)</sup>

![UserForm makra z danymi ukrytymi w nakładających się na siebie polach tekstowych](<../../../images/image (344).png>)

Informacje o dokumentach Office zaszyfrowanych hasłem znajdziesz w [opartym na gramatyce przepływie odzyskiwania offline](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

Informacje o plikach Revit RFA korzystających z OLE/CFBF znajdziesz w sekcji [ponowne obliczanie ECC, kontrolowany gzip i wykorzystanie podatności deserializatora](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md); ten przepływ pracy dotyczący wykorzystania podatności parsera jest odrębny od wstępnej analizy dokumentów Office.

## References

- [1] [Dokumentacja OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [Przewodnik terenowy po CTF z zakresu informatyki śledczej](https://trailofbits.github.io/ctf/forensics/)
- [3] [Dokumentacja olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [Makra automatyczne (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Zdarzenie Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn - kolekcje, kontrolki i obiekty (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn - funkcja `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../../../banners/hacktricks-training.md}}
