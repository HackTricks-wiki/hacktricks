# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper może spakować plik wykonywalny lub skrypt jako plik Windows Installer (`.msi`). Pobierz i uruchom bezpłatną edycję, a następnie wybierz plik wykonywalny do spakowania.<sup>[[3]](#references)</sup> Aby uruchomić sekwencję poleceń, jako dane wejściowe wybierz plik `.bat`, zamiast pakować `cmd.exe`.<sup>[[1]](#references)</sup>

![Wybieranie pliku wykonywalnego lub skryptu wsadowego jako źródła w MSI Wrapper](<../../images/image (417).png>)

Starannie skonfiguruj kontekst wykonywania i pozostałe właściwości instalatora:

![Konfigurowanie identyfikatora aplikacji i kontekstu zabezpieczeń w MSI Wrapper](<../../images/image (312).png>)

![Konfigurowanie właściwości instalatora w MSI Wrapper](<../../images/image (346).png>)

![Przegląd ustawień kompilacji MSI Wrapper](<../../images/image (1072).png>)

Te wartości można zmienić podczas pakowania niestandardowego pliku binarnego.

Przejdź przez pozostałe strony kreatora i wybierz **Build**, aby wygenerować instalator.<sup>[[1]](#references)</sup>

## Weryfikacja kontekstu wykonywania opakowanego polecenia

W testowym pakiecie opakuj plik `.bat`, który zapisuje informacje o swoim tokenie, zamiast zakładać, że ustawienie podniesienia uprawnień MSI ma zastosowanie do jego procesu podrzędnego.<sup>[[4]](#references)</sup> W kreatorze wybierz kontekst zabezpieczeń **System** zamiast **User** i wybierz instalację dla całego komputera z podniesionymi uprawnieniami, jeśli taki jest zamierzony sposób działania.<sup>[[5]](#references)</sup> Opcja **System** nie omija autoryzacji: użytkownik niebędący administratorem nadal potrzebuje sposobu na przeprowadzenie instalacji z podniesionymi uprawnieniami, na przykład przez [błędną konfigurację `AlwaysInstallElevated` za pomocą dwóch zasad](index.html#alwaysinstallelevated) lub uprzywilejowany proces instalatora.<sup>[[2]](#references)</sup> Wybranie **User** powoduje, że opakowane polecenie działa w kontekście użytkownika przeprowadzającego instalację, co może być konieczne w przypadku zasobów specyficznych dla użytkownika lub zasobów sieciowych.<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

Zbuduj MSI, używając tego pliku wsadowego jako danych wejściowych, a następnie uruchom go na hoście testowym i sprawdź zarejestrowaną tożsamość oraz uprawnienia.<sup>[[4]](#references)</sup> MSI Wrapper mapuje niezerowy kod wyjścia pliku wsadowego na błąd instalacji 1603, dlatego jawne zwrócenie zera pozwala uniknąć fałszywego błędu po pomyślnym teście.<sup>[[4]](#references)</sup> Plik wyjściowy jest artefaktem testowym; nie wyciągaj wniosku o uruchomieniu z uprawnieniami SYSTEM wyłącznie na podstawie pomyślnego zakończenia `msiexec` lub cichej instalacji.<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn` wycisza interfejs MSI, ale niekoniecznie interfejs samego opakowanego pliku wykonywalnego.<sup>[[6]](#references)[[7]](#references)</sup> W przypadku opakowanego instalatora ustaw obsługiwane przez niego argumenty trybu cichego w kreatorze; dynamiczna właściwość `WRAPPED_ARGUMENTS` w MSI Wrapper jest dostępna w wersji PRO.<sup>[[1]](#references)[[7]](#references)</sup> Jeśli potrzebujesz bezpośredniej kontroli nad kolejnością i podszywaniem się w akcjach niestandardowych, zobacz [podejście z niestandardową akcją WiX](create-msi-with-wix.md).

> [!WARNING]
> Samo utworzenie pliku MSI nie przyznaje podwyższonych uprawnień. To, czy instalacja zostanie uruchomiona z podwyższonymi uprawnieniami, zależy od zasad Windows Installer, kontekstu pakietu i autoryzacji użytkownika. Microsoft ostrzega, że włączenie `AlwaysInstallElevated` zarówno dla użytkownika, jak i komputera pozwala osobom niebędącym administratorami instalować pakiety z uprawnieniami systemowymi.<sup>[[2]](#references)</sup>



## References

- [1] [Dokumentacja MSI Wrapper - Wprowadzenie](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Instalowanie pakietu z podwyższonymi uprawnieniami przez użytkownika niebędącego administratorem](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Pobieranie](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - Tworzenie pliku MSI z pliku wsadowego](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - Strony kreatora](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - Opcje wiersza poleceń](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - Argumenty wiersza poleceń](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}
