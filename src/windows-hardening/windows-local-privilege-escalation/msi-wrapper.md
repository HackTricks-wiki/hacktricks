# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper może spakować plik wykonywalny lub skrypt jako plik Windows Installer (`.msi`). Pobierz i uruchom darmową edycję, a następnie wybierz plik wykonywalny do spakowania. Aby uruchomić sekwencję poleceń, wybierz plik `.bat` jako dane wejściowe zamiast pakowania `cmd.exe`.<sup>[[1]](#references)</sup>

![Wybieranie pliku wykonywalnego lub skryptu wsadowego jako źródła w MSI Wrapper](<../../images/image (417).png>)

Ostrożnie skonfiguruj kontekst wykonywania i pozostałe właściwości instalatora:

![Konfigurowanie identyfikatora aplikacji i kontekstu zabezpieczeń w MSI Wrapper](<../../images/image (312).png>)

![Konfigurowanie właściwości instalatora w MSI Wrapper](<../../images/image (346).png>)

![Przegląd ustawień kompilacji MSI Wrapper](<../../images/image (1072).png>)

Te wartości można zmienić podczas pakowania niestandardowego pliku binarnego.

Przejdź przez pozostałe strony kreatora i wybierz **Build**, aby wygenerować instalator.<sup>[[1]](#references)</sup>

> [!WARNING]
> Samo utworzenie pliku MSI nie nadaje uprawnień podwyższonych. To, czy instalacja będzie wykonywana z podwyższonymi uprawnieniami, zależy od zasad Windows Installer, kontekstu pakietu i autoryzacji użytkownika. Firma Microsoft ostrzega, że włączenie `AlwaysInstallElevated` zarówno dla użytkownika, jak i komputera pozwala użytkownikom niebędącym administratorami instalować pakiety z uprawnieniami systemowymi.<sup>[[2]](#references)</sup>

## References

- [1] [Dokumentacja MSI Wrapper - Pierwsze kroki](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Instalowanie pakietu z podwyższonymi uprawnieniami przez użytkownika niebędącego administratorem](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
{{#include ../../banners/hacktricks-training.md}}
