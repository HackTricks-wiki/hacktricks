# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

**Apple Events** to funkcja systemu macOS firmy Apple, która umożliwia aplikacjom komunikowanie się ze sobą. Są one częścią **Apple Event Manager**, komponentu systemu operacyjnego macOS odpowiedzialnego za obsługę komunikacji międzyprocesowej. System ten umożliwia jednej aplikacji wysłanie do innej aplikacji wiadomości z żądaniem wykonania określonej operacji, takiej jak otwarcie pliku, pobranie danych lub wykonanie polecenia.

Głównym daemonem jest `/System/Library/CoreServices/appleeventsd`, który rejestruje usługę `com.apple.coreservices.appleevents`.

Każda aplikacja, która może odbierać events, rejestruje się w tym daemonie, przekazując swój Apple Event Mach Port. Gdy aplikacja chce wysłać do niej event, żąda tego portu od daemona.

Aplikacje działające w sandboxie wymagają uprawnień takich jak `allow appleevent-send` oraz `(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))`, aby móc wysyłać events. Należy pamiętać, że entitlements takie jak `com.apple.security.temporary-exception.apple-events` mogą ograniczać, kto ma dostęp do wysyłania events, co może wymagać entitlements takich jak `com.apple.private.appleevents`.

> [!TIP]
> Możliwe jest użycie zmiennej środowiskowej **`AEDebugSends`** w celu logowania informacji o wysyłanej wiadomości:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
