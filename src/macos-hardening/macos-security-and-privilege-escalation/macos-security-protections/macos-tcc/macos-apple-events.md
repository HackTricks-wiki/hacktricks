# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

**Apple Events** to funkcja w macOS firmy Apple, która umożliwia aplikacjom komunikację ze sobą. Są częścią **Apple Event Manager**, który jest komponentem systemu operacyjnego macOS odpowiedzialnym za obsługę komunikacji międzyprocesowej. System ten umożliwia jednej aplikacji wysłanie wiadomości do innej aplikacji w celu zażądania wykonania określonej operacji, takiej jak otwieranie pliku, pobieranie danych lub wykonywanie polecenia.

Demon mina to `/System/Library/CoreServices/appleeventsd`, który rejestruje usługę `com.apple.coreservices.appleevents`.

Każda aplikacja, która może odbierać zdarzenia, będzie sprawdzać z tym demonem, podając swój Apple Event Mach Port. A gdy aplikacja chce wysłać zdarzenie do niego, aplikacja poprosi ten port od demona.

Aplikacje w piaskownicy wymagają uprawnień, takich jak `allow appleevent-send` i `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))`, aby mogły wysyłać zdarzenia. Należy zauważyć, że uprawnienia takie jak `com.apple.security.temporary-exception.apple-events` mogą ograniczać dostęp do wysyłania zdarzeń, co będzie wymagało uprawnień takich jak `com.apple.private.appleevents`.

> [!TIP]
> Możliwe jest użycie zmiennej env **`AEDebugSends`** w celu rejestrowania informacji o wysłanej wiadomości:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
