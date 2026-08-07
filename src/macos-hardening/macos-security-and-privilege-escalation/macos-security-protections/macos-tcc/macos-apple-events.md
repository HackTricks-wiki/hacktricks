# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

**Apple Events** su funkcija u Apple-ovom macOS-u koja aplikacijama omogućava međusobnu komunikaciju. Deo su **Apple Event Manager-a**, komponente macOS operativnog sistema odgovorne za upravljanje međuprocesnom komunikacijom. Ovaj sistem omogućava jednoj aplikaciji da pošalje poruku drugoj aplikaciji i zatraži od nje da izvrši određenu operaciju, kao što je otvaranje datoteke, preuzimanje podataka ili izvršavanje komande.

Glavni daemon je `/System/Library/CoreServices/appleeventsd`, koji registruje servis `com.apple.coreservices.appleevents`.

Svaka aplikacija koja može da prima events proverava se kod ovog daemon-a i prosleđuje svoj Apple Event Mach Port. Kada aplikacija želi da joj pošalje event, zatražiće ovaj port od daemon-a.

Sandboxed aplikacijama su potrebne privilegije kao što su `allow appleevent-send` i `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` kako bi mogle da šalju events. Imajte na umu da entitlements kao što je `com.apple.security.temporary-exception.apple-events` mogu ograničiti ko ima pristup slanju events, za šta će biti potrebni entitlements kao što je `com.apple.private.appleevents`.

> [!TIP]
> Moguće je koristiti env promenljivu **`AEDebugSends`** za beleženje informacija o poslatoj poruci:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
