# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne Informacije

**Apple Events** su funkcija u Apple-ovom macOS-u koja omogućava aplikacijama da komuniciraju jedna s drugom. Oni su deo **Apple Event Manager-a**, koji je komponenta operativnog sistema macOS odgovorna za upravljanje međuprocesnom komunikacijom. Ovaj sistem omogućava jednoj aplikaciji da pošalje poruku drugoj aplikaciji da zatraži da izvrši određenu operaciju, kao što je otvaranje datoteke, preuzimanje podataka ili izvršavanje komande.

Mina daemon je `/System/Library/CoreServices/appleeventsd` koji registruje servis `com.apple.coreservices.appleevents`.

Svaka aplikacija koja može primati događaje će se proveravati sa ovim daemon-om pružajući svoj Apple Event Mach Port. A kada aplikacija želi da pošalje događaj, aplikacija će zatražiti ovaj port od daemona.

Sandboxed aplikacije zahtevaju privilegije kao što su `allow appleevent-send` i `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` kako bi mogle da šalju događaje. Napomena da entitlements kao što su `com.apple.security.temporary-exception.apple-events` mogu ograničiti ko ima pristup slanju događaja, što će zahtevati entitlements kao što su `com.apple.private.appleevents`.

> [!TIP]
> Moguće je koristiti env varijablu **`AEDebugSends`** kako bi se logovale informacije o poslatim porukama:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
