# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Monitorerà ogni connessione effettuata da ciascun processo. A seconda della modalità (consenti connessioni silenziose, nega connessione silenziosa e avvisa) ti **mostrerà un avviso** ogni volta che viene stabilita una nuova connessione. Ha anche un'interfaccia grafica molto bella per vedere tutte queste informazioni.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall di Objective-See. Questo è un firewall di base che ti avviserà per connessioni sospette (ha un'interfaccia grafica ma non è così elegante come quella di Little Snitch).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Applicazione di Objective-See che cercherà in diverse posizioni dove **il malware potrebbe persistere** (è uno strumento a colpo singolo, non un servizio di monitoraggio).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Come KnockKnock, monitorando i processi che generano persistenza.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Applicazione di Objective-See per trovare **keylogger** che installano "event taps" della tastiera. 

{{#include ../../banners/hacktricks-training.md}}
