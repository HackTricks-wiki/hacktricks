{{#include ../../banners/hacktricks-training.md}}

# Controlla le possibili azioni all'interno dell'applicazione GUI

**Dialoghi comuni** sono quelle opzioni di **salvataggio di un file**, **apertura di un file**, selezione di un font, un colore... La maggior parte di essi **offrirà una funzionalità completa di Explorer**. Questo significa che sarai in grado di accedere alle funzionalità di Explorer se puoi accedere a queste opzioni:

- Chiudi/Chiudi come
- Apri/Apri con
- Stampa
- Esporta/Importa
- Cerca
- Scansiona

Dovresti controllare se puoi:

- Modificare o creare nuovi file
- Creare collegamenti simbolici
- Accedere ad aree riservate
- Eseguire altre app

## Esecuzione di comandi

Forse **utilizzando un'opzione `Apri con`** puoi aprire/eseguire qualche tipo di shell.

### Windows

Ad esempio _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ trova più binari che possono essere utilizzati per eseguire comandi (e compiere azioni inaspettate) qui: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX \_\_

_bash, sh, zsh..._ Maggiori informazioni qui: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Bypassare le restrizioni del percorso

- **Variabili di ambiente**: Ci sono molte variabili di ambiente che puntano a qualche percorso
- **Altri protocolli**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Collegamenti simbolici**
- **Scorciatoie**: CTRL+N (apri nuova sessione), CTRL+R (Esegui comandi), CTRL+SHIFT+ESC (Gestione attività), Windows+E (apri explorer), CTRL-B, CTRL-I (Preferiti), CTRL-H (Cronologia), CTRL-L, CTRL-O (File/Dialogo di apertura), CTRL-P (Dialogo di stampa), CTRL-S (Salva con nome)
- Menu amministrativo nascosto: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Strumenti amministrativi, shell:Libreria documenti, shell:Librerie, shell:Profili utente, shell:Personale, shell:Cerca nella cartella home, shell:Posti di rete, shell:Invia a, shell:Profili utenti, shell:Strumenti amministrativi comuni, shell:Cartella Il mio computer, shell:Cartella Internet_
- **Percorsi UNC**: Percorsi per connettersi a cartelle condivise. Dovresti provare a connetterti al C$ della macchina locale ("\\\127.0.0.1\c$\Windows\System32")
- **Altri percorsi UNC:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

## Scarica i tuoi binari

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Editor del registro: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## Accesso al filesystem dal browser

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## Scorciatoie

- Sticky Keys – Premi SHIFT 5 volte
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Tieni premuto NUMLOCK per 5 secondi
- Filter Keys – Tieni premuto SHIFT destro per 12 secondi
- WINDOWS+F1 – Ricerca di Windows
- WINDOWS+D – Mostra desktop
- WINDOWS+E – Avvia Windows Explorer
- WINDOWS+R – Esegui
- WINDOWS+U – Centro accessibilità
- WINDOWS+F – Cerca
- SHIFT+F10 – Menu contestuale
- CTRL+SHIFT+ESC – Gestione attività
- CTRL+ALT+DEL – Schermata di avvio nelle versioni più recenti di Windows
- F1 – Aiuto F3 – Cerca
- F6 – Barra degli indirizzi
- F11 – Attiva/disattiva schermo intero in Internet Explorer
- CTRL+H – Cronologia di Internet Explorer
- CTRL+T – Internet Explorer – Nuova scheda
- CTRL+N – Internet Explorer – Nuova pagina
- CTRL+O – Apri file
- CTRL+S – Salva CTRL+N – Nuovo RDP / Citrix

## Swipe

- Scorri dal lato sinistro verso destra per vedere tutte le finestre aperte, minimizzando l'app KIOSK e accedendo direttamente all'intero sistema operativo;
- Scorri dal lato destro verso sinistra per aprire il Centro operativo, minimizzando l'app KIOSK e accedendo direttamente all'intero sistema operativo;
- Scorri dal bordo superiore per rendere visibile la barra del titolo per un'app aperta in modalità schermo intero;
- Scorri verso l'alto dal basso per mostrare la barra delle applicazioni in un'app a schermo intero.

## Trucchi di Internet Explorer

### 'Image Toolbar'

È una barra degli strumenti che appare in alto a sinistra dell'immagine quando viene cliccata. Sarai in grado di Salvare, Stampare, Inviare per email, Aprire "Le mie immagini" in Explorer. Il Kiosk deve utilizzare Internet Explorer.

### Protocollo Shell

Digita questi URL per ottenere una vista di Explorer:

- `shell:Strumenti amministrativi`
- `shell:Libreria documenti`
- `shell:Librerie`
- `shell:Profili utente`
- `shell:Personale`
- `shell:Cerca nella cartella home`
- `shell:Posti di rete`
- `shell:Invia a`
- `shell:Profili utenti`
- `shell:Strumenti amministrativi comuni`
- `shell:Cartella Il mio computer`
- `shell:Cartella Internet`
- `Shell:Profilo`
- `Shell:Programmi`
- `Shell:Sistema`
- `Shell:Pannello di controllo`
- `Shell:Windows`
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Pannello di controllo
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Il mio computer
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Le mie posizioni di rete
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## Mostra estensioni dei file

Controlla questa pagina per ulteriori informazioni: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# Trucchi dei browser

Backup delle versioni iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Crea un dialogo comune utilizzando JavaScript e accedi all'esplora file: `document.write('<input/type=file>')`
Fonte: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Gesture e pulsanti

- Scorri verso l'alto con quattro (o cinque) dita / Tocca due volte il pulsante Home: Per visualizzare la vista multitasking e cambiare app

- Scorri in un modo o nell'altro con quattro o cinque dita: Per cambiare all'app successiva/precedente

- Pizzica lo schermo con cinque dita / Tocca il pulsante Home / Scorri verso l'alto con 1 dito dal fondo dello schermo in un movimento rapido verso l'alto: Per accedere alla Home

- Scorri un dito dal fondo dello schermo per solo 1-2 pollici (lento): Apparirà il dock

- Scorri verso il basso dalla parte superiore del display con 1 dito: Per visualizzare le tue notifiche

- Scorri verso il basso con 1 dito nell'angolo in alto a destra dello schermo: Per vedere il centro di controllo dell'iPad Pro

- Scorri 1 dito dal lato sinistro dello schermo per 1-2 pollici: Per vedere la vista Oggi

- Scorri rapidamente 1 dito dal centro dello schermo verso destra o sinistra: Per cambiare all'app successiva/precedente

- Tieni premuto il pulsante On/**Off**/Sleep nell'angolo in alto a destra dell'**iPad +** Sposta il cursore per **spegnere** tutto a destra: Per spegnere

- Tieni premuto il pulsante On/**Off**/Sleep nell'angolo in alto a destra dell'**iPad e il pulsante Home per alcuni secondi**: Per forzare uno spegnimento completo

- Tieni premuto il pulsante On/**Off**/Sleep nell'angolo in alto a destra dell'**iPad e il pulsante Home rapidamente**: Per fare uno screenshot che apparirà in basso a sinistra del display. Premi entrambi i pulsanti contemporaneamente molto brevemente, poiché se li tieni premuti per alcuni secondi verrà eseguito uno spegnimento completo.

## Scorciatoie

Dovresti avere una tastiera per iPad o un adattatore per tastiera USB. Solo le scorciatoie che potrebbero aiutare a uscire dall'applicazione saranno mostrate qui.

| Tasto | Nome         |
| --- | ------------ |
| ⌘   | Comando      |
| ⌥   | Opzione (Alt) |
| ⇧   | Shift        |
| ↩   | Ritorna      |
| ⇥   | Tab          |
| ^   | Controllo    |
| ←   | Freccia sinistra   |
| →   | Freccia destra  |
| ↑   | Freccia su     |
| ↓   | Freccia giù    |

### Scorciatoie di sistema

Queste scorciatoie sono per le impostazioni visive e sonore, a seconda dell'uso dell'iPad.

| Scorciatoia | Azione                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Abbassa la luminosità dello schermo                                                                    |
| F2       | Aumenta la luminosità dello schermo                                                                |
| F7       | Torna a una canzone                                                                  |
| F8       | Riproduci/metti in pausa                                                                     |
| F9       | Salta canzone                                                                      |
| F10      | Mute                                                                           |
| F11      | Diminuisci il volume                                                                |
| F12      | Aumenta il volume                                                                |
| ⌘ Space  | Visualizza un elenco delle lingue disponibili; per sceglierne una, tocca di nuovo la barra spaziatrice. |

### Navigazione su iPad

| Scorciatoia                                           | Azione                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Vai alla Home                                              |
| ⌘⇧H (Comando-Shift-H)                              | Vai alla Home                                              |
| ⌘ (Space)                                          | Apri Spotlight                                          |
| ⌘⇥ (Comando-Tab)                                   | Elenca le ultime dieci app utilizzate                                 |
| ⌘\~                                                | Vai all'ultima app                                       |
| ⌘⇧3 (Comando-Shift-3)                              | Screenshot (si ferma in basso a sinistra per salvare o agire su di esso) |
| ⌘⇧4                                                | Screenshot e aprilo nell'editor                    |
| Tieni premuto ⌘                                   | Elenco delle scorciatoie disponibili per l'app                 |
| ⌘⌥D (Comando-Opzione/Alt-D)                         | Mostra il dock                                      |
| ^⌥H (Controllo-Opzione-H)                             | Pulsante Home                                             |
| ^⌥H H (Controllo-Opzione-H-H)                         | Mostra la barra multitasking                                      |
| ^⌥I (Controllo-Opzione-i)                             | Selettore di elementi                                            |
| Escape                                             | Pulsante Indietro                                             |
| → (Freccia destra)                                    | Prossimo elemento                                               |
| ← (Freccia sinistra)                                     | Elemento precedente                                           |
| ↑↓ (Freccia su, Freccia giù)                          | Tocca simultaneamente l'elemento selezionato                        |
| ⌥ ↓ (Opzione-Freccia giù)                            | Scorri verso il basso                                             |
| ⌥↑ (Opzione-Freccia su)                               | Scorri verso l'alto                                               |
| ⌥← o ⌥→ (Opzione-Freccia sinistra o Opzione-Freccia destra) | Scorri a sinistra o a destra                                    |
| ^⌥S (Controllo-Opzione-S)                             | Attiva o disattiva la sintesi vocale                         |
| ⌘⇧⇥ (Comando-Shift-Tab)                            | Passa all'app precedente                              |
| ⌘⇥ (Comando-Tab)                                   | Torna all'app originale                         |
| ←+→, poi Opzione + ← o Opzione+→                   | Naviga attraverso il Dock                                   |

### Scorciatoie di Safari

| Scorciatoia                | Azione                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Comando-L)          | Apri posizione                                    |
| ⌘T                      | Apri una nuova scheda                                   |
| ⌘W                      | Chiudi la scheda corrente                            |
| ⌘R                      | Aggiorna la scheda corrente                          |
| ⌘.                      | Ferma il caricamento della scheda corrente                     |
| ^⇥                      | Passa alla scheda successiva                           |
| ^⇧⇥ (Controllo-Shift-Tab) | Passa alla scheda precedente                         |
| ⌘L                      | Seleziona il campo di input/testo URL per modificarlo     |
| ⌘⇧T (Comando-Shift-T)   | Apri l'ultima scheda chiusa (può essere utilizzata più volte) |
| ⌘\[                     | Torna indietro di una pagina nella cronologia di navigazione      |
| ⌘]                      | Avanza di una pagina nella cronologia di navigazione   |
| ⌘⇧R                     | Attiva la modalità lettore                             |

### Scorciatoie di Mail

| Scorciatoia                   | Azione                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Apri posizione                |
| ⌘T                         | Apri una nuova scheda               |
| ⌘W                         | Chiudi la scheda corrente        |
| ⌘R                         | Aggiorna la scheda corrente      |
| ⌘.                         | Ferma il caricamento della scheda |
| ⌘⌥F (Comando-Opzione/Alt-F) | Cerca nella tua casella di posta       |

# Riferimenti

- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../../banners/hacktricks-training.md}}
