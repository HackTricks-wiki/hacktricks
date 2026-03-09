# Evasione dai KIOSK

{{#include ../banners/hacktricks-training.md}}

---

## Verifica del dispositivo fisico

| Componente   | Azione                                                               |
| ------------ | -------------------------------------------------------------------- |
| Pulsante di accensione | Spegnere e riaccendere il dispositivo può mostrare la schermata iniziale |
| Cavo di alimentazione  | Verificare se il dispositivo si riavvia quando l'alimentazione viene interrotta brevemente |
| Porte USB    | Collegare una tastiera fisica per usare più scorciatoie              |
| Ethernet     | La scansione o lo sniffing della rete potrebbe permettere possibili ulteriori sfruttamenti |

## Verifica delle azioni possibili all'interno dell'applicazione GUI

'Common Dialogs' sono quelle opzioni come salvare un file, aprire un file, selezionare un font, un colore... La maggior parte di esse offrirà una funzionalità completa di Explorer. Questo significa che potrai accedere alle funzionalità di Explorer se puoi raggiungere queste opzioni:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Dovresti verificare se puoi:

- Modificare o creare nuovi file
- Creare collegamenti simbolici
- Accedere ad aree ristrette
- Eseguire altre app

### Esecuzione di comandi

Forse **using a `Open with`** option\*\* puoi aprire/eseguire una sorta di shell.

#### Windows

Ad esempio _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ trova altri binari che possono essere usati per eseguire comandi (e compiere azioni inattese) qui: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Altro qui: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Bypassare le restrizioni di percorso

- **Variabili d'ambiente**: Ci sono molte variabili d'ambiente che puntano a percorsi
- **Altri protocolli**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Collegamenti simbolici**
- **Scorciatoie**: CTRL+N (apri nuova sessione), CTRL+R (Esegui comandi), CTRL+SHIFT+ESC (Task Manager), Windows+E (apri Explorer), CTRL-B, CTRL-I (Preferiti), CTRL-H (Cronologia), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Menu amministrativo nascosto: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
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

### Restricted Desktop Breakouts (Citrix/RDS/VDI)

- **Dialog-box pivoting**: Usa le finestre di dialogo *Open/Save/Print-to-file* come una versione ridotta di Explorer. Prova `*.*` / `*.exe` nel campo nome file, fai clic destro sulle cartelle per **Open in new window**, e usa **Properties → Open file location** per espandere la navigazione.
- **Create execution paths from dialogs**: Crea un nuovo file e rinominalo in `.CMD` o `.BAT`, oppure crea un collegamento che punti a `%WINDIR%\System32` (o a un binario specifico come `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Se puoi navigare fino a `cmd.exe`, prova a **drag-and-drop** qualsiasi file su di esso per aprire un prompt. Se Task Manager è raggiungibile (`CTRL+SHIFT+ESC`), usa **Run new task**.
- **Task Scheduler bypass**: Se le shell interattive sono bloccate ma è consentita la schedulazione, crea un task per eseguire `cmd.exe` (GUI `taskschd.msc` o `schtasks.exe`).
- **Weak allowlists**: Se l'esecuzione è permessa per **filename/extension**, rinomina il tuo payload con un nome consentito. Se è permessa per **directory**, copia il payload in una cartella di programmi consentita ed eseguilo da lì.
- **Trova percorsi di staging scrivibili**: Inizia da `%TEMP%` e enumera le cartelle scrivibili con Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Passo successivo**: Se ottieni una shell, pivotare alla checklist Windows LPE:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Scarica i tuoi binari

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Accesso al filesystem dal browser

| PERCORSO            | PERCORSO          | PERCORSO           | PERCORSO            |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Scorciatoie

- Sticky Keys – Premere SHIFT 5 volte
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Tenere premuto NUMLOCK per 5 secondi
- Filter Keys – Tenere premuto il tasto SHIFT destro per 12 secondi
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Mostra Desktop
- WINDOWS+E – Avvia Windows Explorer
- WINDOWS+R – Esegui
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Cerca
- SHIFT+F10 – Menu contestuale
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – Schermata iniziale nelle versioni più recenti di Windows
- F1 – Help F3 – Search
- F6 – Barra degli indirizzi
- F11 – Passa a schermo intero in Internet Explorer
- CTRL+H – Cronologia di Internet Explorer
- CTRL+T – Internet Explorer – Nuova scheda
- CTRL+N – Internet Explorer – Nuova finestra
- CTRL+O – Apri file
- CTRL+S – Salva CTRL+N – Nuovo RDP / Citrix

### Gesti

- Scorri dal lato sinistro verso destra per vedere tutte le finestre aperte, minimizzare l'app Kiosk e accedere direttamente all'intero OS;
- Scorri dal lato destro verso sinistra per aprire l'Action Center, minimizzare l'app Kiosk e accedere direttamente all'intero OS;
- Scorri dall'orlo superiore verso l'interno per rendere visibile la barra del titolo per un'app aperta in modalità a schermo intero;
- Scorri verso l'alto dal fondo per mostrare la barra delle applicazioni in un'app a schermo intero.

### Trucchi per Internet Explorer

#### 'Image Toolbar'

È una barra degli strumenti che appare in alto a sinistra dell'immagine quando viene cliccata. Potrai Save, Print, Mailto, Open "My Pictures" in Explorer. Il Kiosk deve usare Internet Explorer.

#### Shell Protocol

Digita questi URL per ottenere una vista di Explorer:

- `shell:Administrative Tools`
- `shell:DocumentsLibrary`
- `shell:Libraries`
- `shell:UserProfiles`
- `shell:Personal`
- `shell:SearchHomeFolder`
- `shell:NetworkPlacesFolder`
- `shell:SendTo`
- `shell:UserProfiles`
- `shell:Common Administrative Tools`
- `shell:MyComputerFolder`
- `shell:InternetFolder`
- `Shell:Profile`
- `Shell:ProgramFiles`
- `Shell:System`
- `Shell:ControlPanelFolder`
- `Shell:Windows`
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Control Panel
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> My Computer
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> My Network Places
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Mostrare le estensioni dei file

Consulta questa pagina per maggiori informazioni: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Trucchi per browser

Versioni di backup iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Crea un dialogo comune usando JavaScript e accedi a file explorer: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gesti e pulsanti

- Scorri verso l'alto con quattro (o cinque) dita / Doppio tap sul pulsante Home: Per visualizzare il multitask view e cambiare App
- Scorri in una direzione con quattro o cinque dita: Per passare all'App successiva/precedente
- Pizzica lo schermo con cinque dita / Tocca il pulsante Home / Scorri verso l'alto con 1 dito dal fondo dello schermo in un movimento rapido verso l'alto: Per accedere alla Home
- Scorri con un dito dal fondo dello schermo per 1-2 pollici (lento): Apparirà il dock
- Scorri verso il basso dall'alto del display con 1 dito: Per vedere le notifiche
- Scorri verso il basso con 1 dito l'angolo in alto a destra dello schermo: Per vedere il control centre dell'iPad Pro
- Scorri con 1 dito da sinistra dello schermo di 1-2 pollici: Per vedere la Today view
- Scorri rapidamente con 1 dito dal centro dello schermo verso destra o sinistra: Per cambiare all'App successiva/precedente
- Premi e tieni premuto il pulsante On/Off/Sleep nell'angolo in alto a destra dell'iPad + Muovi lo slider Slide to power off tutto verso destra: Per spegnere
- Premi il pulsante On/Off/Sleep nell'angolo in alto a destra dell'iPad e il pulsante Home per alcuni secondi: Per forzare lo spegnimento
- Premi il pulsante On/Off/Sleep nell'angolo in alto a destra dell'iPad e il pulsante Home rapidamente: Per fare uno screenshot che apparirà in basso a sinistra del display. Premendo entrambi i pulsanti contemporaneamente molto brevemente; se li tieni premuti qualche secondo verrà eseguito uno spegnimento forzato.

### Scorciatoie

Dovresti avere una tastiera per iPad o un adattatore per tastiera USB. Qui vengono mostrate solo le scorciatoie che possono aiutare a uscire dall'applicazione.

| Key | Name         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Left Arrow   |
| →   | Right Arrow  |
| ↑   | Up Arrow     |
| ↓   | Down Arrow   |

#### Scorciatoie di sistema

Queste scorciatoie sono per le impostazioni visive e del suono, a seconda dell'uso dell'iPad.

| Shortcut | Azione                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Diminuire la luminosità                                                        |
| F2       | Aumentare la luminosità                                                        |
| F7       | Brano precedente                                                               |
| F8       | Play/pause                                                                     |
| F9       | Brano successivo                                                               |
| F10      | Muto                                                                           |
| F11      | Diminuire il volume                                                            |
| F12      | Aumentare il volume                                                            |
| ⌘ Space  | Visualizza la lista delle lingue disponibili; per sceglierne una, tocca di nuovo la barra spaziatrice. |

#### Navigazione iPad

| Shortcut                                           | Azione                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Vai alla Home                                           |
| ⌘⇧H (Command-Shift-H)                              | Vai alla Home                                           |
| ⌘ (Space)                                          | Apri Spotlight                                          |
| ⌘⇥ (Command-Tab)                                   | Elenca le ultime dieci app usate                        |
| ⌘\~                                                | Vai all'ultima app                                       |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (compare in basso a sinistra per salvarlo o agire su di esso) |
| ⌘⇧4                                                | Screenshot e aprilo nell'editor                         |
| Premi e tieni premuto ⌘                             | Elenco delle scorciatoie disponibili per l'App         |
| ⌘⌥D (Command-Option/Alt-D)                         | Mostra il dock                                          |
| ^⌥H (Control-Option-H)                             | Pulsante Home                                           |
| ^⌥H H (Control-Option-H-H)                         | Mostra la barra multitask                               |
| ^⌥I (Control-Option-i)                             | Selettore elementi                                      |
| Escape                                             | Pulsante Indietro                                       |
| → (Right arrow)                                    | Voce successiva                                         |
| ← (Left arrow)                                     | Voce precedente                                         |
| ↑↓ (Up arrow, Down arrow)                          | Seleziona/attiva l'elemento selezionato                |
| ⌥ ↓ (Option-Down arrow)                            | Scorri verso il basso                                   |
| ⌥↑ (Option-Up arrow)                               | Scorri verso l'alto                                     |
| ⌥← o ⌥→ (Option-Left arrow o Option-Right arrow)   | Scorri a sinistra o a destra                           |
| ^⌥S (Control-Option-S)                             | Attiva/disattiva la lettura vocale VoiceOver            |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Passa all'app precedente                                |
| ⌘⇥ (Command-Tab)                                   | Torna all'app originale                                 |
| ←+→, then Option + ← or Option+→                   | Naviga attraverso il Dock                               |

#### Scorciatoie Safari

| Shortcut                | Azione                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Seleziona la barra indirizzi                     |
| ⌘T                      | Apri una nuova scheda                            |
| ⌘W                      | Chiudi la scheda corrente                        |
| ⌘R                      | Ricarica la scheda corrente                      |
| ⌘.                      | Interrompi il caricamento della scheda corrente  |
| ^⇥                      | Passa alla scheda successiva                     |
| ^⇧⇥ (Control-Shift-Tab) | Torna alla scheda precedente                     |
| ⌘L                      | Seleziona il campo di input/URL per modificarlo  |
| ⌘⇧T (Command-Shift-T)   | Apri l'ultima scheda chiusa (può essere usato più volte) |
| ⌘\[                     | Torna indietro di una pagina nella cronologia    |
| ⌘]                      | Vai avanti di una pagina nella cronologia        |
| ⌘⇧R                     | Attiva la Reader Mode                             |

#### Scorciatoie Mail

| Shortcut                   | Azione                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Seleziona la barra indirizzi |
| ⌘T                         | Apri una nuova scheda        |
| ⌘W                         | Chiudi la scheda corrente    |
| ⌘R                         | Ricarica la scheda corrente  |
| ⌘.                         | Interrompi il caricamento     |
| ⌘⌥F (Command-Option/Alt-F) | Cerca nella tua mailbox      |

## Riferimenti

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
