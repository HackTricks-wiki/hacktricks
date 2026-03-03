# Evasione dai KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Controlla il dispositivo fisico

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | Spegnere e riaccendere il dispositivo può mostrare la schermata iniziale    |
| Power cable  | Verifica se il dispositivo si riavvia quando l'alimentazione viene interrotta brevemente |
| USB ports    | Collega una tastiera fisica per più scorciatoie                      |
| Ethernet     | Una scansione di rete o sniffing può consentire ulteriori sfruttamenti           |

## Controlla le possibili azioni all'interno dell'applicazione GUI

**I dialoghi comuni** sono quelle opzioni per **salvare un file**, **aprire un file**, selezionare un font, un colore... La maggior parte di essi **offrirà una piena funzionalità di Explorer**. Questo significa che potrai accedere alle funzionalità di Explorer se riesci ad accedere a queste opzioni:

- Chiudi/Chiudi come
- Apri/Apri con
- Stampa
- Esporta/Importa
- Cerca
- Scansiona

Dovresti verificare se puoi:

- Modificare o creare nuovi file
- Creare link simbolici
- Accedere ad aree ristrette
- Eseguire altre app

### Esecuzione di comandi

Forse **usando `Open with`** option\*\* puoi aprire/eseguire una sorta di shell.

#### Windows

Per esempio _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ trova più binari che possono essere usati per eseguire comandi (e compiere azioni inaspettate) qui: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Maggiori informazioni qui: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Bypassare le restrizioni di percorso

- **Environment variables**: Ci sono molte variabili d'ambiente che puntano a percorsi
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (apri nuova sessione), CTRL+R (Esegui comandi), CTRL+SHIFT+ESC (Task Manager), Windows+E (apri Explorer), CTRL-B, CTRL-I (Preferiti), CTRL-H (Cronologia), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Salva con nome)
- Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Percorsi per connettersi a cartelle condivise. Dovresti provare a connetterti al C$ della macchina locale ("\\\127.0.0.1\c$\Windows\System32")
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

### Breakout del Desktop Restrittto (Citrix/RDS/VDI)

- **Dialog-box pivoting**: Usa i dialoghi *Open/Save/Print-to-file* come Explorer-lite. Prova `*.*` / `*.exe` nel campo nome file, clicca con il destro sulle cartelle per **Apri in nuova finestra**, e usa **Proprietà → Apri percorso file** per espandere la navigazione.
- **Crea percorsi di esecuzione dai dialoghi**: Crea un nuovo file e rinominalo in `.CMD` o `.BAT`, oppure crea un collegamento che punti a `%WINDIR%\System32` (o a un binario specifico come `%WINDIR%\System32\cmd.exe`).
- **Pivot di lancio shell**: Se riesci a navigare fino a `cmd.exe`, prova il **drag-and-drop** di qualsiasi file su di esso per avviare un prompt. Se Task Manager è raggiungibile (`CTRL+SHIFT+ESC`), usa **Esegui nuova attività**.
- **Bypass Task Scheduler**: Se le shell interattive sono bloccate ma la schedulazione è consentita, crea un task per eseguire `cmd.exe` (GUI `taskschd.msc` o `schtasks.exe`).
- **Allowlist deboli**: Se l'esecuzione è consentita per nome file/estensione, rinomina il tuo payload in un nome permesso. Se è consentita per directory, copia il payload in una cartella di programma permessa ed eseguilo da lì.
- **Trova percorsi di staging scrivibili**: Inizia con %TEMP% ed enumera le cartelle scrivibili con Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Prossimo passo**: Se ottieni una shell, pivot to the Windows LPE checklist:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Scarica i tuoi binari

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Editor del registro: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Accesso al filesystem dal browser

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Scorciatoie

- Sticky Keys – Premi SHIFT 5 volte
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Tieni premuto NUMLOCK per 5 secondi
- Filter Keys – Tieni premuto il tasto SHIFT destro per 12 secondi
- WINDOWS+F1 – Ricerca di Windows
- WINDOWS+D – Mostra Desktop
- WINDOWS+E – Avvia Windows Explorer
- WINDOWS+R – Esegui
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Cerca
- SHIFT+F10 – Menu contestuale
- CTRL+SHIFT+ESC – Gestione attività
- CTRL+ALT+DEL – Schermata di blocco nelle versioni più recenti di Windows
- F1 – Aiuto F3 – Cerca
- F6 – Barra degli indirizzi
- F11 – Passa a schermo intero in Internet Explorer
- CTRL+H – Cronologia di Internet Explorer
- CTRL+T – Internet Explorer – Nuova scheda
- CTRL+N – Internet Explorer – Nuova pagina
- CTRL+O – Apri file
- CTRL+S – Salva CTRL+N – Nuovo RDP / Citrix

### Scorrimenti (Swipes)

- Scorri dal lato sinistro verso destra per vedere tutte le finestre aperte, minimizzare l'app KIOSK e accedere direttamente all'intero OS;
- Scorri dal lato destro verso sinistra per aprire Action Center, minimizzare l'app KIOSK e accedere direttamente all'intero OS;
- Scorri dall'alto verso il basso per rendere visibile la barra del titolo di un'app aperta in modalità schermo intero;
- Scorri verso l'alto dal basso per mostrare la taskbar in un'app a schermo intero.

### Trucchi di Internet Explorer

#### 'Image Toolbar'

È una barra degli strumenti che appare in alto a sinistra di un'immagine quando viene cliccata. Potrai Salvare, Stampare, Mailto, Aprire "My Pictures" in Explorer. L'app Kiosk deve usare Internet Explorer.

#### Protocollo Shell

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

### Mostra le estensioni dei file

Controlla questa pagina per maggiori informazioni: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Trucchi per i browser

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Crea una common dialog usando JavaScript e accedi a Esplora risorse: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gesti e pulsanti

- Scorri verso l'alto con quattro (o cinque) dita / Doppio tap sul pulsante Home: Per visualizzare la vista multitasking e cambiare App
- Scorri con quattro o cinque dita in una direzione o nell'altra: Per passare all'App successiva/precedente
- Pizzica lo schermo con cinque dita / Premi il pulsante Home / Scorri verso l'alto con 1 dito dal bordo inferiore dello schermo in un movimento rapido verso l'alto: Per accedere alla Home
- Scorri con un dito dal fondo dello schermo per 1-2 pollici (lento): Comparirà il dock
- Scorri verso il basso dalla parte superiore del display con 1 dito: Per visualizzare le notifiche
- Scorri verso il basso con 1 dito l'angolo in alto a destra dello schermo: Per vedere il centro di controllo dell'iPad Pro
- Scorri con 1 dito dall'estrema sinistra dello schermo per 1-2 pollici: Per vedere la vista Oggi (Today view)
- Scorri velocemente con 1 dito dal centro dello schermo verso destra o sinistra: Per cambiare all'App successiva/precedente
- Premi e tieni premuto il pulsante On/**Off**/Sleep nell'angolo in alto a destra del **iPad +** Muovi lo slider **power off** tutto a destra: Per spegnere
- Premi il pulsante On/**Off**/Sleep nell'angolo in alto a destra del **iPad e il pulsante Home per alcuni secondi**: Per forzare lo spegnimento
- Premi rapidamente il pulsante On/**Off**/Sleep nell'angolo in alto a destra del **iPad e il pulsante Home**: Per fare uno screenshot che apparirà in basso a sinistra del display. Premi entrambi i pulsanti contemporaneamente molto brevemente; se li tieni premuti qualche secondo verrà eseguito uno spegnimento forzato.

### Scorciatoie

Dovresti avere una tastiera per iPad o un adattatore tastiera USB. Qui sono mostrate solo le scorciatoie che possono aiutare a uscire dall'applicazione.

| Key | Name                 |
| --- | -------------------- |
| ⌘   | Comando              |
| ⌥   | Opzione (Alt)        |
| ⇧   | Maiusc               |
| ↩   | Invio                |
| ⇥   | Tab                  |
| ^   | Control              |
| ←   | Freccia sinistra     |
| →   | Freccia destra       |
| ↑   | Freccia su           |
| ↓   | Freccia giù          |

#### Scorciatoie di sistema

Queste scorciatoie riguardano le impostazioni visive e del suono, a seconda dell'uso dell'iPad.

| Shortcut | Azione                                                                 |
| -------- | ---------------------------------------------------------------------- |
| F1       | Riduci luminosità                                                      |
| F2       | Aumenta luminosità                                                     |
| F7       | Brano precedente                                                       |
| F8       | Play/pausa                                                             |
| F9       | Salta brano                                                            |
| F10      | Muto                                                                   |
| F11      | Diminuisci volume                                                      |
| F12      | Aumenta volume                                                         |
| ⌘ Space  | Visualizza la lista delle lingue disponibili; per sceglierne una, premi di nuovo la barra spaziatrice. |

#### Navigazione iPad

| Shortcut                                           | Azione                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Vai alla Home                                           |
| ⌘⇧H (Command-Shift-H)                              | Vai alla Home                                           |
| ⌘ (Space)                                          | Apri Spotlight                                          |
| ⌘⇥ (Command-Tab)                                   | Elenca le ultime dieci app usate                        |
| ⌘\~                                                | Vai all'ultima App                                       |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (compare in basso a sinistra per salvare o agire) |
| ⌘⇧4                                                | Screenshot e aprilo nell'editor                         |
| Press and hold ⌘                                   | Elenco delle scorciatoie disponibili per l'App         |
| ⌘⌥D (Command-Option/Alt-D)                         | Mostra il dock                                          |
| ^⌥H (Control-Option-H)                             | Pulsante Home                                           |
| ^⌥H H (Control-Option-H-H)                         | Mostra la barra multitasking                            |
| ^⌥I (Control-Option-i)                             | Selettore oggetti                                       |
| Escape                                             | Pulsante Indietro                                       |
| → (Right arrow)                                    | Elemento successivo                                     |
| ← (Left arrow)                                     | Elemento precedente                                     |
| ↑↓ (Up arrow, Down arrow)                          | Tocca simultaneamente l'elemento selezionato           |
| ⌥ ↓ (Option-Down arrow)                            | Scorri verso il basso                                   |
| ⌥↑ (Option-Up arrow)                               | Scorri verso l'alto                                     |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Scorri a sinistra o a destra                            |
| ^⌥S (Control-Option-S)                             | Attiva o disattiva la voce di VoiceOver                 |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Passa all'app precedente                                |
| ⌘⇥ (Command-Tab)                                   | Torna all'app originale                                 |
| ←+→, then Option + ← or Option+→                   | Naviga nel Dock                                         |

#### Scorciatoie Safari

| Shortcut                | Azione                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Apri posizione                                   |
| ⌘T                      | Apri una nuova scheda                            |
| ⌘W                      | Chiudi la scheda corrente                         |
| ⌘R                      | Ricarica la scheda corrente                       |
| ⌘.                      | Interrompi il caricamento della scheda corrente   |
| ^⇥                      | Passa alla scheda successiva                      |
| ^⇧⇥ (Control-Shift-Tab) | Vai alla scheda precedente                        |
| ⌘L                      | Seleziona il campo di input/URL per modificarlo   |
| ⌘⇧T (Command-Shift-T)   | Apri l'ultima scheda chiusa (può essere usato più volte) |
| ⌘\[                     | Torna indietro di una pagina nella cronologia     |
| ⌘]                      | Avanti di una pagina nella cronologia             |
| ⌘⇧R                     | Attiva Reader Mode                                 |

#### Scorciatoie Mail

| Shortcut                   | Azione                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Apri posizione               |
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
