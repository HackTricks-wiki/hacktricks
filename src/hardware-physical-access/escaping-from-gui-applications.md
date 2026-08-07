# Uscire dai KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Controllare il dispositivo fisico

| Componente   | Azione                                                             |
| ------------ | ------------------------------------------------------------------ |
| Pulsante di accensione | Spegnere e riaccendere il dispositivo potrebbe mostrare la schermata iniziale |
| Cavo di alimentazione  | Verificare se il dispositivo si riavvia quando l'alimentazione viene interrotta brevemente |
| Porte USB    | Collegare una tastiera fisica con più shortcut                    |
| Ethernet     | Una scansione della rete o sniffing potrebbe consentire ulteriori attività di exploitation |

## Controllare le possibili azioni all'interno della GUI application

I **Common Dialogs** sono quelle opzioni per **salvare un file**, **aprire un file**, selezionare un font, un colore... La maggior parte di essi **offrirà una funzionalità completa di Explorer**. Ciò significa che sarà possibile accedere alle funzionalità di Explorer se si riesce ad accedere a queste opzioni:

- Chiudi/Chiudi come
- Apri/Apri con
- Stampa
- Esporta/Importa
- Cerca
- Scansiona

Verificare se è possibile:

- Modificare o creare nuovi file
- Creare symbolic links
- Ottenere accesso ad aree con restrizioni
- Eseguire altre app

### Command Execution

Forse **usando un'opzione `Open with`**\*\* è possibile aprire/eseguire una shell di qualche tipo.

#### Windows

Ad esempio _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ trovare qui altri binary che possono essere usati per eseguire comandi (e svolgere azioni impreviste): [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Altri qui: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Bypassare le restrizioni sui path

- **Environment variables**: Esistono molte environment variables che puntano a un path
- **Altri protocolli**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcut**: CTRL+N (apre una nuova sessione), CTRL+R (esegue comandi), CTRL+SHIFT+ESC (Task Manager), Windows+E (apre Explorer), CTRL-B, CTRL-I (Preferiti), CTRL-H (Cronologia), CTRL-L, CTRL-O (Dialog di apertura file), CTRL-P (Dialog di stampa), CTRL-S (Salva con nome)
- Menu amministrativo nascosto: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Path per connettersi a cartelle condivise. Provare a connettersi al C$ della macchina locale ("\\\127.0.0.1\c$\Windows\System32")
- **Altri UNC paths:**

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

### Uscite da Restricted Desktop (Citrix/RDS/VDI)

- **Pivot tramite finestre di dialogo**: Usare le finestre di dialogo *Open/Save/Print-to-file* come una versione semplificata di Explorer. Provare `*.*` / `*.exe` nel campo del nome file, fare clic con il tasto destro sulle cartelle per **Open in new window** e usare **Properties → Open file location** per ampliare la navigazione.<sup>[[1]](#references)</sup>
- **Creare percorsi di esecuzione dalle finestre di dialogo**: Creare un nuovo file e rinominarlo in `.CMD` o `.BAT`, oppure creare uno shortcut che punti a `%WINDIR%\System32` (o a un binary specifico come `%WINDIR%\System32\cmd.exe`).
- **Pivot per l'avvio di una shell**: Se è possibile navigare fino a `cmd.exe`, provare a usare il **drag-and-drop** di un file qualsiasi su di esso per avviare un prompt. Se Task Manager è raggiungibile (`CTRL+SHIFT+ESC`), usare **Run new task**.
- **Bypass di Task Scheduler**: Se le shell interattive sono bloccate ma la schedulazione è consentita, creare un task per eseguire `cmd.exe` (GUI `taskschd.msc` o `schtasks.exe`).
- **Allowlists deboli**: Se l'esecuzione è consentita in base a **filename/extension**, rinominare il payload con un nome consentito. Se è consentita in base alla **directory**, copiare il payload in una cartella di programmi consentita ed eseguirlo da lì.
- **Trovare path di staging scrivibili**: Iniziare da `%TEMP%` ed enumerare le cartelle scrivibili con Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Passo successivo**: Se ottieni una shell, passa alla checklist Windows LPE:
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
- Contrasto elevato – SHIFT+ALT+PRINTSCN
- Toggle Keys – Tieni premuto NUMLOCK per 5 secondi
- Filter Keys – Tieni premuto SHIFT destro per 12 secondi
- WINDOWS+F1 – Ricerca di Windows
- WINDOWS+D – Mostra il desktop
- WINDOWS+E – Avvia Windows Explorer
- WINDOWS+R – Esegui
- WINDOWS+U – Centro accessibilità
- WINDOWS+F – Cerca
- SHIFT+F10 – Menu contestuale
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – Schermata iniziale nelle versioni più recenti di Windows
- F1 – Guida F3 – Cerca
- F6 – Barra degli indirizzi
- F11 – Attiva/disattiva lo schermo intero in Internet Explorer
- CTRL+H – Cronologia di Internet Explorer
- CTRL+T – Internet Explorer – Nuova scheda
- CTRL+N – Internet Explorer – Nuova pagina
- CTRL+O – Apri file
- CTRL+S – Salva CTRL+N – Nuova sessione RDP / Citrix

### Scorrimenti

- Scorri dal lato sinistro verso destra per visualizzare tutte le finestre aperte, riducendo a icona l'app KIOSK e accedendo direttamente all'intero sistema operativo;
- Scorri dal lato destro verso sinistra per aprire il Centro notifiche, riducendo a icona l'app KIOSK e accedendo direttamente all'intero sistema operativo;
- Scorri dal bordo superiore per rendere visibile la barra del titolo di un'app aperta in modalità schermo intero;
- Scorri verso l'alto dal bordo inferiore per mostrare la barra delle applicazioni in un'app a schermo intero.

### Trucchi di Internet Explorer

#### 'Barra degli strumenti immagini'

È una barra degli strumenti che appare nella parte superiore sinistra dell'immagine quando viene selezionata. Sarà possibile salvare, stampare, inviare tramite Mailto e aprire "Immagini" in Explorer. Il Kiosk deve utilizzare Internet Explorer.

#### Protocollo Shell

Digita questi URL per ottenere una visualizzazione di Explorer:

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
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Pannello di controllo
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Computer
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Risorse di rete
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Mostra estensioni dei file

Consulta questa pagina per ulteriori informazioni: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)<sup>[[7]](#references)</sup>

## Trucchi dei browser

Versioni di backup di iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Crea una finestra di dialogo comune usando JavaScript e accedi a Esplora file: `document.write('<input/type=file>')`<sup>[[2]](#references)</sup>\
Fonte: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gesti e pulsanti

- Scorri verso l'alto con quattro (o cinque) dita / Tocca due volte il pulsante Home: per visualizzare la vista multitasking e cambiare app
- Scorri in una direzione o nell'altra con quattro o cinque dita: per passare all'app successiva/precedente
- Pizzica lo schermo con cinque dita / Tocca il pulsante Home / Scorri verso l'alto con 1 dito dal fondo dello schermo con un movimento rapido verso l'alto: per accedere alla Home
- Scorri con un dito dal fondo dello schermo per appena 1-2 pollici (lentamente): apparirà il dock
- Scorri verso il basso dalla parte superiore del display con 1 dito: per visualizzare le notifiche
- Scorri verso il basso con 1 dito dall'angolo superiore destro dello schermo: per visualizzare il Centro di Controllo dell'iPad Pro
- Scorri con 1 dito dal lato sinistro dello schermo per 1-2 pollici: per visualizzare la vista Oggi
- Scorri rapidamente con 1 dito dal centro dello schermo verso destra o sinistra: per passare all'app successiva/precedente
- Tieni premuto il pulsante On/**Off**/Sleep nell'angolo superiore destro dell'**iPad +** sposta completamente verso destra il cursore **spegni**: per spegnere il dispositivo
- Premi il pulsante On/**Off**/Sleep nell'angolo superiore destro dell'**iPad e il pulsante Home per alcuni secondi**: per forzare lo spegnimento
- Premi rapidamente il pulsante On/**Off**/Sleep nell'angolo superiore destro dell'**iPad e il pulsante Home**: per acquisire uno screenshot che apparirà nell'angolo inferiore sinistro del display. Premi entrambi i pulsanti contemporaneamente per un istante; se li tieni premuti per alcuni secondi verrà eseguito uno spegnimento forzato.<sup>[[3]](#references)</sup>

### Scorciatoie

Dovresti avere una tastiera per iPad o un adattatore per tastiera USB. Qui verranno mostrate solo le scorciatoie che possono aiutare a uscire dall'applicazione.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

| Tasto | Nome         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Freccia sinistra   |
| →   | Freccia destra  |
| ↑   | Freccia su     |
| ↓   | Freccia giù   |

#### Scorciatoie di sistema

Queste scorciatoie riguardano le impostazioni visive e audio, a seconda dell'utilizzo dell'iPad.

| Scorciatoia | Azione                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Riduci luminosità dello schermo                                                                    |
| F2       | Aumenta luminosità dello schermo                                                                |
| F7       | Brano precedente                                                                  |
| F8       | Riproduci/metti in pausa                                                                     |
| F9       | Salta brano                                                                      |
| F10      | Disattiva audio                                                                           |
| F11      | Diminuisci volume                                                                |
| F12      | Aumenta volume                                                                |
| ⌘ Space  | Visualizza un elenco delle lingue disponibili; per sceglierne una, tocca nuovamente la barra spaziatrice. |

#### Navigazione dell'iPad

| Scorciatoia                                           | Azione                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Vai alla Home                                              |
| ⌘⇧H (Command-Shift-H)                              | Vai alla Home                                              |
| ⌘ (Space)                                          | Apri Spotlight                                          |
| ⌘⇥ (Command-Tab)                                   | Elenca le ultime dieci app utilizzate                                 |
| ⌘\~                                                | Vai all'app precedente                                       |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (rimane visualizzato nell'angolo inferiore sinistro per salvarlo o utilizzarlo) |
| ⌘⇧4                                                | Acquisisci uno screenshot e aprilo nell'editor                    |
| Premi e tieni premuto ⌘                                   | Elenco delle scorciatoie disponibili per l'app                 |
| ⌘⌥D (Command-Option/Alt-D)                         | Visualizza il dock                                      |
| ^⌥H (Control-Option-H)                             | Pulsante Home                                             |
| ^⌥H H (Control-Option-H-H)                         | Mostra la barra del multitasking                                      |
| ^⌥I (Control-Option-i)                             | Selettore degli elementi                                            |
| Escape                                             | Pulsante Indietro                                             |
| → (Right arrow)                                    | Elemento successivo                                               |
| ← (Left arrow)                                     | Elemento precedente                                           |
| ↑↓ (Up arrow, Down arrow)                          | Tocca contemporaneamente l'elemento selezionato                        |
| ⌥ ↓ (Option-Down arrow)                            | Scorri verso il basso                                             |
| ⌥↑ (Option-Up arrow)                               | Scorri verso l'alto                                               |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Scorri verso sinistra o destra                                    |
| ^⌥S (Control-Option-S)                             | Attiva o disattiva la sintesi vocale di VoiceOver                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Passa all'app precedente                              |
| ⌘⇥ (Command-Tab)                                   | Torna all'app originale                         |
| ←+→, then Option + ← or Option+→                   | Naviga nel Dock                                   |

#### Scorciatoie di Safari

| Scorciatoia                | Azione                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Apri posizione                                    |
| ⌘T                      | Apri una nuova scheda                                   |
| ⌘W                      | Chiudi la scheda corrente                            |
| ⌘R                      | Aggiorna la scheda corrente                          |
| ⌘.                      | Interrompi il caricamento della scheda corrente                     |
| ^⇥                      | Passa alla scheda successiva                           |
| ^⇧⇥ (Control-Shift-Tab) | Passa alla scheda precedente                         |
| ⌘L                      | Seleziona il campo di testo/URL per modificarlo     |
| ⌘⇧T (Command-Shift-T)   | Apri l'ultima scheda chiusa (può essere utilizzato più volte) |
| ⌘\[                     | Torna indietro di una pagina nella cronologia di navigazione      |
| ⌘]                      | Vai avanti di una pagina nella cronologia di navigazione   |
| ⌘⇧R                     | Attiva la modalità Lettore                             |

#### Scorciatoie di Mail

| Scorciatoia                   | Azione                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Apri posizione                |
| ⌘T                         | Apri una nuova scheda               |
| ⌘W                         | Chiudi la scheda corrente               |
| ⌘R                         | Aggiorna la scheda corrente               |
| ⌘.                         | Interrompi il caricamento della scheda corrente |
| ⌘⌥F (Command-Option/Alt-F) | Cerca nella casella di posta       |

## Riferimenti

- [1] [Uscire da Citrix e da altri ambienti desktop con restrizioni](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [2] [Dammi un browser e ti darò una shell](https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
- [3] [6 gesti per iPad che devi conoscere](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [4] [Guida alle scorciatoie per iPad](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [5] [Le migliori scorciatoie da tastiera per iPad](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [6] [Scorciatoie da tastiera per iPad](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
- [7] [howtohaven.com - Mostrare le estensioni dei file in Windows Explorer](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

{{#include ../banners/hacktricks-training.md}}
