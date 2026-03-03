# Bypass di Admin Protection tramite UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Panoramica
- Windows AppInfo espone `RAiLaunchAdminProcess` per spawnare processi UIAccess (intesi per l'accessibilità). UIAccess bypassa la maggior parte del filtro dei messaggi di User Interface Privilege Isolation (UIPI) in modo che il software di accessibilità possa controllare UI a IL superiore.
- Abilitare UIAccess direttamente richiede `NtSetInformationToken(TokenUIAccess)` con **SeTcbPrivilege**, quindi i chiamanti a basso privilegio si affidano al servizio. Il servizio esegue tre controlli sul binario target prima di impostare UIAccess:
- Il manifest incorporato contiene `uiAccess="true"`.
- Firmato da un qualsiasi certificato attendibile dallo store root della Local Machine (nessun requisito EKU/Microsoft).
- Collocato in un percorso riservato agli amministratori sul disco di sistema (es., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, escludendo specifici sottopercorsi scrivibili).
- `RAiLaunchAdminProcess` non mostra alcuna richiesta di consenso per i lanci UIAccess (altrimenti gli strumenti di accessibilità non potrebbero interagire con la prompt).

## Modellazione del token e livelli di integrità
- Se i controlli hanno esito positivo, AppInfo **copia il token del chiamante**, abilita UIAccess e aumenta il Integrity Level (IL):
- Limited admin user (l'utente è nel gruppo Administrators ma esegue in modalità filtrata) ➜ **High IL**.
- Non-admin user ➜ IL aumentato di **+16 livelli** fino a un limite **High** (System IL non viene mai assegnato).
- Se il token del chiamante ha già UIAccess, l'IL rimane invariato.
- “Ratchet” trick: un processo UIAccess può disabilitare UIAccess su se stesso, rilanciarsi tramite `RAiLaunchAdminProcess` e ottenere un ulteriore incremento di +16 IL. Medium➜High richiede 255 rilanci (rumoroso, ma funziona).

## Perché UIAccess abilita un bypass di Admin Protection
- UIAccess permette a un processo a IL inferiore di inviare messaggi di finestra a finestre a IL superiore (bypassando i filtri UIPI). A **uguale IL**, primitive UI classiche come `SetWindowsHookEx` **permettono l'iniezione di codice/caricamento di DLL** in qualsiasi processo che possieda una finestra (incluse le **message-only windows** usate da COM).
- Admin Protection lancia il processo UIAccess sotto l'identità dell'**utente limitato** ma a **High IL**, silenziosamente. Una volta che codice arbitrario viene eseguito all'interno di quel processo UIAccess a High IL, l'attaccante può iniettare in altri processi High IL sul desktop (anche appartenenti a utenti diversi), rompendo la separazione prevista.

## Primitive HWND-to-process handle (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Su Windows 10 1803+ l'API è stata spostata in Win32k (`NtUserGetWindowProcessHandle`) e può aprire un handle di processo usando un `DesiredAccess` fornito dal chiamante. Il percorso kernel usa `ObOpenObjectByPointer(..., KernelMode, ...)`, che bypassa i normali controlli di accesso in user-mode.
- Preconditions in pratica: la finestra target deve essere sullo stesso desktop, e i controlli UIPI devono passare. Storicamente, un chiamante con UIAccess poteva bypassare il fallimento UIPI e ottenere comunque un handle in kernel-mode (fixato come CVE-2023-41772).
- Impatto: un handle di finestra diventa una **capability** per ottenere un handle di processo potente (comunemente `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) che il chiamante normalmente non potrebbe aprire. Questo abilita accesso cross-sandbox e può infrangere i confini di Protected Process / PPL se il target espone qualsiasi finestra (incluse le message-only windows).
- Flusso pratico di abuso: enumerare o individuare HWND (es., `EnumWindows`/`FindWindowEx`), risolvere il PID proprietario (`GetWindowThreadProcessId`), chiamare `GetProcessHandleFromHwnd`, quindi usare l'handle restituito per primitive di lettura/scrittura di memoria o hijack di codice.
- Comportamento post-fix: UIAccess non concede più aperture in kernel-mode su fallimento UIPI e i diritti di accesso permessi sono limitati all'insieme legacy per gli hook; Windows 11 24H2 aggiunge controlli di protezione processo e percorsi più sicuri feature-flagged. Disabilitare UIPI a livello di sistema (`EnforceUIPI=0`) indebolisce queste protezioni.

## Debolezze nella validazione di directory sicure (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo risolve il percorso fornito tramite `GetFinalPathNameByHandle` e poi applica **controlli stringa allow/deny** contro radici/esclusioni hardcoded. Molte classi di bypass derivano da quella validazione semplicistica:
- **Directory named streams**: directory escluse e scrivibili (es., `C:\Windows\tracing`) possono essere bypassate con uno named stream sulla directory stessa, es. `C:\Windows\tracing:file.exe`. I controlli stringa vedono `C:\Windows\` e non rilevano il sottopercorso escluso.
- **File/directory scrivibile dentro una root consentita**: `CreateProcessAsUser` **non richiede un'estensione `.exe`**. Sovrascrivere qualsiasi file scrivibile sotto una root consentita con un payload eseguibile funziona, oppure copiare un EXE firmato con `uiAccess="true"` in qualsiasi sottodirectory scrivibile (es., ritagli di aggiornamento come `Tasks_Migrated` quando presenti) gli permette di superare il controllo del percorso sicuro.
- **MSIX in `C:\Program Files\WindowsApps` (fixato)**: i non-admin potevano installare pacchetti MSIX firmati che finivano in `WindowsApps`, che non era escluso. Impacchettare un binario UIAccess dentro l'MSIX e poi lanciarlo tramite `RAiLaunchAdminProcess` generava un processo UIAccess a High IL senza prompt. Microsoft ha mitigato escludendo questo percorso; la capability MSIX limitata `uiAccess` richiede già l'installazione come admin.

## Attack workflow (High IL without a prompt)
1. Ottenere/compilare un **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Posizionarlo dove la allowlist di AppInfo lo accetta (o abusare di un edge case di validazione del percorso/artifact scrivibile come sopra).
3. Chiamare `RAiLaunchAdminProcess` per spawnarlo **silenziosamente** con UIAccess + IL elevato.
4. Da quel foothold a High IL, prendere di mira un altro processo High IL sul desktop usando **window hooks/DLL injection** o altre primitive a pari IL per compromettere completamente il contesto admin.

## Enumerazione dei percorsi scrivibili candidati
Eseguire l'helper PowerShell per scoprire oggetti scrivibili/sovrascrivibili all'interno di root nominalmente sicure dalla prospettiva di un token scelto:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Esegui come amministratore per una visibilità maggiore; imposta `-ProcessId` su un low-priv process per rispecchiare l'accesso di quel token.
- Filtra manualmente per escludere sottodirectory note come non consentite prima di usare i candidati con `RAiLaunchAdminProcess`.

## Riferimenti
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
