# Bypass di Admin Protection tramite UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Overview
- Windows AppInfo espone `RAiLaunchAdminProcess` per avviare processi UIAccess (destinati all'accessibilità). UIAccess bypassa la maggior parte del filtraggio dei messaggi di User Interface Privilege Isolation (UIPI) così che il software di accessibilità possa controllare interfacce UI con IL più elevato.
- Abilitare UIAccess direttamente richiede `NtSetInformationToken(TokenUIAccess)` con **SeTcbPrivilege**, quindi i caller a basso privilegio si affidano al servizio. Il servizio esegue tre controlli sul binario target prima di impostare UIAccess:
- Il manifest incorporato contiene `uiAccess="true"`.
- Firmato da qualsiasi certificato trusted dal Local Machine root store (nessun requisito EKU/Microsoft).
- Situato in un percorso accessibile solo dagli amministratori sul sistema drive (es. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, escludendo specifici sottopercorsi scrivibili).
- `RAiLaunchAdminProcess` non mostra alcun prompt di consenso per i lanci UIAccess (altrimenti gli strumenti di accessibilità non potrebbero controllare il prompt).

## Token shaping and integrity levels
- Se i controlli hanno successo, AppInfo **copia il token del chiamante**, abilita UIAccess e aumenta il Integrity Level (IL):
- Limited admin user (l'utente è negli Administrators ma sta eseguendo filtrato) ➜ **High IL**.
- Non-admin user ➜ IL aumentato di **+16 livelli** fino a un tetto **High** (System IL non viene mai assegnato).
- Se il token del chiamante ha già UIAccess, l'IL rimane invariato.
- “Ratchet” trick: un processo UIAccess può disabilitare UIAccess su se stesso, rilanciarsi via `RAiLaunchAdminProcess`, e ottenere un ulteriore incremento di +16 IL. Medium➜High richiede 255 rilanci (rumoroso, ma funziona).

## Why UIAccess enables an Admin Protection escape
- UIAccess permette a un processo con IL inferiore di inviare messaggi di finestra a finestre con IL più alto (bypassando i filtri UIPI). A **IL uguale**, primitive UI classiche come `SetWindowsHookEx` **consentono l'injection di codice/caricamento di DLL** in qualsiasi processo che possieda una finestra (incluse le **message-only windows** usate da COM).
- Admin Protection avvia il processo UIAccess sotto l'identità dell'utente limitato ma a **High IL**, silenziosamente. Una volta che codice arbitrario gira dentro quel processo UIAccess a High IL, l'attaccante può injectare in altri processi a High IL sul desktop (anche appartenenti a utenti diversi), violando la separazione prevista.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Su Windows 10 1803+ l'API è stata spostata in Win32k (`NtUserGetWindowProcessHandle`) e può aprire un handle di processo usando un `DesiredAccess` fornito dal chiamante. Il percorso kernel usa `ObOpenObjectByPointer(..., KernelMode, ...)`, che bypassa i normali controlli di accesso in user-mode.
- Precondizioni in pratica: la finestra target deve essere sullo stesso desktop, e i controlli UIPI devono passare. Storicamente, un chiamante con UIAccess poteva bypassare il fallimento UIPI e ottenere comunque un handle in kernel-mode (fixato come CVE-2023-41772).
- Impatto: un handle di finestra diventa una **capability** per ottenere un potente handle di processo (comunemente `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) che il chiamante normalmente non potrebbe aprire. Questo abilita accesso cross-sandbox e può rompere i confini di Protected Process / PPL se il target espone qualsiasi finestra (incluse le message-only windows).
- Flusso pratico di abuso: enumerare o trovare HWND (es. `EnumWindows`/`FindWindowEx`), risolvere il PID proprietario (`GetWindowThreadProcessId`), chiamare `GetProcessHandleFromHwnd`, quindi usare l'handle restituito per primitive di lettura/scrittura memoria o hijack di codice.
- Comportamento post-fix: UIAccess non concede più aperture in kernel-mode su fallimento UIPI e i diritti di accesso consentiti sono limitati al set legacy degli hook; Windows 11 24H2 aggiunge controlli di process-protection e percorsi più sicuri feature-flagged. Disabilitare UIPI a livello di sistema (`EnforceUIPI=0`) indebolisce queste protezioni.

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo risolve il percorso fornito tramite `GetFinalPathNameByHandle` e poi applica **controlli di stringa allow/deny** contro radici/esclusioni hardcoded. Diverse classi di bypass derivano da quella validazione semplicistica:
- **Directory named streams**: directory escluse come scrivibili (es. `C:\Windows\tracing`) possono essere bypassate con uno named stream sulla directory stessa, es. `C:\Windows\tracing:file.exe`. I controlli stringa vedono `C:\Windows\` e mancano il sottopercorso escluso.
- **File/directory scrivibile dentro una root consentita**: `CreateProcessAsUser` **non richiede un'estensione `.exe`**. Sovrascrivere qualsiasi file scrivibile sotto una root consentita con un payload eseguibile funziona, oppure copiare un EXE firmato con `uiAccess="true"` in qualsiasi sottodirectory scrivibile (es. avanzi di aggiornamenti come `Tasks_Migrated` quando presenti) lo fa passare il controllo sul percorso sicuro.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: i non-admin potevano installare pacchetti MSIX firmati che finivano in `WindowsApps`, che non era escluso. Impacchettare un binario UIAccess dentro l'MSIX e poi avviarlo via `RAiLaunchAdminProcess` generava un processo UIAccess a High IL **senza prompt**. Microsoft ha mitigato escludendo questo percorso; la capability `uiAccess` per MSIX richiede già installazione admin.

## Attack workflow (High IL without a prompt)
1. Ottenere/compilare un **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Posizionarlo dove la allowlist di AppInfo lo accetta (o abusare di un edge case di validazione percorso/artifact scrivibile come sopra).
3. Chiamare `RAiLaunchAdminProcess` per lanciarlo **silenziosamente** con UIAccess + IL elevato.
4. Da quel foothold a High IL, prendere di mira un altro processo a High IL sul desktop usando **window hooks/DLL injection** o altre primitive same-IL per compromettere completamente il contesto admin.

## Enumerating candidate writable paths
Run the PowerShell helper to discover writable/overwritable objects inside nominally secure roots from the perspective of a chosen token:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Esegui come Administrator per una visibilità più ampia; imposta `-ProcessId` su un processo low-priv per rispecchiare l'accesso di quel token.
- Filtra manualmente per escludere sottodirectory note come non consentite prima di usare i candidati con `RAiLaunchAdminProcess`.

## Correlati

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Riferimenti
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
