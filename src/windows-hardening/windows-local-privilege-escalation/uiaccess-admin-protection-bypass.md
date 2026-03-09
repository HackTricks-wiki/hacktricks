# Bypass di Admin Protection tramite UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Panoramica
- Windows AppInfo espone `RAiLaunchAdminProcess` per avviare processi UIAccess (destinati all'accessibilità). UIAccess bypassa la maggior parte del filtraggio dei messaggi di User Interface Privilege Isolation (UIPI) in modo che il software per l'accessibilità possa controllare UI con IL più alto.
- Abilitare UIAccess direttamente richiede `NtSetInformationToken(TokenUIAccess)` con **SeTcbPrivilege**, quindi i chiamanti a basso privilegio si affidano al servizio. Il servizio esegue tre controlli sul binario di destinazione prima di impostare UIAccess:
  - Il manifest incorporato contiene `uiAccess="true"`.
  - Firmato da un qualsiasi certificato attendibile dal Local Machine root store (nessun requisito EKU/Microsoft).
  - Posizionato in un percorso riservato agli amministratori sul disco di sistema (es., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, escludendo specifici sottopercorsi scrivibili).
- `RAiLaunchAdminProcess` non mostra alcun prompt di consenso per i lanci UIAccess (altrimenti gli strumenti di accessibilità non potrebbero interagire con il prompt).

## Token shaping and integrity levels
- Se i controlli hanno successo, AppInfo **copia il token del chiamante**, abilita UIAccess e aumenta l'Integrity Level (IL):
  - Limited admin user (l'utente è in Administrators ma in esecuzione filtrata) ➜ **High IL**.
  - Non-admin user ➜ IL aumentato di **+16 livelli** fino a un limite **High** (il System IL non viene mai assegnato).
  - Se il token del chiamante ha già UIAccess, l'IL resta invariato.
  - Trucco “Ratchet”: un processo UIAccess può disabilitare UIAccess su se stesso, rilanciarsi tramite `RAiLaunchAdminProcess` e ottenere un ulteriore incremento di +16 IL. Medium➜High richiede 255 rilanci (rumoroso, ma funziona).

## Perché UIAccess abilita un bypass di Admin Protection
- UIAccess permette a un processo con IL inferiore di inviare messaggi di finestra a finestre con IL superiore (bypassando i filtri UIPI). A **pari IL**, le primitive UI classiche come `SetWindowsHookEx` **consentono l'injection di codice/caricamento di DLL** in qualsiasi processo che possieda una finestra (incluse le **message-only windows** usate da COM).
- Admin Protection avvia il processo UIAccess con l’identità dell'**utente limitato** ma a **High IL**, silenziosamente. Una volta che codice arbitrario viene eseguito all'interno di quel processo UIAccess a High IL, l'attaccante può iniettare in altri processi High IL sul desktop (anche appartenenti ad altri utenti), rompendo la separazione prevista.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Su Windows 10 1803+ l'API è stata spostata in Win32k (`NtUserGetWindowProcessHandle`) e può aprire un handle di processo usando un `DesiredAccess` fornito dal chiamante. Il percorso kernel usa `ObOpenObjectByPointer(..., KernelMode, ...)`, che bypassa i normali controlli di accesso in user-mode.
- Condizioni pratiche: la finestra target deve trovarsi sulla stessa desktop e i controlli UIPI devono passare. Storicamente, un chiamante con UIAccess poteva bypassare un fallimento UIPI e ottenere comunque un handle in kernel-mode (fixato come CVE-2023-41772).
- Impatto: un handle di finestra diventa una **capability** per ottenere un handle di processo potente (comunemente `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) che il chiamante normalmente non poteva aprire. Questo abilita accesso cross-sandbox e può compromettere i confini Protected Process / PPL se il target espone qualsiasi finestra (incluse le message-only windows).
- Flusso di abuso pratico: enumerare o localizzare HWND (es., `EnumWindows`/`FindWindowEx`), risolvere il PID proprietario (`GetWindowThreadProcessId`), chiamare `GetProcessHandleFromHwnd`, quindi usare l'handle restituito per primitive di lettura/scrittura memoria o code-hijack.
- Comportamento post-fix: UIAccess non concede più aperture in kernel-mode su fallimento UIPI e i diritti di accesso ammessi sono limitati all'insieme legacy degli hook; Windows 11 24H2 aggiunge controlli di process-protection e percorsi più sicuri attivati da feature flags. Disabilitare UIPI a livello di sistema (`EnforceUIPI=0`) indebolisce queste protezioni.

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo risolve il percorso fornito tramite `GetFinalPathNameByHandle` e poi applica **controlli stringa allow/deny** contro radici/esclusioni hardcoded. Diverse classi di bypass derivano da quella validazione semplicistica:
- **Directory named streams**: directory escluse ma scrivibili (es., `C:\Windows\tracing`) possono essere bypassate con uno named stream sulla directory stessa, es. `C:\Windows\tracing:file.exe`. I controlli stringa vedono `C:\Windows\` e non rilevano il sottopercorso escluso.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` **non richiede un'estensione `.exe`**. Sovrascrivere qualsiasi file scrivibile sotto una root consentita con un payload eseguibile funziona, oppure copiare un EXE firmato con `uiAccess="true"` in qualsiasi sottodirectory scrivibile (es., residui di update come `Tasks_Migrated` quando presenti) gli permette di superare il controllo del percorso sicuro.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: i non-admin potevano installare pacchetti MSIX firmati che finivano in `WindowsApps`, che non era escluso. Impacchettare un binario UIAccess dentro l'MSIX e poi lanciarlo tramite `RAiLaunchAdminProcess` portava a un processo UIAccess **High IL senza prompt**. Microsoft ha mitigato escludendo questo percorso; la capability MSIX che restringe `uiAccess` richiede comunque installazione da admin.

## Attack workflow (High IL without a prompt)
1. Ottenere/creare un **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Posizionarlo dove l'allowlist di AppInfo lo accetta (o abusare di un edge case di validazione del percorso/di un artefatto scrivibile come sopra).
3. Chiamare `RAiLaunchAdminProcess` per avviarlo **silenziosamente** con UIAccess + IL elevato.
4. Da quel foothold High-IL, prendere di mira un altro processo High-IL sul desktop usando **window hooks/DLL injection** o altre primitive same-IL per compromettere completamente il contesto admin.

## Enumerating candidate writable paths
Esegui l'helper PowerShell per scoprire oggetti scrivibili/sovrascrivibili all'interno di radici nominalmente sicure dal punto di vista di un token scelto:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Esegui come amministratore per una visibilità più ampia; imposta `-ProcessId` su un processo a basso privilegio per rispecchiare gli accessi di quel token.
- Filtra manualmente per escludere le sottodirectory note come non consentite prima di usare i candidati con `RAiLaunchAdminProcess`.

## Riferimenti
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
