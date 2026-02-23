# Bypass della Admin Protection tramite UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Panoramica
- Windows AppInfo espone `RAiLaunchAdminProcess` per avviare processi UIAccess (destinati all'accessibilità). UIAccess bypassa gran parte del filtro User Interface Privilege Isolation (UIPI) sui messaggi in modo che il software di accessibilità possa controllare l'interfaccia di processi con IL superiore.
- Abilitare UIAccess direttamente richiede `NtSetInformationToken(TokenUIAccess)` con **SeTcbPrivilege**, quindi chiamanti con pochi privilegi si affidano al servizio. Il servizio esegue tre controlli sul binario di destinazione prima di impostare UIAccess:
  - Il manifest incorporato contiene `uiAccess="true"`.
  - Firmato da un qualsiasi certificato attendibile nello store Local Machine root (nessun requisito EKU/Microsoft).
  - Collocato in un percorso accessibile solo dagli amministratori sul drive di sistema (es., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, escludendo specifici sottopercorsi scrivibili).
- `RAiLaunchAdminProcess` non mostra prompt di consenso per i lanci UIAccess (altrimenti gli strumenti di accessibilità non potrebbero interagire con il prompt).

## Modellazione del token e livelli di integrità
- Se i controlli riescono, AppInfo **copia il token del chiamante**, abilita UIAccess e aumenta il Integrity Level (IL):
  - Limited admin user (l'utente è nel gruppo Administrators ma eseguito con token filtrato) ➜ **High IL**.
  - Non-admin user ➜ IL aumentato di **+16 livelli** fino a un tetto **High** (System IL non viene mai assegnato).
- Se il token del chiamante ha già UIAccess, l'IL rimane invariato.
- Trucco “ratchet”: un processo UIAccess può disabilitare UIAccess su se stesso, rilanciarsi tramite `RAiLaunchAdminProcess` e ottenere un altro incremento di +16 IL. Medium➜High richiede 255 rilanci (rumoroso, ma funziona).

## Perché UIAccess permette di eludere Admin Protection
- UIAccess consente a un processo con IL inferiore di inviare messaggi di finestra a finestre con IL superiore (bypassando i filtri UIPI). A parità di IL, primitive UI classiche come `SetWindowsHookEx` **permettono l'iniezione di codice/caricamento DLL** in qualsiasi processo che possieda una finestra (incluse le **message-only windows** usate da COM).
- Admin Protection lancia il processo UIAccess sotto l'**identità dell'utente limitato** ma a **High IL**, silenziosamente. Una volta che codice arbitrario gira dentro quel processo UIAccess a High IL, l'attaccante può iniettare in altri processi a High IL sul desktop (anche appartenenti a utenti diversi), rompendo la separazione prevista.

## Debolezze nella validazione delle directory sicure (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo risolve il percorso fornito tramite `GetFinalPathNameByHandle` e poi applica controlli di stringa allow/deny contro root/esclusioni hardcoded. Diversi bypass derivano da questa validazione semplicistica:
- **Directory named streams**: directory escluse e scrivibili (es., `C:\Windows\tracing`) possono essere aggirate con uno stream nominato sulla directory stessa, es. `C:\Windows\tracing:file.exe`. I controlli di stringa vedono `C:\Windows\` e non rilevano il sottopercorso escluso.
- **File/directory scrivibile dentro una root consentita**: `CreateProcessAsUser` non richiede l'estensione `.exe`. Sovrascrivere qualsiasi file scrivibile sotto una root consentita con un payload eseguibile funziona, oppure copiare un EXE firmato con `uiAccess="true"` in una qualsiasi sottodirectory scrivibile (es., residui di update come `Tasks_Migrated` quando presenti) gli fa superare il controllo di percorso sicuro.
- **MSIX in `C:\Program Files\WindowsApps` (fixed)**: i non-admin potevano installare pacchetti MSIX firmati che finivano in `WindowsApps`, che non era escluso. Impacchettare un binario UIAccess dentro l'MSIX e poi lanciarlo tramite `RAiLaunchAdminProcess` permetteva di ottenere un processo UIAccess a High IL senza prompt. Microsoft ha mitigato escludendo questo percorso; la capability MSIX limitata a `uiAccess` richiede già l'installazione da admin.

## Flusso d'attacco (High IL senza prompt)
1. Ottenere/creare un binario UIAccess **firmato** (manifest `uiAccess="true"`).
2. Posizionarlo dove la allowlist di AppInfo lo accetta (o sfruttare una edge case di validazione del percorso/artifatto scrivibile come sopra).
3. Chiamare `RAiLaunchAdminProcess` per avviarlo **silenziosamente** con UIAccess + IL elevato.
4. Da quel foothold a High IL, prendere di mira un altro processo a High IL sul desktop usando **window hooks/DLL injection** o altre primitive a stesso IL per compromettere completamente il contesto admin.

## Enumerazione dei percorsi scrivibili candidati
Eseguire l'helper PowerShell per scoprire oggetti scrivibili/sovrascrivibili all'interno di root nominalmente sicure dalla prospettiva di un token scelto:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Esegui Run as Administrator per maggiore visibilità; imposta `-ProcessId` su un processo low-priv per rispecchiare l'accesso di quel token.
- Filtra manualmente per escludere sottodirectory note non consentite prima di utilizzare i candidati con `RAiLaunchAdminProcess`.

## References
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
