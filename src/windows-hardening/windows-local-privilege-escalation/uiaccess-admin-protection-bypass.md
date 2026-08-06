# Bypass della protezione Administrator tramite UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Panoramica
- Windows AppInfo espone `RAiLaunchAdminProcess` per generare processi UIAccess (destinati all'accessibilità). UIAccess bypassa la maggior parte del filtraggio dei messaggi User Interface Privilege Isolation (UIPI), consentendo ai software di accessibilità di controllare interfacce con IL superiore.
- L'abilitazione diretta di UIAccess richiede `NtSetInformationToken(TokenUIAccess)` con **SeTcbPrivilege**, quindi i chiamanti con privilegi bassi si affidano al servizio. Il servizio esegue tre controlli sul binario di destinazione prima di impostare UIAccess:
- Il manifest incorporato contiene `uiAccess="true"`.
- È firmato da un certificato considerato attendibile dal root store Local Machine (senza requisiti EKU/Microsoft).
- Si trova in un percorso riservato agli amministratori sull'unità di sistema (ad esempio `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), escluse specifiche sottocartelle scrivibili.
- `RAiLaunchAdminProcess` non mostra alcun prompt di consenso per gli avvii UIAccess (altrimenti gli strumenti di accessibilità non potrebbero controllare il prompt).<sup>[[1]](#references)</sup>

## Modellazione dei token e livelli di integrità
- Se i controlli hanno esito positivo, AppInfo **copia il token del chiamante**, abilita UIAccess e aumenta il livello di integrità (IL):
- Utente amministratore limitato (l'utente appartiene ad Administrators ma opera con un token filtrato) ➜ **High IL**.
- Utente non amministratore ➜ IL aumentato di **+16 livelli**, fino a un limite **High** (System IL non viene mai assegnato).
- Se il token del chiamante dispone già di UIAccess, l'IL rimane invariato.
- Tecnica del “ratchet”: un processo UIAccess può disabilitare UIAccess su se stesso, riavviarsi tramite `RAiLaunchAdminProcess` e ottenere un ulteriore incremento IL di +16. Il passaggio da Medium a High richiede 255 riavvii (rumoroso, ma funziona).<sup>[[1]](#references)</sup>

## Perché UIAccess consente di eludere la protezione Administrator
- UIAccess consente a un processo con IL inferiore di inviare messaggi alle finestre con IL superiore (bypassando i filtri UIPI). Con **lo stesso IL**, le primitive UI classiche come `SetWindowsHookEx` **consentono l'iniezione di codice/il caricamento di DLL** in qualsiasi processo proprietario di una finestra (incluse le **message-only windows** utilizzate da COM).
- Admin Protection avvia il processo UIAccess con l'identità dell'utente limitato, ma con **High IL**, senza mostrare prompt. Una volta eseguito codice arbitrario all'interno di quel processo UIAccess con High IL, l'attaccante può effettuare injection in altri processi con High IL sul desktop (anche se appartenenti a utenti diversi), violando la separazione prevista.<sup>[[1]](#references)</sup>

## Primitiva per ottenere un handle dal HWND (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Su Windows 10 1803+ l'API è stata spostata in Win32k (`NtUserGetWindowProcessHandle`) e può aprire un handle di processo utilizzando un `DesiredAccess` fornito dal chiamante. Il percorso del kernel usa `ObOpenObjectByPointer(..., KernelMode, ...)`, bypassando i normali controlli di accesso user-mode.<sup>[[2]](#references)</sup>
- Prerequisiti pratici: la finestra di destinazione deve trovarsi sullo stesso desktop e i controlli UIPI devono avere esito positivo. Storicamente, un chiamante con UIAccess poteva bypassare il fallimento UIPI e ottenere comunque un handle in kernel-mode (corretto con CVE-2023-41772).
- Impatto: un handle di finestra diventa una **capability** per ottenere un potente handle di processo (comunemente `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) che il chiamante normalmente non potrebbe aprire. Questo abilita l'accesso cross-sandbox e può violare i confini Protected Process / PPL se la destinazione espone una finestra qualsiasi (incluse le message-only windows).
- Flusso di abuso pratico: enumerare o individuare gli HWND (ad esempio `EnumWindows`/`FindWindowEx`), risolvere il PID proprietario (`GetWindowThreadProcessId`), chiamare `GetProcessHandleFromHwnd`, quindi utilizzare l'handle restituito per primitive di lettura/scrittura della memoria o di dirottamento dell'esecuzione del codice.
- Comportamento dopo la correzione: UIAccess non concede più aperture in kernel-mode in caso di fallimento UIPI e i diritti di accesso consentiti sono limitati al set di hook legacy; Windows 11 24H2 aggiunge controlli sulla protezione dei processi e percorsi più sicuri controllati da feature flag. La disabilitazione globale di UIPI (`EnforceUIPI=0`) indebolisce queste protezioni.<sup>[[2]](#references)</sup>

## Debolezze nella validazione delle directory sicure (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo risolve il percorso fornito tramite `GetFinalPathNameByHandle` e applica quindi **controlli di stringhe allow/deny** rispetto a root/esclusioni hardcoded. Diverse classi di bypass derivano da questa validazione semplicistica:
- **Named stream delle directory**: le directory scrivibili escluse (ad esempio `C:\Windows\tracing`) possono essere bypassate tramite uno named stream sulla directory stessa, ad esempio `C:\Windows\tracing:file.exe`. I controlli sulle stringhe rilevano `C:\Windows\` e non individuano la sottocartella esclusa.
- **File/directory scrivibile all'interno di una root consentita**: `CreateProcessAsUser` **non richiede l'estensione `.exe`**. Sovrascrivere un file scrivibile qualsiasi all'interno di una root consentita con un payload eseguibile funziona; in alternativa, copiare un EXE firmato con `uiAccess="true"` in una sottodirectory scrivibile qualsiasi (ad esempio residui di aggiornamenti come `Tasks_Migrated`, quando presenti) gli consente di superare il controllo del percorso sicuro.
- **MSIX in `C:\Program Files\WindowsApps` (corretto)**: gli utenti non amministratori potevano installare pacchetti MSIX firmati che finivano in `WindowsApps`, un percorso che non era escluso. Inserire un binario UIAccess nel pacchetto MSIX e avviarlo tramite `RAiLaunchAdminProcess` produceva un **processo UIAccess con High IL, avviato senza prompt**. Microsoft ha mitigato il problema escludendo questo percorso; la capability MSIX limitata `uiAccess` richiede già un'installazione da parte di un amministratore.<sup>[[1]](#references)</sup>

## Workflow di attacco (High IL senza prompt)
1. Ottenere/creare un **binario UIAccess firmato** (manifest `uiAccess="true"`).
2. Collocarlo in un percorso accettato dall'allowlist di AppInfo (oppure abusare di un edge case nella validazione del percorso o di un artefatto scrivibile come descritto sopra).
3. Chiamare `RAiLaunchAdminProcess` per avviarlo **silenziosamente** con UIAccess + IL elevato.
4. Da questo foothold con High IL, attaccare un altro processo con High IL sul desktop utilizzando **window hook/DLL injection** o altre primitive con lo stesso IL, compromettendo completamente il contesto dell'amministratore.<sup>[[1]](#references)</sup>

## Enumerazione dei percorsi scrivibili candidati
Eseguire l'helper PowerShell per individuare oggetti scrivibili/sovrascrivibili all'interno di root nominalmente sicure dal punto di vista del token scelto:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Esegui come Administrator per una visibilità più ampia; imposta `-ProcessId` su un processo con privilegi ridotti per rispecchiare l’accesso di quel token.
- Filtra manualmente per escludere le sottodirectory note come non consentite prima di utilizzare i candidati con `RAiLaunchAdminProcess`.

## Correlato

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Riferimenti

- [1] [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
