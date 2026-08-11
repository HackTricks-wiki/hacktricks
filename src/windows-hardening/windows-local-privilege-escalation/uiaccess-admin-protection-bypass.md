# Bypass della protezione amministratore tramite UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Panoramica
- Windows AppInfo espone il percorso interno `RAiLaunchAdminProcess` utilizzato per avviare le applicazioni UIAccess destinate all'accessibilità. UIAccess consente interazioni selezionate oltre i confini di User Interface Privilege Isolation (UIPI); non costituisce un bypass generale di ogni confine di sicurezza dei processi.<sup>[[1]](#references)[[3]](#references)</sup>
- L'abilitazione diretta di UIAccess richiede `NtSetInformationToken(TokenUIAccess)` con **SeTcbPrivilege**, quindi i chiamanti con privilegi ridotti dipendono dal servizio. Il servizio esegue tre controlli sul binario di destinazione prima di impostare UIAccess:
- Il manifest incorporato contiene `uiAccess="true"`.
- È firmato da un certificato considerato attendibile da qualsiasi autorità nel Local Machine root store (senza requisiti EKU/Microsoft).
- Si trova in un percorso accessibile esclusivamente agli amministratori sull'unità di sistema (ad esempio `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), escludendo specifici sottopercorsi scrivibili.
- `RAiLaunchAdminProcess` non mostra alcun prompt di consenso per gli avvii UIAccess (altrimenti gli strumenti di accessibilità non potrebbero interagire con il prompt).<sup>[[1]](#references)</sup>

## Manipolazione dei token e livelli di integrità
- Se i controlli hanno esito positivo, AppInfo **copia il token del chiamante**, abilita UIAccess e aumenta il livello di integrità (IL):
- Utente amministratore limitato (l'utente appartiene al gruppo Administrators ma è in esecuzione con token filtrato) ➜ **High IL**.
- Utente non amministratore ➜ IL aumentato di **+16 livelli**, fino al limite **High** (System IL non viene mai assegnato).
- Se il token del chiamante dispone già di UIAccess, l'IL non viene modificato.
- Tecnica del “ratchet”: un processo UIAccess può disabilitare UIAccess su se stesso, rieseguire l'avvio tramite `RAiLaunchAdminProcess` e ottenere un ulteriore incremento di +16 IL. Il passaggio da Medium a High richiede 255 riesecuzioni (rumoroso, ma funziona).<sup>[[1]](#references)</sup>

## Perché UIAccess consente di eludere la protezione amministratore
- UIAccess consente a un processo con IL inferiore di inviare messaggi alle finestre con IL superiore (bypassando i filtri UIPI). Con **lo stesso IL**, le primitive UI classiche come `SetWindowsHookEx` **consentono l'iniezione di codice/il caricamento di DLL** in qualsiasi processo che possieda una finestra (incluse le **message-only windows** utilizzate da COM).
- Admin Protection avvia il processo UIAccess con l'identità dell'**utente limitato**, ma con **High IL**, senza mostrare prompt. Una volta eseguito codice arbitrario all'interno di quel processo UIAccess con High IL, l'attaccante può effettuare injection in altri processi con High IL sul desktop (anche appartenenti ad altri utenti), compromettendo la separazione prevista.<sup>[[1]](#references)</sup>

## Primitiva dell'handle da HWND a processo (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- In Windows 10 1803 e versioni successive, l'API è stata spostata in Win32k (`NtUserGetWindowProcessHandle`) e può aprire un handle di processo utilizzando un `DesiredAccess` fornito dal chiamante. Il percorso del kernel usa `ObOpenObjectByPointer(..., KernelMode, ...)`, bypassando i normali controlli di accesso in user mode.<sup>[[2]](#references)</sup>
- Prerequisiti pratici: la finestra di destinazione deve trovarsi sullo stesso desktop e i controlli UIPI devono avere esito positivo. Storicamente, un chiamante con UIAccess poteva bypassare l'errore UIPI e ottenere comunque un handle in kernel mode (corretto con CVE-2023-41772).
- Impatto storico: un handle di finestra diventava una **capability** per ottenere accessi al processo come `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE` o `PROCESS_VM_OPERATION`, che il chiamante normalmente non avrebbe potuto ottenere. Prima delle correzioni documentate, ciò poteva attraversare i confini di sandbox e protected process quando una destinazione esponeva una finestra, inclusa una message-only window.<sup>[[2]](#references)</sup>
- Flusso di abuso pratico: enumerare o individuare gli HWND (ad esempio `EnumWindows`/`FindWindowEx`), risolvere il PID proprietario (`GetWindowThreadProcessId`), chiamare `GetProcessHandleFromHwnd`, quindi utilizzare l'handle restituito per primitive di lettura/scrittura della memoria o di code hijacking.
- Comportamento dopo la correzione: UIAccess non concede più aperture in kernel mode quando il controllo UIPI fallisce e i diritti di accesso consentiti sono limitati al legacy hook set; Windows 11 24H2 aggiunge controlli di protezione dei processi e percorsi più sicuri controllati da feature flag. La disabilitazione globale di UIPI (`EnforceUIPI=0`) indebolisce queste protezioni.<sup>[[2]](#references)</sup>

## Debolezze nella convalida delle directory sicure (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo risolve il percorso fornito tramite `GetFinalPathNameByHandle` e poi applica **controlli basati su stringhe** rispetto a root/esclusioni hardcoded. Diverse classi di bypass derivano da questa convalida semplicistica:
- **Named stream delle directory**: le directory scrivibili escluse (ad esempio `C:\Windows\tracing`) possono essere bypassate utilizzando uno stream denominato sulla directory stessa, ad esempio `C:\Windows\tracing:file.exe`. I controlli sulle stringhe rilevano `C:\Windows\` e non individuano il sottopercorso escluso.
- **File/directory scrivibile all'interno di una root consentita**: `CreateProcessAsUser` **non richiede l'estensione `.exe`**. Sovrascrivere qualsiasi file scrivibile sotto una root consentita con un payload eseguibile funziona; in alternativa, copiare un EXE firmato con `uiAccess="true"` in qualsiasi sottodirectory scrivibile (ad esempio residui di aggiornamenti come `Tasks_Migrated`, quando presenti) consente di superare il controllo del percorso sicuro.
- **MSIX in `C:\Program Files\WindowsApps` (corretto)**: gli utenti non amministratori potevano installare pacchetti MSIX firmati che finivano in `WindowsApps`, percorso che non era escluso. Inserire un binario UIAccess nel pacchetto MSIX e avviarlo tramite `RAiLaunchAdminProcess` produceva un **processo UIAccess con High IL avviato senza prompt**. Microsoft ha mitigato il problema escludendo questo percorso; la capability MSIX limitata `uiAccess` richiede già un'installazione eseguita da un amministratore.<sup>[[1]](#references)</sup>

## Flusso dell'attacco (High IL senza prompt)
1. Ottenere/creare un **binario UIAccess firmato** (manifest `uiAccess="true"`). Per una valutazione realistica, eseguire i test utilizzando materiale di trust e percorsi esplicitamente autorizzati per il laboratorio; non aggiungere il certificato dell'attaccante al Local Machine root store di una macchina di produzione.
2. Posizionarlo dove la allowlist di AppInfo lo accetta (oppure abusare di un edge case nella validazione del percorso o di un artefatto scrivibile come descritto sopra).
3. Chiamare `RAiLaunchAdminProcess` per avviarlo **silenziosamente** con UIAccess + IL elevato.
4. Dal foothold con High IL, prendere di mira un altro processo con High IL sul desktop utilizzando **window hooks/DLL injection** o altre primitive con lo stesso IL, per compromettere completamente il contesto amministrativo.<sup>[[1]](#references)</sup>

## Enumerazione dei percorsi scrivibili candidati
Eseguire l'helper PowerShell per individuare oggetti scrivibili/sovrascrivibili all'interno di root nominalmente sicure dal punto di vista del token scelto:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Esegui come Amministratore per una visibilità più ampia; imposta `-ProcessId` su un processo con privilegi ridotti per replicare l'accesso di quel token.
- Filtra manualmente per escludere le sottodirectory note come non consentite prima di utilizzare i candidati con `RAiLaunchAdminProcess`.

## Correlati

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## References

- [1] [Bypassare la protezione dell'amministratore abusando di UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [Approfondimento su GetProcessHandleFromHwnd (GPHFH)](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [3] [Microsoft Learn — Applicazioni UIAccess](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works#uiaccess-applications)
{{#include ../../banners/hacktricks-training.md}}
