# Bypass dei controlli di accesso ai file in modalità kernel

{{#include ../../banners/hacktricks-training.md}}

## Pattern di driver vulnerabile

Un driver non preserva il confine di sicurezza del chiamante semplicemente impersonandolo. Le aperture di oggetti in modalità kernel normalmente ignorano i controlli di accesso. `OBJ_KERNEL_HANDLE` rende l'handle risultante accessibile solo dalla modalità kernel. Quando un driver apre o manipola un oggetto per conto della modalità utente, deve usare anche `OBJ_FORCE_ACCESS_CHECK` affinché Object Manager valuti l'accesso richiesto rispetto al token effettivo.<sup>[[3]](#references)[[4]](#references)</sup>

Verifica gli IOCTL che gestiscono file e le callback di creazione per individuare questa sequenza:<sup>[[3]](#references)[[4]](#references)</sup>

1. La modalità utente fornisce un percorso, un handle di origine, l'accesso desiderato o il tipo di operazione.
2. Il driver impersona il chiamante, ma chiama `IoCreateFileEx`, `ZwCreateFile` o una routine simile senza `OBJ_FORCE_ACCESS_CHECK`.
3. Un handle a un file o una directory accessibile solo al kernel viene salvato nello stato associato all'handle.
4. Un'operazione successiva decide se impersonare in base a uno stato influenzabile dall'attaccante, come la maschera di accesso richiesta durante la prima apertura.
5. Il ramo privilegiato esegue una rinomina o un collegamento con una classe di informazioni `BypassAccessCheck`.

Questa è una **primitive file confused-deputy**, non necessariamente una corruzione della memoria. Un'inversione di stato particolarmente pericolosa è «se è stata richiesta la scrittura, impersona; se non è stata richiesta, mantieni i privilegi». In questo design, richiedere deliberatamente solo l'accesso in lettura può sbloccare il percorso più potente.<sup>[[3]](#references)</sup>

## Esempio vSMB: root privilegiata e rinomina privilegiata

`storvsp.sys` implementa Virtual Server Message Block (vSMB). Quando la funzionalità **Virtual Machine Platform** è abilitata, la modalità utente può raggiungere `\Device\STORVSP` tramite `\\.\STORVSP`. Un percorso del filesystem vSMB ha la forma `\\.\STORVSP\VSMB\??\C:\path`. CVE-2025-59517 e CVE-2025-64673 hanno mostrato come due decisioni incoerenti sul controllo degli accessi potessero trasformare questa interfaccia in un'escalation dei privilegi locali.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

La corrispondenza tra funzioni e CVE nel sorgente deriva dal reverse engineering del binario corretto, non dal codice sorgente Microsoft. I ricercatori avvertono che i due identificativi potrebbero corrispondere alle funzioni opposte.<sup>[[3]](#references)</sup>

### 1. Crea una condivisione di sola lettura radicata in una directory protetta

Il percorso di creazione vulnerabile registrava i diritti richiesti in flag persistenti come `HasReadAccess`, `HasWriteAccess` e `HasAppendAccess`. Apriva quindi il percorso sottostante con `OBJ_KERNEL_HANDLE`, ma senza `OBJ_FORCE_ACCESS_CHECK`. Di conseguenza, il tentativo di impersonificazione non faceva sì che l'apertura del file rispettasse le autorizzazioni NTFS del chiamante.<sup>[[3]](#references)[[4]](#references)</sup>

Richiedi solo `FILE_READ_DATA`. In questo modo `HasWriteAccess` resta disattivato, pur ottenendo una condivisione la cui root interna è una directory protetta:<sup>[[3]](#references)</sup>

```c
HANDLE root = CreateFileW(
    L"\\\\.\\STORVSP\\VSMB\\??\\C:\\Windows\\System32\\",
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY,
    NULL
);
```

L'elemento importante non è un handle alla directory System32 in modalità utente. È un handle di dispositivo vSMB associato a uno stato del driver che contiene un handle root del kernel privilegiato.<sup>[[3]](#references)</sup>

### 2. Trasformare la discrepanza di stato nella sostituzione di un file protetto

L'IOCTL `0x240330` accettava un handle di file sorgente, una classe di informazioni e un buffer di informazioni a lunghezza variabile:<sup>[[3]](#references)</sup>

```c
#define IOCTL_VSMB_SET_INFORMATION_FILE_REQUEST 0x240330

typedef struct _VSMB_SET_INFO {
    DWORD Version;
    DWORD Reserved;
    UINT64 SourceHandle;
    DWORD InformationClass;
    DWORD BufferLength;
    BYTE Buffer[1];
} VSMB_SET_INFO;
```

Il handler vulnerabile accettava `FileRenameInformation`, `FileLinkInformation` e `FileRenameInformationEx`. Per un normale percorso di rename, separava il percorso della directory padre dal componente finale, quindi apriva la directory padre relativamente all'handle root memorizzato. Anche questa apertura usava `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE` senza `OBJ_FORCE_ACCESS_CHECK`. Un `RootDirectory` non zero fornito dall'attaccante nella struttura di rename veniva rifiutato, quindi il driver forniva il proprio handle di directory privilegiato.<sup>[[3]](#references)</sup>

Il ramo sfruttabile veniva selezionato **non** richiedendo l'accesso in scrittura durante la fase 1:<sup>[[3]](#references)</sup>

- `HasWriteAccess == 1`: impersona il contesto di sicurezza root salvato.
- `HasWriteAccess == 0`: salta l'impersonation e converte `FileRenameInformation` o `FileRenameInformationEx` nella variante `BypassAccessCheck`.

Il handler duplicava l'handle sorgente fornito dall'attaccante in `PsInitialSystemProcess`, lo referenziava come file object, installava l'handle privilegiato della directory di destinazione nella struttura di rename e chiamava `ZwSetInformationFile`. Con `ReplaceIfExists = TRUE`, un file controllato dal chiamante poteva quindi sostituire un file esistente sotto la root protetta.<sup>[[3]](#references)</sup>

Quando esamini un handler simile, traccia **sia la provenienza degli handle sia il contesto di sicurezza** in ogni ramo. La convalida degli input, i controlli di integer overflow, `IO_STOP_ON_SYMLINK` e la restrizione delle classi di informazioni accettate non compensano la combinazione di un handle root privilegiato e un'operazione che bypassa il controllo degli accessi.<sup>[[3]](#references)</sup>

## Da una scrittura protetta all'esecuzione come SYSTEM

Una primitiva di sostituzione di file protetti diventa code execution quando un processo privilegiato carica successivamente il modulo sostituito. Nella chain illustrata, la destinazione era `C:\Windows\System32\wuapi.dll`. L'attivazione della classe COM local-server `{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}` per l'interfaccia `{b4c1d279-966e-44e9-a9c5-ccaf4a77023d}` e la chiamata a `IWaaSRemediation::LaunchDetectionOnly()` inducevano un processo SYSTEM a caricare quella DLL.<sup>[[3]](#references)</sup>

Questa chiamata COM è un **trigger di attivazione**, non un [COM registry hijacking](com-hijacking.md). La primitiva sui file fornisce il modulo inserito e il loader privilegiato fornisce l'esecuzione. Per altre chain di scrittura su file protetti, identifica l'immagine esatta, il percorso DLL, la signature policy, la bitness, le funzioni esportate e un trigger affidabile prima di scegliere un target. Consulta [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) per il workflow generale di analisi del loader.<sup>[[3]](#references)</sup>

### Spostare un token di Session 0 sul desktop interattivo

Un payload caricato da un servizio viene normalmente eseguito in Session 0. Per creare un processo interattivo, può ottenere la sessione attiva della console tramite `WTSGetActiveConsoleSessionId`, abilitare i privilegi richiesti, duplicare il token SYSTEM corrente come token primario e impostare il suo `TokenSessionId` sulla sessione attiva. `CreateProcessAsUserW` usa quindi quel token con `STARTUPINFO.lpDesktop = L"winsta0\\default"`.<sup>[[3]](#references)[[5]](#references)</sup>

```c
DWORD sid = WTSGetActiveConsoleSessionId();
DuplicateTokenEx(currentToken, MAXIMUM_ALLOWED, NULL,
                 SecurityImpersonation, TokenPrimary, &primary);
SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
si.lpDesktop = L"winsta0\\default";
CreateProcessAsUserW(primary, L"C:\\Windows\\System32\\cmd.exe",
                     NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                     NULL, NULL, &si, &pi);
```

`SeTcbPrivilege` è necessario per impostare l'ID di sessione di un token in questo scenario. Anche la window station interattiva e il desktop devono concedere l'accesso al token. Per il flusso più ampio di copia del token, vedere [duplicazione del token dalla Sessione 0](sedebug-+-seimpersonate-copy-token.md).<sup>[[3]](#references)[[5]](#references)</sup>

## Indicazioni per patch e revisione

Gli aggiornamenti Microsoft di dicembre 2025 hanno corretto la catena dimostrata. Il reverse engineering ha rilevato che il percorso di creazione vSMB aggiornato rifiuta le richieste di chiamanti non attendibili che richiedono la root di una share senza `FILE_WRITE_DATA`. Anche alle operazioni pertinenti è stato aggiunto un controllo forzato degli accessi. Ciò blocca l'inversione dello stato prima che un chiamante non privilegiato possa ottenere la root privilegiata.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Per il codice dei driver, applicare queste regole:<sup>[[3]](#references)[[4]](#references)</sup>

- Aggiungere `OBJ_FORCE_ACCESS_CHECK` ogni volta che un oggetto viene aperto per conto di una richiesta in modalità utente. Non considerare `OBJ_KERNEL_HANDLE` un controllo di autorizzazione.<sup>[[4]](#references)</sup>
- Acquisire e convalidare la modalità del richiedente e il contesto effettivo del soggetto. Non consentire ai diritti richiesti di selezionare un ramo di esecuzione più privilegiato.
- Convalidare gli handle utente con il tipo di oggetto, la maschera di accesso e `UserMode` corretti. La duplicazione di un handle nel processo di sistema non convalida l'autorizzazione dell'operazione richiesta.
- Mantenere la risoluzione della destinazione relativa a un handle attendibile, ma assicurarsi che l'handle attendibile sia stato aperto applicando il controllo di accesso del richiedente.
- Evitare le classi `File*BypassAccessCheck` per le operazioni avviate dall'utente. Se il codice interno ne ha effettivamente bisogno, subordinare quel percorso a una decisione di autorizzazione indipendente dai flag di accesso controllati dall'utente.
- Applicare le patch ai sistemi interessati. La superficie vulnerabile è pertinente quando Virtual Machine Platform carica `storvsp.sys`.<sup>[[3]](#references)</sup>

## References

- [1] [Microsoft Security Response Center - CVE-2025-59517](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59517)
- [2] [Microsoft Security Response Center - CVE-2025-64673](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64673)
- [3] [Exodus Intelligence - Da Virtual Share a shell fisica: sfruttare il controllo degli accessi incoerente di Windows per LPE](https://blog.exodusintel.com/2026/07/27/from-virtual-share-to-physical-shell-leveraging-windows-inconsistent-access-control-for-lpe/)
- [4] [Microsoft Learn - Handle di oggetti](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [5] [Microsoft Learn - Funzione CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
{{#include ../../banners/hacktricks-training.md}}
