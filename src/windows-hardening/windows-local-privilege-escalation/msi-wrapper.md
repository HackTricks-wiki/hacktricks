# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper può creare un pacchetto contenente un eseguibile o uno script come file Windows Installer (`.msi`). Scarica e avvia l'edizione gratuita, quindi seleziona l'eseguibile da includere nel pacchetto.<sup>[[3]](#references)</sup> Per eseguire una sequenza di comandi, seleziona un file `.bat` come input invece di includere `cmd.exe` nel pacchetto.<sup>[[1]](#references)</sup>

![Selezione dell'eseguibile o dello script batch di origine in MSI Wrapper](<../../images/image (417).png>)

Configura con attenzione il contesto di esecuzione e le altre proprietà del programma di installazione:

![Configurazione dell'ID dell'applicazione e del contesto di sicurezza in MSI Wrapper](<../../images/image (312).png>)

![Configurazione delle proprietà del programma di installazione in MSI Wrapper](<../../images/image (346).png>)

![Revisione delle impostazioni di compilazione di MSI Wrapper](<../../images/image (1072).png>)

Questi valori possono essere modificati quando si crea un pacchetto con un binario personalizzato.

Prosegui nelle pagine successive della procedura guidata e seleziona **Build** per generare il programma di installazione.<sup>[[1]](#references)</sup>

## Verifica il contesto di esecuzione del comando incluso nel pacchetto

Per un pacchetto di test, includi un file `.bat` che registri il proprio token, invece di presumere che l'impostazione di elevazione dell'MSI si applichi al processo figlio.<sup>[[4]](#references)</sup> Nella procedura guidata, scegli il contesto di sicurezza **System** invece di **User** e seleziona un'installazione per computer con privilegi elevati, se questo è il percorso desiderato.<sup>[[5]](#references)</sup> L'opzione **System** non aggira l'autorizzazione: anche un utente non amministratore ha bisogno di un percorso di installazione con privilegi elevati, come la [configurazione errata delle due policy `AlwaysInstallElevated`](index.html#alwaysinstallelevated) o un flusso di lavoro del programma di installazione con privilegi elevati.<sup>[[2]](#references)</sup> Selezionando invece **User**, il comando incluso nel pacchetto viene eseguito nel contesto dell'utente che avvia l'installazione, cosa che può essere necessaria per accedere a risorse specifiche dell'utente o di rete.<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

Crea l’MSI usando questo file batch come input, quindi eseguilo sull’host di test e verifica l’identità e i privilegi registrati.<sup>[[4]](#references)</sup> MSI Wrapper associa un codice di uscita batch diverso da zero all’errore di installazione 1603, quindi lo zero esplicito evita un falso errore dopo un test riuscito.<sup>[[4]](#references)</sup> Il file di output è un artefatto di test; non dedurre che sia stata eseguita un’operazione come SYSTEM solo perché `msiexec` è terminato con successo o l’installazione è stata silenziosa.<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn` disattiva l'interfaccia di MSI, ma non necessariamente quella dell'eseguibile incluso.<sup>[[6]](#references)[[7]](#references)</sup> Per un installer incluso, imposta i relativi argomenti per l'installazione silenziosa supportati nella procedura guidata; la proprietà dinamica `WRAPPED_ARGUMENTS` di MSI Wrapper è una funzionalità PRO.<sup>[[1]](#references)[[7]](#references)</sup> Consulta [l'approccio con le custom action di WiX](create-msi-with-wix.md) se hai bisogno di controllare direttamente la sequenza e l'impersonificazione delle custom action.

> [!WARNING]
> La creazione di un MSI non concede di per sé privilegi elevati. L'elevazione dell'installazione dipende dai criteri di Windows Installer, dal contesto del pacchetto e dall'autorizzazione dell'utente. Microsoft avverte che abilitare `AlwaysInstallElevated` sia per l'utente sia per il computer consente agli utenti non amministratori di installare pacchetti con privilegi di sistema.<sup>[[2]](#references)</sup>



## References

- [1] [Documentazione di MSI Wrapper - Primi passi](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Installare un pacchetto con privilegi elevati per un utente non amministratore](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Download](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - Creare un MSI da un file batch](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - Pagine della procedura guidata](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - Opzioni della riga di comando](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - Argomenti della riga di comando](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}
