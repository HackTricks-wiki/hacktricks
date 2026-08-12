# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper può impacchettare un eseguibile o uno script come file Windows Installer (`.msi`). Scarica e avvia l'edizione gratuita, quindi seleziona l'eseguibile da impacchettare.<sup>[[3]](#references)</sup> Per eseguire una sequenza di comandi, seleziona un file `.bat` come input invece di impacchettare `cmd.exe`.<sup>[[1]](#references)</sup>

![Selezione dell'eseguibile di origine o dello script batch in MSI Wrapper](<../../images/image (417).png>)

Configura attentamente il contesto di esecuzione e le altre proprietà dell'installer:

![Configurazione dell'ID dell'applicazione e del contesto di sicurezza in MSI Wrapper](<../../images/image (312).png>)

![Configurazione delle proprietà dell'installer in MSI Wrapper](<../../images/image (346).png>)

![Revisione delle impostazioni di build di MSI Wrapper](<../../images/image (1072).png>)

Questi valori possono essere modificati quando si impacchetta un binario personalizzato.

Prosegui nelle pagine rimanenti della procedura guidata e seleziona **Build** per generare l'installer.<sup>[[1]](#references)</sup>

> [!WARNING]
> La creazione di un MSI non garantisce di per sé privilegi elevati. L'eventuale elevazione dell'installazione dipende dai criteri di Windows Installer, dal contesto del pacchetto e dall'autorizzazione dell'utente. Microsoft avverte che abilitare `AlwaysInstallElevated` sia per l'utente sia per il computer consente agli utenti non amministratori di installare pacchetti con privilegi di sistema.<sup>[[2]](#references)</sup>

## References

- [1] [Documentazione di MSI Wrapper - Primi passi](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Installazione di un pacchetto con privilegi elevati per un utente non amministratore](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Download](https://www.exemsi.com/download/)
{{#include ../../banners/hacktricks-training.md}}
