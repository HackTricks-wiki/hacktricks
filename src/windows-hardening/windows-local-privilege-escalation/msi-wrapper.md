# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper può impacchettare un executable o uno script come file Windows Installer (`.msi`). Scarica e avvia la free edition, quindi seleziona l'executable da impacchettare. Per eseguire una sequenza di comandi, seleziona un file `.bat` come input invece di impacchettare `cmd.exe`.<sup>[[1]](#references)</sup>

![Selezione dell'executable sorgente o dello script batch in MSI Wrapper](<../../images/image (417).png>)

Configura con attenzione il contesto di esecuzione e le altre proprietà dell'installer:

![Configurazione dell'application ID e del contesto di sicurezza in MSI Wrapper](<../../images/image (312).png>)

![Configurazione delle proprietà dell'installer in MSI Wrapper](<../../images/image (346).png>)

![Revisione delle impostazioni di build di MSI Wrapper](<../../images/image (1072).png>)

Questi valori possono essere modificati durante l'impacchettamento di un binary personalizzato.

Prosegui nelle pagine rimanenti del wizard e seleziona **Build** per generare l'installer.<sup>[[1]](#references)</sup>

> [!WARNING]
> La creazione di un MSI non concede di per sé privilegi elevati. L'elevazione durante l'installazione dipende dai criteri di Windows Installer, dal contesto del package e dall'autorizzazione dell'utente. Microsoft avverte che l'abilitazione di `AlwaysInstallElevated` sia per l'utente sia per il computer consente ai non amministratori di installare package con privilegi di sistema.<sup>[[2]](#references)</sup>

## References

- [1] [Documentazione di MSI Wrapper - Introduzione](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Installazione di un package con privilegi elevati per un non amministratore](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
{{#include ../../banners/hacktricks-training.md}}
