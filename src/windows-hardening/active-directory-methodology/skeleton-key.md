# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Attacco Skeleton Key

L'**attacco Skeleton Key** è una tecnica sofisticata che consente agli attaccanti di **bypassare l'autenticazione di Active Directory** **iniettando una password master** nel controller di dominio. Questo consente all'attaccante di **autenticarsi come qualsiasi utente** senza la loro password, **concedendo loro accesso illimitato** al dominio.

Può essere eseguito utilizzando [Mimikatz](https://github.com/gentilkiwi/mimikatz). Per portare a termine questo attacco, **i diritti di Domain Admin sono un prerequisito**, e l'attaccante deve mirare a ciascun controller di dominio per garantire una violazione completa. Tuttavia, l'effetto dell'attacco è temporaneo, poiché **riavviare il controller di dominio eradicata il malware**, rendendo necessaria una reimplementazione per un accesso sostenuto.

**Eseguire l'attacco** richiede un singolo comando: `misc::skeleton`.

## Mitigazioni

Le strategie di mitigazione contro tali attacchi includono il monitoraggio di specifici ID evento che indicano l'installazione di servizi o l'uso di privilegi sensibili. In particolare, cercare l'ID Evento di Sistema 7045 o l'ID Evento di Sicurezza 4673 può rivelare attività sospette. Inoltre, eseguire `lsass.exe` come processo protetto può ostacolare significativamente gli sforzi degli attaccanti, poiché questo richiede loro di impiegare un driver in modalità kernel, aumentando la complessità dell'attacco.

Ecco i comandi PowerShell per migliorare le misure di sicurezza:

- Per rilevare l'installazione di servizi sospetti, utilizzare: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- In particolare, per rilevare il driver di Mimikatz, può essere utilizzato il seguente comando: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Per rafforzare `lsass.exe`, è consigliato abilitarlo come processo protetto: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

La verifica dopo un riavvio del sistema è cruciale per garantire che le misure protettive siano state applicate con successo. Questo è realizzabile tramite: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## Riferimenti

- [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

{{#include ../../banners/hacktricks-training.md}}
