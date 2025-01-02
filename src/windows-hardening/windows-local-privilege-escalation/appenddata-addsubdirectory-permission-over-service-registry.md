{{#include ../../banners/hacktricks-training.md}}

**Il post originale è** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Riepilogo

Due chiavi di registro sono state trovate scrivibili dall'utente attuale:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

È stato suggerito di controllare i permessi del servizio **RpcEptMapper** utilizzando la **GUI di regedit**, specificamente la scheda **Permessi Efficaci** nella finestra **Impostazioni di Sicurezza Avanzate**. Questo approccio consente di valutare i permessi concessi a specifici utenti o gruppi senza la necessità di esaminare ogni voce di controllo accessi (ACE) singolarmente.

Uno screenshot mostrava i permessi assegnati a un utente a basso privilegio, tra cui il permesso **Crea Sottocchiave** era notevole. Questo permesso, noto anche come **AppendData/AddSubdirectory**, corrisponde ai risultati dello script.

È stata notata l'impossibilità di modificare direttamente alcuni valori, ma la capacità di creare nuove sottocchiavi. Un esempio evidenziato è stato un tentativo di alterare il valore **ImagePath**, che ha portato a un messaggio di accesso negato.

Nonostante queste limitazioni, è stata identificata una potenzialità di escalation dei privilegi attraverso la possibilità di sfruttare la sottocchiave **Performance** all'interno della struttura di registro del servizio **RpcEptMapper**, una sottocchiave non presente per impostazione predefinita. Questo potrebbe consentire la registrazione di DLL e il monitoraggio delle prestazioni.

È stata consultata la documentazione sulla sottocchiave **Performance** e il suo utilizzo per il monitoraggio delle prestazioni, portando allo sviluppo di una DLL di prova di concetto. Questa DLL, che dimostra l'implementazione delle funzioni **OpenPerfData**, **CollectPerfData** e **ClosePerfData**, è stata testata tramite **rundll32**, confermando il suo successo operativo.

L'obiettivo era costringere il **servizio RPC Endpoint Mapper** a caricare la DLL di Performance creata. Le osservazioni hanno rivelato che l'esecuzione di query di classi WMI relative ai Dati di Performance tramite PowerShell ha portato alla creazione di un file di log, consentendo l'esecuzione di codice arbitrario nel contesto di **LOCAL SYSTEM**, concedendo così privilegi elevati.

Sono state sottolineate la persistenza e le potenziali implicazioni di questa vulnerabilità, evidenziando la sua rilevanza per le strategie di post-sfruttamento, movimento laterale e evasione dei sistemi antivirus/EDR.

Sebbene la vulnerabilità sia stata inizialmente divulgata involontariamente attraverso lo script, è stato enfatizzato che il suo sfruttamento è limitato a versioni obsolete di Windows (ad es., **Windows 7 / Server 2008 R2**) e richiede accesso locale.

{{#include ../../banners/hacktricks-training.md}}
