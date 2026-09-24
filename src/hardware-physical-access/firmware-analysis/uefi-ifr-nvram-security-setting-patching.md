# Patch delle impostazioni di sicurezza UEFI IFR e NVRAM

{{#include ../../banners/hacktricks-training.md}}

Una password di setup protegge l'interfaccia utente del firmware, ma non autentica necessariamente i byte di configurazione memorizzati nella SPI flash. Con accesso fisico in scrittura, un assessor può associare un'impostazione UEFI nascosta o bloccata dell'**Human Interface Infrastructure (HII) Internal Forms Representation (IFR)** alla variabile NVRAM di supporto, applicare una patch offline a quel valore e riflasharlo. Su un sistema Dell interessato, questa procedura ha modificato lo stato IOMMU pre-boot, mentre il setup grafico continuava a mostrare la protezione DMA come abilitata.<sup>[[3]](#references)</sup>

> [!CAUTION]
> Le scritture nel firmware possono rendere il target permanentemente inutilizzabile. Operare su un dispositivo di test autorizzato e ripristinabile; conservare l'immagine originale e ottenere almeno tre letture indipendenti i cui hash crittografici coincidano prima di modificare qualsiasi cosa.<sup>[[3]](#references)</sup>

## Acquisire l'immagine del firmware

Leggere solo la regione BIOS quando il flash descriptor Intel consente l'accesso dall'host, oppure utilizzare un programmatore esterno con tensione corretta e un clip in-circuit. Normalmente è necessario un programmatore esterno per ripristinare una macchina che non si avvia più.<sup>[[3]](#references)[[9]](#references)</sup>
```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```
Non dare per scontato che un vendor update capsule equivalga al contenuto del chip: potrebbe omettere NVRAM, contenere un'encapsulation o essere encrypted. [UEFITool](https://github.com/LongSoft/UEFITool) può analizzare una raw UEFI image suddividendola in firmware volumes, files e sections.<sup>[[7]](#references)</sup>

## Mappa una domanda IFR a NVRAM

[IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS) converte i pacchetti HII form in testo ed espone impostazioni che una vendor GUI nasconde, rinomina o sopprime. Il suo output può identificare la domanda, il variable store, il byte offset, la storage width, i valori validi e la visibilità condizionale.<sup>[[8]](#references)</sup>

1. Apri il dump in UEFITool, cerca il firmware file denominato `Setup`, espandilo fino alla PE32 image section e usa **Extract body**.
2. Esegui IFRExtractor-RS sul corpo EFI/PE32 estratto, quindi cerca nel testo generato controlli come `DMA`, `IOMMU`, `VT-d`, `Secure Boot` o l'etichetta mostrata all'utente dal vendor.
3. Registra `VarStoreId`, `VarOffset`, `Size`, le opzioni valide e il question ID. Non dedurre la semantica dei valori basandoti solo su `Flags`.
4. Trova la dichiarazione `VarStore`/`VarStoreEfi` corrispondente e associa lo store ID numerico al **name e GUID** della variabile.
5. Cerca quel GUID in UEFITool finché non raggiungi il relativo NVRAM object. Apri **Body hex view** e vai a `VarOffset` relativo al variable body, non all'intera flash image.<sup>[[3]](#references)</sup>
```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```
Per esempio, un'immagine Dell descriveva la domanda rilevante come `Control Iommu Pre-boot Behavior`, con `VarStoreId: 0x1`, `VarOffset: 0x975` e un campo di 8 bit. Lo Store `0x1` corrispondeva alla variabile `Setup` e al GUID `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9`; i dump differenziali hanno stabilito che, su quel firmware, `01` indicava abilitato e `00` disabilitato.<sup>[[3]](#references)</sup>

> [!WARNING]
> GUID, offset, layout delle strutture, istanze duplicate delle variabili e codifiche dei valori possono cambiare tra modelli e versioni del firmware. Non riutilizzare mai l'offset dell'esempio come valore universale per Dell.

## Validate with differential dumps

Quando l'interfaccia di setup è disponibile su un'unità di test equivalente, crea un dump con l'opzione abilitata e un altro con l'opzione disabilitata. Confronta il corpo della variabile derivato dall'IFR e verifica che cambi soltanto il campo previsto. In questo modo determini la codifica effettiva e distingui una variabile attiva dalle copie obsolete, predefinite o di recovery. Applica la patch a una copia dell'immagine originale verificata, riaprila in UEFITool e verifica che la modifica sia esterna agli intervalli di codice autenticati o misurati prima del reflashing.<sup>[[3]](#references)[[4]](#references)</sup>

Una modifica mirata può avere meno effetti collaterali rispetto alla cancellazione di una password del firmware, che potrebbe portare il dispositivo allo stato di fabbrica, richiedere il reinserimento di dati specifici del dispositivo o modificare le misurazioni dei PCR del TPM. Tuttavia, una modifica offline mirata può anche creare una pericolosa **divergenza tra stato visualizzato e stato effettivo**: l'interfaccia e gli strumenti di gestione potrebbero mostrare il vecchio valore mentre il firmware iniziale utilizza il byte modificato. La modifica illustrata non ha richiesto il recupero di BitLocker ed è sopravvissuta a un aggiornamento del BIOS del vendor, poiché l'aggiornamento ha preservato lo stato NVRAM alterato.<sup>[[3]](#references)</sup>

Il [Dell UEFI Patcher](https://github.com/craigsblackie/Dell_UEFI_Patcher) dell'autore illustra un patcher specifico per modello che individua gli intervalli dell'Intel Boot Guard Initial Boot Block e rifiuta le scritture normali al loro interno. Usa la modalità di analisi prima di `--apply`, esamina ogni corrispondenza candidata e considera i suoi valori predefiniti come esempi, non come offset riutilizzabili.<sup>[[4]](#references)</sup>
```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```
## Automatizza il mapping con NVRAMap

[NVRAMap](https://github.com/PN-Tester/NVRAMap) automatizza l'estrazione IFR, risolve il `VarStoreId` di una question nel GUID/nome NVRAM, visualizza i valori correnti delle opzioni e può modificare il campo selezionato. Può funzionare con un dump completo del firmware o con blob EFI e NVRAM estratti separatamente.<sup>[[5]](#references)</sup>
```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```
L'automazione non elimina la necessità di disporre di dump corrispondenti, hardware di recovery, controlli di integrità della regione o validazione post-flash.

## Concatenare un downgrade pre-boot dell'IOMMU con l'accesso DMA a Windows

Se il valore patchato consente il DMA PCIe prima di ExitBootServices, [DMAReaper](https://github.com/PN-Tester/DMAReaper) può risalire dalla EFI System Table attraverso le tabelle root ACPI, individuare la tabella `DMAR` e sovrascriverla prima che Windows la analizzi. In assenza di dati DMAR utilizzabili, Windows potrebbe non riuscire a inizializzare la Kernel DMA Protection basata su IOMMU. DMAReaper **non** disabilita autonomamente VBS/HVCI.<sup>[[1]](#references)</sup>

Nella catena dimostrata, il target è stato quindi avviato in Safe Mode per rimuovere la barriera VBS rimanente, dopodiché [PCILeech](https://github.com/ufrisk/pcileech) ha patchato la memoria fisica usando una firma di Sticky Keys:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```
Dopo una patch riuscita e compatibile con la build, l'attivazione di Sticky Keys nella schermata di accesso di Windows avviava un prompt dei comandi come `NT AUTHORITY\SYSTEM`. Le signature e gli intervalli di memoria raggiungibili dipendono dal target, dalla build e dall'hardware; una corrispondenza segnalata non dimostra che ogni versione di Windows sia sfruttabile.<sup>[[2]](#references)[[3]](#references)</sup>

Non considerare il menu del firmware come una validazione. Controlla **System Information (`msinfo32.exe`) → Kernel DMA Protection**, verifica VBS separatamente, controlla se il sistema operativo ha ricevuto una tabella DMAR valida e testa l'effettiva raggiungibilità DMA. Windows segnala Kernel DMA Protection solo quando la piattaforma e il firmware supportano la configurazione IOMMU richiesta.<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - Disabilitare Kernel DMA Protection tramite sovrascrittura DMAR pre-boot](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Software per attacchi Direct Memory Access](https://github.com/ufrisk/pcileech)
- [3] [MDSec - Disabilitare le funzionalità di sicurezza in un BIOS bloccato](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - Patching NVRAM compatibile con IBB](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - Mappare le impostazioni EFI ai valori NVRAM](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - Visualizzatore e parser di immagini firmware UEFI](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - Estrarre l'IFR UEFI in testo leggibile](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [flashrom manual - programmer e operazioni di lettura/scrittura](https://flashrom.org/classic_cli_manpage.html)
{{#include ../../banners/hacktricks-training.md}}
