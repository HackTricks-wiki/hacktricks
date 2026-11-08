# Test del bootloader

{{#include ../../banners/hacktricks-training.md}}

I passaggi seguenti sono consigliati per modificare le configurazioni di avvio dei dispositivi e testare bootloader come U-Boot e i loader di classe UEFI. Concentrati sull’ottenere l’esecuzione di codice nelle fasi iniziali, valutare le protezioni delle firme e contro il rollback e sfruttare i percorsi di ripristino o di avvio da rete.

Correlato: bypass del secure boot MediaTek tramite patching di bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Soluzioni rapide per U-Boot e abuso dell’ambiente

1. Accedi alla shell dell’interprete
   - Durante l’avvio, premi un tasto di interruzione noto (spesso un tasto qualsiasi, 0, spazio o una sequenza "magica" specifica della scheda) prima dell’esecuzione di `bootcmd` per accedere al prompt di U-Boot.<sup>[[1]](#references)</sup>

2. Esamina lo stato di avvio e le variabili
   - Comandi utili:
     - `printenv` (mostra l’ambiente)
     - `bdinfo` (informazioni sulla scheda, indirizzi di memoria)
     - `help bootm; help booti; help bootz` (metodi supportati per l’avvio del kernel)
     - `help ext4load; help fatload; help tftpboot` (loader disponibili)

3. Modifica gli argomenti di avvio per ottenere una shell root
   - Aggiungi `init=/bin/sh` per fare in modo che il kernel avvii una shell invece del normale processo init:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Avvio di rete dal tuo server TFTP
   - Configura la rete e recupera un’immagine kernel/FIT dalla LAN:
     ```
     # setenv ipaddr 192.168.2.2      # device IP
     # setenv serverip 192.168.2.1    # TFTP server IP
     # saveenv; reset
     # ping ${serverip}
     # tftpboot ${loadaddr} zImage           # kernel
     # tftpboot ${fdt_addr_r} devicetree.dtb # DTB
     # setenv bootargs "${bootargs} init=/bin/sh"
     # booti ${loadaddr} - ${fdt_addr_r}
     ```

5. Persisti le modifiche tramite l’ambiente
   - Se lo storage di env non è protetto da scrittura, puoi mantenere il controllo:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Controlla variabili come `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` che influenzano i percorsi di fallback. Valori configurati in modo errato possono consentire di accedere ripetutamente alla shell.

6. Controlla le funzionalità di debug/non sicure
   - Cerca: `bootdelay` > 0, `autoboot` disabilitato, `usb start; fatload usb 0:1 ...` senza restrizioni, possibilità di usare `loady`/`loads` tramite seriale, `env import` da supporti non attendibili e kernel/ramdisk caricati senza verifiche della firma.

7. Test delle immagini/verifiche U-Boot
   - Se la piattaforma dichiara di usare secure boot/verified boot con immagini FIT, prova sia immagini non firmate sia immagini manomesse:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - L’assenza di `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` o il comportamento legacy `verify=n` spesso consente di avviare payload arbitrari.
   - Non fermarti a un semplice risultato di allow/deny: ricerche recenti su FIT hanno dimostrato che il percorso di verifica stesso può costituire una superficie di attacco pre-auth. Esegui test negativi sui dati FIT archiviati esternamente (`data-offset`, `data-position`, `data-size`), sulla selezione della configurazione firmata, su `loadables` e sulla gestione di overlay / `extra-conf`.
   - Se hai un albero dei sorgenti corrispondente, `test/vboot/vboot_test.sh` è un modo rapido per riprodurre il comportamento della verifica FIT nel sandbox di U-Boot prima di intervenire sull’hardware reale.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` e flussi di avvio tramite script
   - Nelle build moderne di U-Boot, `bootcmd` è spesso solo un wrapper attorno a Standard Boot. Ciò significa che i supporti scrivibili, PXE o la memoria flash SPI possono diventare il vero confine di fiducia, anche quando l’ambiente visibile sembra innocuo.
   - Il bootmeth `extlinux` cerca `extlinux/extlinux.conf` sotto `/` e `/boot`; il bootmeth per gli script cerca prima `boot.scr.uimg` e poi `boot.scr`. Nell’avvio di rete, il nome dello script può provenire da `boot_script_dhcp`.
   - Comandi utili per il triage:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Casi di abuso da testare: supporti USB/SD controllati dall’attaccante posizionati prima in `boot_targets`, `/boot/extlinux/extlinux.conf` scrivibile, server TFTP rogue che fornisce `boot.scr` oppure esecuzione di script tramite SPI con `script_offset_f`.
   - Se la piattaforma si affida alla verifica FIT, assicurati che le configurazioni siano firmate a livello di configurazione e non solo per immagine; `required-mode=all` è più rigoroso che accettare una qualsiasi singola chiave richiesta.

### Dati FIT esterni di SPL copiati prima della verifica

Nel caricamento FIT di SPL, una firma di configurazione intatta non rende sicuri i metadati dei payload esterni. U-Boot esclude `data-position`, `data-offset` e `data-size` dalle proprietà della configurazione firmata. Nei percorsi `load_simple_fit()` interessati, SPL ricava da questi campi l’offset sorgente e la lunghezza da copiare, quindi chiama `info->read()` **prima** di controllare l’hash dell’immagine. Un FIT appositamente creato su supporti di avvio scrivibili può quindi sovrascrivere la RAM senza falsificare una firma. La proprietà firmata `load` normalmente fissa la destinazione, quindi per prima cosa determina se una copia troppo grande può raggiungere lo stack o altri dati di controllo a partire da quell’indirizzo.<sup>[[15]](#references)[[16]](#references)</sup>

Traccia il loader effettivo della scheda e la mappa di memoria, invece di presumere che avvenga una lettura flash: il loader RAM dimostrato raggiungeva `spl_ram_load_read()` e `memcpy()`. Nel punto della chiamata, annota `fit_offset` e qualsiasi indirizzo base FIT aggiunto dal reader, la lunghezza del blocco del loader (`spl_get_bl_len(info)`), l’eventuale allineamento specifico del fork, i valori risultanti di `read_offset` e della dimensione del trasferimento `size`, la destinazione `src_ptr` e la posizione dell’indirizzo di ritorno salvato. Verifica se una regione sorgente mappata contigua copre la distanza di copia richiesta, se si sovrappone alla destinazione e se i byte nella posizione sorgente possono fornire un puntatore a dati FIT controllati dall’attaccante. La tecnica generica di [partial return-address overwrite](../../binary-exploitation/stack-overflow/ret2win/) si applica se un puntatore completo non rispetta i vincoli di allineamento del loader.<sup>[[16]](#references)</sup>

Nel test build AST2600 a 32 bit dei ricercatori, `src_ptr` era `0x80001000` e l’indirizzo di ritorno salvato da `memcpy` si trovava a `0x902ffe24`. Hanno usato un build upstream modificato con il posizionamento dello stack e gli helper di allineamento di OpenBMC: il reader RAM aggiungeva una base FIT di `0x10000` e tali helper arrotondavano l’offset sorgente per difetto a `ARCH_DMA_MINALIGN` (64 byte). Un puntatore little-endian valido a `0x902fffe4` e una copia terminata un byte prima modificavano solo i tre byte meno significativi dell’indirizzo di ritorno salvato, preservandone il byte alto noto, pari a zero. Il loader RAM upstream, invece, usa una lunghezza del blocco di un byte, quindi questo allineamento a 64 byte e questa soluzione alternativa con sovrascrittura parziale non sono requisiti generali di SPL. Ricalcola indirizzi, lunghezza del blocco del loader ed estensione della copia per ogni build. Nel calcolo originale qui sotto, `fit_offset` indica l’aggiunta effettiva della base FIT da parte del reader RAM, non necessariamente l’argomento passato a `load_simple_fit()`.<sup>[[16]](#references)</sup>

```text
distance      = saved_return_slot - destination = 0x102fee24
data-position = pointer_slot - distance - fit_offset = 0x7fff11c0
data-size     = distance + 3 = 0x102fee27
```

La correzione upstream limita sia il `data-size` grezzo sia la dimensione di trasferimento **allineata ai blocchi** prima di `info->read()`. Il percorso overlay passa la capacità effettiva del buffer, mentre gli altri chiamanti usano `CONFIG_SYS_BOOTM_LEN`, che è solo un limite superiore approssimativo e non prova che la destinazione disponga di altrettanta memoria libera. Quando valuti un fork del vendor, verifica che questi controlli siano presenti e confronta l’intervallo di copia consentito con lo stack SPL effettivo della scheda e le aree riservate.<sup>[[15]](#references)[[16]](#references)</sup>

## Superficie di attacco del network boot (DHCP/PXE) e server malevoli

9. Fuzzing dei parametri PXE/DHCP
   - La gestione BOOTP/DHCP legacy di U-Boot ha presentato problemi di memory safety. Ad esempio, CVE‑2024‑42040 descrive una divulgazione di memoria tramite risposte DHCP appositamente create, che possono far trapelare in rete byte della memoria di U-Boot.<sup>[[4]](#references)</sup> Esercita i percorsi del codice DHCP/PXE usando valori eccessivamente lunghi o casi limite (nome del file di boot dell’opzione 67, opzioni del vendor, campi file/servername) e controlla se si verificano blocchi o leak.
   - Snippet minimo di Scapy per stressare i parametri di boot durante il netboot:
     ```python
     from scapy.all import *
     offer = (Ether(dst='ff:ff:ff:ff:ff:ff')/
              IP(src='192.168.2.1', dst='255.255.255.255')/
              UDP(sport=67, dport=68)/
              BOOTP(op=2, yiaddr='192.168.2.2', siaddr='192.168.2.1', chaddr=b'\xaa\xbb\xcc\xdd\xee\xff')/
              DHCP(options=[('message-type','offer'),
                            ('server_id','192.168.2.1'),
                            # Intentionally oversized and strange values
                            ('bootfile_name','A'*300),
                            ('vendor_class_id','B'*240),
                            'end']))
     sendp(offer, iface='eth0', loop=1, inter=0.2)
     ```
   - Verifica inoltre se i campi filename PXE vengono passati alla logica della shell/del loader senza sanitizzazione quando sono concatenati a script di provisioning lato OS.

10. Test di command injection nel server DHCP rogue
   - Configura un servizio DHCP/PXE rogue e prova a inserire caratteri nei campi filename o options per raggiungere gli interpreti di comandi nelle fasi successive della catena di boot. Metasploit’s DHCP auxiliary, `dnsmasq` o script Scapy personalizzati sono adatti. Assicurati prima di isolare la rete di laboratorio.

## Modalità di recovery della ROM del SoC che sovrascrivono il boot normale

Molti SoC espongono una modalità "loader" BootROM che accetta codice tramite USB/UART anche quando le immagini flash non sono valide. Se i fuse del secure boot non sono programmati, questa modalità può consentire l’esecuzione di codice arbitrario nelle primissime fasi della catena.

- NXP i.MX (Serial Download Mode)
  - Strumenti: `uuu` (mfgtools3) o `imx-usb-loader`.
  - Esempio: `imx-usb-loader u-boot.imx` per caricare ed eseguire dalla RAM un U-Boot personalizzato.
- Allwinner (FEL)
  - Strumento: `sunxi-fel`.
  - Esempio: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` oppure `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Strumento: `rkdeveloptool`.
  - Esempio: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` per caricare uno stadio intermedio e caricare un U-Boot personalizzato.

Verifica se i fuse eFuses/OTP del secure boot sono programmati. In caso contrario, le modalità di download BootROM spesso aggirano qualsiasi verifica di livello superiore (U-Boot, kernel, rootfs), eseguendo direttamente il payload del primo stadio dalla SRAM/DRAM.

## Bootloader UEFI/di classe PC: verifiche rapide

11. Test di manomissione dell’ESP, rollback e registrazione delle chiavi
   - Monta la EFI System Partition (ESP) e controlla i componenti del loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, i percorsi dei loghi del vendor.
   - Se possibile, scarica lo stato del Secure Boot e i database delle chiavi dal sistema operativo:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Se la piattaforma è in Setup Mode, accetta la registrazione di chiavi non autenticata o viene fornita con una Platform Key di test/predefinita (classe PKfail), un amministratore locale o un aggressore con accesso fisico può registrare la propria KEK/db e mantenere Secure Boot apparentemente “abilitato” pur avviando binari EFI arbitrari.<sup>[[3]](#references)</sup>
   - Prova ad avviare componenti di boot firmati con versioni precedenti o notoriamente vulnerabili, se le revoche di Secure Boot (dbx) non sono aggiornate. Se la piattaforma continua a fidarsi di vecchi shim/bootmanager, spesso puoi caricare il tuo kernel o `grub.cfg` dalla ESP per ottenere persistenza.
   - Su Windows, gli host aggiornati possono comunque accettare boot manager firmati vulnerabili se il firmatario `Microsoft Windows Production PCA 2011` è ancora assente dal `dbx` del firmware, come osservato con BlackX.<sup>[[13]](#references)[[14]](#references)</sup> Un bypass in stile Baton Drop può registrare una MOK dell'aggressore; in seguito, uno shim legittimo può caricare un payload EFI firmato con quella chiave.<sup>[[12]](#references)[[13]](#references)</sup> Revocare in seguito il vecchio firmatario di Windows non rimuove la MOK registrata, quindi il percorso basato su shim può persistere se lo shim continua a essere considerato attendibile.<sup>[[12]](#references)</sup>
   - Prima di testare questo percorso di rollback su una macchina UEFI autorizzata, controlla lo **stato effettivo delle revoche del firmware**, non solo la cronologia degli aggiornamenti di Windows.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft fornisce questo controllo in PowerShell, di sola lettura e con privilegi elevati, per verificare il firmatario 2011 in `dbx`:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` è solo un indizio: conferma quale componente di boot firmato e quali altre revoche sono coinvolti in un laboratorio ripristinabile.<sup>[[12]](#references)[[14]](#references)</sup> Un aggiornamento del registro in sospeso o un certificato di firma scaduto non equivalgono a una revoca `dbx` completata.<sup>[[13]](#references)[[14]](#references)</sup>

12. Test delle revoche per shim obsoleti / SBAT / dbx
   - Shim firmati da Microsoft e fork dei vendor obsoleti possono ancora costituire un percorso di bootkit in stile BYOVD se le revoche non sono aggiornate. In un laboratorio isolato, colloca uno shim storicamente vulnerabile sull'ESP e prova a eseguire chainload del tuo `grubx64.efi` o kernel.<sup>[[11]](#references)</sup>
   - Triage rapido:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Se lo shim continua a essere eseguito nonostante sia presente nell'elenco di revoca, il firmware/OS ha aggiornamenti `dbx` obsoleti oppure considera attendibile un loader forkato che non ha mai ereditato le protezioni SBAT upstream.

13. Bug nell'analisi del logo di avvio (classe LogoFAIL)
   - Diversi firmware OEM/IBV erano vulnerabili a difetti nell'analisi delle immagini in DXE, che elaborano i loghi di avvio. Se un attaccante può inserire un'immagine appositamente creata nell'ESP in un percorso specifico del vendor (ad es., `\EFI\<vendor>\logo\*.bmp`) e riavviare, potrebbe ottenere l'esecuzione di codice durante le prime fasi di avvio, anche con Secure Boot abilitato. Verifica se la piattaforma accetta loghi forniti dall'utente e se tali percorsi sono scrivibili dal sistema operativo.<sup>[[2]](#references)</sup>


## Lacune di attendibilità di Android/Qualcomm ABL + GBL (Android 16)

Nei dispositivi Android 16 che usano ABL di Qualcomm per caricare la **Generic Bootloader Library (GBL)**, verifica se ABL **autentica** l'app UEFI che carica dalla partizione `efisp`. Se ABL controlla soltanto la **presenza** di un'app UEFI e non ne verifica le firme, una primitiva di scrittura su `efisp` consente l'**esecuzione di codice non firmato prima dell'avvio del sistema operativo**.<sup>[[6]](#references)[[7]](#references)</sup>

Verifiche pratiche e vettori di abuso:

- **Primitiva di scrittura su efisp**: serve un modo per scrivere un'app UEFI personalizzata in `efisp` (servizio root/con privilegi, bug nell'app OEM, percorso recovery/fastboot). Senza questo, la lacuna nel caricamento di GBL non è direttamente sfruttabile.<sup>[[6]](#references)</sup>
- **Iniezione di argomenti OEM fastboot** (bug di ABL): alcune build accettano token aggiuntivi in `fastboot oem set-gpu-preemption` e li aggiungono alla riga di comando del kernel. Questo può essere usato per forzare SELinux in modalità permissiva e consentire la scrittura nelle partizioni protette:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Se il dispositivo è patchato, il comando dovrebbe rifiutare gli argomenti aggiuntivi.<sup>[[5]](#references)[[6]](#references)</sup>
- **Sblocco del bootloader tramite flag persistenti**: un payload nella fase di boot può modificare i flag di sblocco persistenti (ad es., `is_unlocked=1`, `is_unlocked_critical=1`) per emulare `fastboot oem unlock` senza i controlli del server o di approvazione OEM. Questo modifica in modo duraturo lo stato del dispositivo dopo il riavvio successivo.<sup>[[6]](#references)</sup>

Note difensive/di triage:

- Verifica se ABL esegue la verifica della firma sul payload GBL/UEFI proveniente da `efisp`. In caso contrario, considera `efisp` una superficie di persistenza ad alto rischio.
- Verifica se i gestori OEM di fastboot in ABL sono patchati per **convalidare il numero di argomenti** e rifiutare token aggiuntivi.<sup>[[8]](#references)[[9]](#references)</sup>

## Avvertenza sull'hardware

Presta attenzione quando interagisci con la flash SPI/NAND durante le prime fasi del boot (ad es., mettendo a massa i pin per aggirare le letture) e consulta sempre il datasheet della flash. Cortocircuiti eseguiti nel momento sbagliato possono danneggiare il dispositivo o il programmatore.

## Note e suggerimenti aggiuntivi

- Prova `env export -t ${loadaddr}` e `env import -t ${loadaddr}` per trasferire i blob dell'ambiente tra RAM e storage; alcune piattaforme consentono di importare l'ambiente da supporti rimovibili senza autenticazione.
- Per ottenere persistenza sui sistemi basati su Linux che eseguono il boot tramite `extlinux.conf`, spesso è sufficiente modificare la riga `APPEND` (per iniettare `init=/bin/sh` o `rd.break`) nella partizione di boot, se non vengono applicati controlli della firma.
- Se il target usa aggiornamenti a doppio slot / A/B, consulta le tecniche anti-rollback e di desincronizzazione degli slot nella [panoramica sull'analisi del firmware](README.md) per non trascurare eventuali lacune di trust presenti solo nell'updater, al di fuori del bootloader stesso.
- Se lo userland fornisce `fw_printenv/fw_setenv`, verifica che `/etc/fw_env.config` corrisponda allo storage effettivo dell'ambiente. Offset non corretti consentono di leggere/scrivere la regione MTD sbagliata.

## References

- [1] [Metodologia di test della sicurezza del firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Alla scoperta di LogoFAIL: i pericoli dell'analisi delle immagini durante l'avvio del sistema](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: chiavi di piattaforma non attendibili compromettono Secure Boot nell'ecosistema UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Dettagli su CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: sbloccare Xiaomi tramite due stringhe non sanificate](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [L'exploit GBL di Qualcomm Snapdragon 8 Elite consente agli attaccanti di sbloccare i bootloader](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Architettura del Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: corregge la propagazione di input non attendibili nella riga di comando del kernel](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: aggiunge un controllo per il comando set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Unfit to boot: aggirare la verifica della firma FIT di U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Nota sulla vulnerabilità VU#616257 - I bootloader shim UEFI firmati da Microsoft sono vulnerabili all'aggiramento di Secure Boot](https://kb.cert.org/vuls/id/616257)
- [12] [Bootkit UEFI BlackLotus: il mito confermato](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: un bootkit UEFI simile a BlackLotus](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Come gestire le revoche di Windows Boot Manager per le modifiche a Secure Boot](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
- [15] [Patch U-Boot: limita la dimensione dei dati esterni prima di leggerli](https://github.com/u-boot/u-boot/commit/8f71d7170f5c3abadee45683e35ae6d925b6d417)
- [16] [Hidden beneFITs: aggirare la verifica della firma in U-Boot SPL](https://www.binarly.io/blog/signature-verification-bypass-in-u-boot-spl)
{{#include ../../banners/hacktricks-training.md}}
