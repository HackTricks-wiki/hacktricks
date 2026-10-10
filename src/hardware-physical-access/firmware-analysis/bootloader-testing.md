# Test dei bootloader

{{#include ../../banners/hacktricks-training.md}}

I seguenti passaggi sono consigliati per modificare le configurazioni di avvio dei dispositivi e testare bootloader come U-Boot e i loader di classe UEFI. Concentrati sull'ottenere l'esecuzione precoce del codice, valutare le protezioni di firma e rollback e abusare dei percorsi di recovery o network boot.

Correlato: bypass del secure boot MediaTek tramite patching di bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Soluzioni rapide per U-Boot e abuso dell'ambiente

1. Accedi alla shell dell'interprete
   - Durante l'avvio, premi un tasto di interruzione noto (spesso un tasto qualsiasi, 0, spazio o una sequenza "magica" specifica della scheda) prima che venga eseguito `bootcmd` per accedere al prompt di U-Boot.<sup>[[1]](#references)</sup>

2. Esamina lo stato di avvio e le variabili
   - Comandi utili:
     - `printenv` (mostra l'ambiente)
     - `bdinfo` (informazioni sulla scheda, indirizzi di memoria)
     - `help bootm; help booti; help bootz` (metodi supportati per l'avvio del kernel)
     - `help ext4load; help fatload; help tftpboot` (loader disponibili)

3. Modifica gli argomenti di avvio per ottenere una root shell
   - Aggiungi `init=/bin/sh` in modo che il kernel avvii una shell invece del normale init:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Avvia tramite netboot dal tuo server TFTP
   - Configura la rete e recupera un'immagine kernel/fit dalla LAN:
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

5. Rendi persistenti le modifiche tramite l'ambiente
   - Se l'archiviazione dell'ambiente non è protetta da scrittura, puoi rendere persistente il controllo:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Controlla variabili come `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` che influenzano i percorsi di fallback. Valori configurati male possono consentire accessi ripetuti alla shell.

6. Controlla le funzionalità di debug/non sicure
   - Cerca: `bootdelay` > 0, `autoboot` disabilitato, `usb start; fatload usb 0:1 ...` senza restrizioni, possibilità di usare `loady`/`loads` via seriale, `env import` da supporti non attendibili e kernel/ramdisk caricati senza controlli della firma.

7. Test delle immagini/verifiche U-Boot
   - Se la piattaforma dichiara di usare il secure boot/verified boot con immagini FIT, prova immagini sia non firmate sia manomesse:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - L’assenza di `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` o il comportamento legacy `verify=n` spesso consente di avviare payload arbitrari.
   - Non fermarti a un semplice risultato di autorizzazione/negazione: ricerche recenti su FIT hanno mostrato che il percorso di verifica stesso può costituire una superficie di attacco pre-auth. Esegui test negativi sui dati FIT archiviati esternamente (`data-offset`, `data-position`, `data-size`), sulla selezione della configurazione firmata, su `loadables` e sulla gestione di overlay / `extra-conf`.
   - Se hai un albero dei sorgenti corrispondente, `test/vboot/vboot_test.sh` è un modo rapido per riprodurre il comportamento di verifica FIT in U-Boot sandbox prima di intervenire sull’hardware reale.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` e script bootflow
   - Nelle build moderne di U-Boot, `bootcmd` spesso è solo un wrapper attorno a Standard Boot. Ciò significa che i supporti scrivibili, PXE o la flash SPI possono diventare il vero confine di fiducia, anche quando l’ambiente visibile sembra innocuo.
   - Il bootmeth `extlinux` cerca `extlinux/extlinux.conf` sotto `/` e `/boot`; lo script bootmeth cerca prima `boot.scr.uimg` e poi `boot.scr`. Nell’avvio di rete, il nome dello script può provenire da `boot_script_dhcp`.
   - Comandi utili per il triage:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Casi di abuso da testare: supporti USB/SD controllati dall’attaccante in una posizione precedente in `boot_targets`, `/boot/extlinux/extlinux.conf` scrivibile, un server TFTP rogue che fornisce `boot.scr` oppure l’esecuzione di script tramite SPI con `script_offset_f`.
   - Se la piattaforma si affida alla verifica FIT, assicurati che le configurazioni siano firmate a livello di configurazione e non solo per immagine; `required-mode=all` è più rigoroso rispetto all’accettazione di una qualsiasi singola chiave richiesta.

## Superficie di avvio di rete (DHCP/PXE) e server rogue

9. Fuzzing dei parametri PXE/DHCP
   - La gestione legacy di BOOTP/DHCP di U-Boot ha presentato problemi di sicurezza della memoria. Per esempio, CVE‑2024‑42040 descrive una divulgazione di memoria tramite risposte DHCP appositamente create, che possono esporre byte della memoria di U-Boot in rete.<sup>[[4]](#references)</sup> Esegui test sui percorsi del codice DHCP/PXE usando valori eccessivamente lunghi o limite (nome file di avvio dell’opzione 67, opzioni vendor, campi file/servername) e verifica la presenza di blocchi/leak.
   - Frammento Scapy minimo per mettere sotto stress i parametri di avvio durante il netboot:
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
   - Verifica inoltre se i campi filename PXE vengono passati alla logica della shell/loader senza sanitizzazione quando sono concatenati a script di provisioning lato OS.

10. Test di command injection con server DHCP rogue
   - Configura un servizio DHCP/PXE rogue e prova a iniettare caratteri nei campi filename o options per raggiungere gli interpreti di comandi nelle fasi successive della catena di boot. Metasploit’s DHCP auxiliary, `dnsmasq` o script Scapy personalizzati sono strumenti efficaci. Prima, assicurati di isolare la rete di laboratorio.

## Modalità di recovery della ROM del SoC che sovrascrivono il boot normale

Molti SoC espongono una modalità "loader" della BootROM che accetta codice tramite USB/UART anche quando le immagini flash non sono valide. Se i fuse del secure boot non sono programmati, questa modalità può consentire l’esecuzione di codice arbitrario nelle primissime fasi della catena.

- NXP i.MX (Serial Download Mode)
  - Strumenti: `uuu` (mfgtools3) o `imx-usb-loader`.
  - Esempio: `imx-usb-loader u-boot.imx` per caricare ed eseguire da RAM un U-Boot personalizzato.
- Allwinner (FEL)
  - Strumento: `sunxi-fel`.
  - Esempio: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` oppure `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Strumento: `rkdeveloptool`.
  - Esempio: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` per caricare un loader e caricare un U-Boot personalizzato.

Verifica se gli eFuse/OTP del secure boot del dispositivo sono programmati. In caso contrario, le modalità di download della BootROM spesso aggirano qualsiasi verifica di livello superiore (U-Boot, kernel, rootfs), eseguendo direttamente il payload del primo stadio da SRAM/DRAM.

## Bootloader UEFI/PC: controlli rapidi

11. Test di manomissione dell’ESP, rollback e registrazione delle chiavi
   - Monta la EFI System Partition (ESP) e cerca i componenti del loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, percorsi dei loghi del produttore.
   - Quando possibile, scarica lo stato del Secure Boot e i database delle chiavi dal sistema operativo:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Se la piattaforma è in Setup Mode, accetta la registrazione di chiavi senza autenticazione oppure viene fornita con una Platform Key di test/predefinita (classe PKfail), un amministratore locale o un aggressore con accesso fisico può registrare le proprie KEK/db e mantenere Secure Boot apparentemente “abilitato” mentre avvia binari EFI arbitrari.<sup>[[3]](#references)</sup>
   - Prova ad avviare componenti di boot firmati vulnerabili noti o con versione precedente se le revoche di Secure Boot (dbx) non sono aggiornate. Se la piattaforma si fida ancora di vecchi shim/bootmanager, spesso puoi caricare il tuo kernel o `grub.cfg` dall’ESP per ottenere persistenza.

12. Test delle revoche di shim / SBAT / dbx obsolete
   - I vecchi shim firmati da Microsoft e i fork dei vendor possono ancora fungere da vettore per un bootkit in stile BYOVD se le revoche sono obsolete. In un laboratorio isolato, colloca uno shim storicamente vulnerabile nell’ESP e prova a concatenare il caricamento del tuo `grubx64.efi` o kernel.<sup>[[11]](#references)</sup>
   - Triage rapido:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Se lo shim continua a essere eseguito nonostante sia nell’elenco di revoca, il firmware/OS ha aggiornamenti `dbx` obsoleti oppure si fida di un loader forkato che non ha mai ereditato le protezioni SBAT upstream.

13. Bug nel parsing del logo di avvio (classe LogoFAIL)
   - Diversi firmware OEM/IBV erano vulnerabili a flaw nel parsing delle immagini in DXE, durante l’elaborazione dei loghi di avvio. Se un attaccante può inserire un’immagine appositamente creata nell’ESP in un percorso specifico del vendor (ad es., `\EFI\<vendor>\logo\*.bmp`) e riavviare, potrebbe essere possibile ottenere code execution nelle prime fasi dell’avvio, anche con Secure Boot abilitato. Verifica se la piattaforma accetta loghi forniti dall’utente e se è possibile scrivere in quei percorsi dall’OS.<sup>[[2]](#references)</sup>


## Lacune di trust in Android/Qualcomm ABL + GBL (Android 16)

Sui dispositivi Android 16 che usano ABL di Qualcomm per caricare la **Generic Bootloader Library (GBL)**, verifica se ABL **autentica** l'app UEFI caricata dalla partizione `efisp`. Se ABL controlla solo la **presenza** di un'app UEFI e non ne verifica le firme, una write primitive su `efisp` consente code execution non firmata prima dell'avvio dell'OS.<sup>[[6]](#references)[[7]](#references)</sup>

Controlli pratici e percorsi di abuso:

- **write primitive su efisp**: serve un modo per scrivere un'app UEFI personalizzata in `efisp` (root/servizio privilegiato, bug di un'app OEM, percorso recovery/fastboot). Senza questo, la lacuna nel caricamento di GBL non è direttamente sfruttabile.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (bug di ABL): alcune build accettano token aggiuntivi in `fastboot oem set-gpu-preemption` e li aggiungono alla cmdline del kernel. Questo può essere usato per forzare SELinux in modalità permissiva, consentendo la scrittura su partizioni protette:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Se il dispositivo è patchato, il comando dovrebbe rifiutare gli argomenti extra.<sup>[[5]](#references)[[6]](#references)</sup>
- **Sblocco del bootloader tramite flag persistenti**: un payload nella fase di boot può modificare i flag di sblocco persistenti (ad es. `is_unlocked=1`, `is_unlocked_critical=1`) per simulare `fastboot oem unlock` senza passare dai controlli del server o dell’approvazione OEM. Questo modifica in modo duraturo lo stato del dispositivo dopo il riavvio successivo.<sup>[[6]](#references)</sup>

Note per la difesa e il triage:

- Verificare se ABL esegue la verifica della firma del payload GBL/UEFI da `efisp`. In caso contrario, considerare `efisp` una superficie di persistenza ad alto rischio.
- Verificare se gli handler fastboot OEM di ABL sono patchati per **convalidare il numero di argomenti** e rifiutare token aggiuntivi.<sup>[[8]](#references)[[9]](#references)</sup>

## Precauzioni hardware

Prestare attenzione quando si interagisce con la flash SPI/NAND durante le prime fasi di boot (ad es., mettendo a massa i pin per bypassare le letture) e consultare sempre il datasheet della flash. Cortocircuiti eseguiti nel momento sbagliato possono danneggiare il dispositivo o il programmatore.

## Note e suggerimenti aggiuntivi

- Provare `env export -t ${loadaddr}` e `env import -t ${loadaddr}` per spostare i blob dell’ambiente tra RAM e storage; alcune piattaforme consentono di importare l’ambiente da supporti rimovibili senza autenticazione.
- Per ottenere persistenza su sistemi basati su Linux che si avviano tramite `extlinux.conf`, spesso è sufficiente modificare la riga `APPEND` (per iniettare `init=/bin/sh` o `rd.break`) nella partizione di boot, se non vengono applicati controlli della firma.
- Se il target usa aggiornamenti dual-slot/A/B, consultare le tecniche anti-rollback e di desincronizzazione degli slot nella [panoramica sull’analisi del firmware](README.md) per non tralasciare eventuali lacune di trust presenti solo nell’updater, al di fuori del bootloader stesso.
- Se lo userland fornisce `fw_printenv/fw_setenv`, verificare che `/etc/fw_env.config` corrisponda alla posizione effettiva dello storage dell’ambiente. Offset configurati in modo errato consentono di leggere/scrivere la regione MTD sbagliata.

## References

- [1] [Metodologia di test della sicurezza del firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Alla scoperta di LogoFAIL: i pericoli dell’analisi delle immagini durante il boot del sistema](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: chiavi di piattaforma non attendibili compromettono Secure Boot nell’ecosistema UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Dettagli su CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: sbloccare Xiaomi tramite due stringhe non sanificate](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [L’exploit GBL di Qualcomm Snapdragon 8 Elite consente agli attaccanti di sbloccare i bootloader](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Architettura del Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: correzione della propagazione di input non attendibili nella riga di comando del kernel](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: aggiunta di un controllo per il comando set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Non adatto al boot: come aggirare la verifica della firma FIT di U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Nota sulla vulnerabilità VU#616257 - I bootloader shim UEFI firmati da Microsoft sono vulnerabili al bypass di Secure Boot](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
