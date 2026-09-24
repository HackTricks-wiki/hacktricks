# UEFI IFR e NVRAM Security-Setting Patching

{{#include ../../banners/hacktricks-training.md}}

Uma senha de setup protege a interface de usuário do firmware, mas não autentica necessariamente os bytes de configuração armazenados no SPI flash. Com acesso físico de escrita, um assessor pode mapear uma configuração UEFI oculta ou bloqueada a partir de sua **Human Interface Infrastructure (HII) Internal Forms Representation (IFR)** para a variável NVRAM correspondente, modificar esse valor offline e fazer o reflash. Em um sistema Dell afetado, isso alterou o estado do IOMMU no pré-boot, enquanto a configuração gráfica ainda exibia a proteção DMA como habilitada.<sup>[[3]](#references)</sup>

> [!CAUTION]
> A gravação do firmware pode inutilizar permanentemente o alvo. Trabalhe em um dispositivo de teste autorizado e recuperável; mantenha a imagem original; e obtenha pelo menos três leituras independentes cujos hashes criptográficos correspondam antes de modificar qualquer coisa.<sup>[[3]](#references)</sup>

## Adquirir a imagem do firmware

Leia apenas a região BIOS quando o flash descriptor da Intel permitir acesso pelo host, ou use um programador externo com a tensão correta e um clip para conexão em circuito. Normalmente, é necessário um programador externo para restaurar uma máquina que não inicializa mais.<sup>[[3]](#references)[[9]](#references)</sup>
```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```
Não presuma que uma cápsula de atualização do fornecedor seja equivalente ao conteúdo do chip: ela pode omitir a NVRAM, conter encapsulamento ou estar criptografada. O [UEFITool](https://github.com/LongSoft/UEFITool) pode analisar uma imagem UEFI bruta em volumes de firmware, arquivos e seções.<sup>[[7]](#references)</sup>

## Mapear uma pergunta IFR para a NVRAM

O [IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS) converte pacotes de formulários HII em texto e expõe configurações que uma GUI do fornecedor oculta, renomeia ou suprime. A saída pode identificar a pergunta, o armazenamento de variáveis, o deslocamento em bytes, a largura de armazenamento, os valores válidos e a visibilidade condicional.<sup>[[8]](#references)</sup>

1. Abra o dump no UEFITool, pesquise pelo arquivo de firmware chamado `Setup`, expanda-o até a seção de imagem PE32 e use **Extract body**.
2. Execute o IFRExtractor-RS no corpo EFI/PE32 extraído e pesquise no texto gerado por controles como `DMA`, `IOMMU`, `VT-d`, `Secure Boot` ou pelo rótulo exibido ao usuário pelo fornecedor.
3. Registre `VarStoreId`, `VarOffset`, `Size`, as opções válidas e o ID da pergunta. Não infira a semântica dos valores apenas com base em `Flags`.
4. Encontre a declaração `VarStore`/`VarStoreEfi` correspondente e mapeie o ID numérico do armazenamento para seu **nome e GUID**.
5. Pesquise esse GUID no UEFITool até chegar ao objeto NVRAM correspondente. Abra **Body hex view** e navegue até `VarOffset` relativo ao corpo da variável — não à imagem flash inteira.<sup>[[3]](#references)</sup>
```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```
Por exemplo, uma imagem da Dell descreveu a pergunta relevante como `Control Iommu Pre-boot Behavior`, com `VarStoreId: 0x1`, `VarOffset: 0x975` e um campo de 8 bits. O Store `0x1` mapeava para a variável `Setup` e o GUID `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9`; dumps diferenciais estabeleceram `01` como habilitado e `00` como desabilitado nesse firmware.<sup>[[3]](#references)</sup>

> [!WARNING]
> GUIDs, offsets, layouts de estruturas, instâncias de variáveis duplicadas e codificações de valores podem mudar entre modelos e versões de firmware. Nunca reutilize o offset do exemplo como um valor universal da Dell.

## Validate with differential dumps

Quando a interface de setup estiver disponível em uma unidade de teste equivalente, crie um dump com a opção habilitada e outro com ela desabilitada. Compare o corpo da variável derivado do IFR e confirme que somente o campo esperado foi alterado. Isso determina a codificação real e distingue uma variável ativa de cópias obsoletas, padrão ou de recuperação. Faça o patch de uma cópia da imagem original verificada, reabra-a no UEFITool e confirme que a edição está fora dos intervalos de código autenticados ou medidos antes de reflashear.<sup>[[3]](#references)[[4]](#references)</sup>

Uma edição direcionada pode ter menos efeitos colaterais do que limpar uma senha de firmware, o que pode colocar o dispositivo em um estado de fábrica, exigir que dados específicos do dispositivo sejam inseridos novamente ou alterar as medições dos PCRs do TPM. No entanto, uma edição offline direcionada também pode criar uma perigosa **divergência entre estado exibido e estado efetivo**: a interface e as ferramentas de gerenciamento podem mostrar o valor antigo enquanto o firmware inicial consome o byte alterado. A alteração demonstrada não solicitou a recuperação do BitLocker e persistiu após uma atualização do BIOS do fabricante, pois a atualização preservou o estado alterado do NVRAM.<sup>[[3]](#references)</sup>

O [Dell UEFI Patcher](https://github.com/craigsblackie/Dell_UEFI_Patcher) do autor ilustra um patcher específico para um modelo que identifica intervalos do Intel Boot Guard Initial Boot Block e recusa gravações normais dentro deles. Use o modo de análise antes de `--apply`, inspecione cada correspondência candidata e trate seus padrões como exemplos, não como offsets portáteis.<sup>[[4]](#references)</sup>
```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```
## Automatize o mapeamento com NVRAMap

[NVRAMap](https://github.com/PN-Tester/NVRAMap) automatiza a extração de IFR, resolve o `VarStoreId` de uma questão para o GUID/nome do NVRAM, exibe os valores atuais das opções e pode editar o campo selecionado. Ele pode funcionar a partir de um dump completo do firmware ou de blobs EFI e NVRAM extraídos separadamente.<sup>[[5]](#references)</sup>
```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```
A automação não elimina a necessidade de dumps correspondentes, hardware de recuperação, verificações de integridade da região ou validação pós-flash.

## Encadeando um downgrade de IOMMU pré-boot ao acesso DMA do Windows

Se o valor patched permitir DMA PCIe antes de ExitBootServices, [DMAReaper](https://github.com/PN-Tester/DMAReaper) pode percorrer a EFI System Table a partir das tabelas raiz ACPI, localizar a tabela `DMAR` e sobrescrevê-la antes que o Windows a analise. Sem dados `DMAR` utilizáveis, o Windows pode não conseguir inicializar a Kernel DMA Protection baseada em IOMMU. O DMAReaper **não** desabilita VBS/HVCI por si só.<sup>[[1]](#references)</sup>

Na cadeia demonstrada, o alvo foi então inicializado no Modo de Segurança para remover a barreira VBS restante, e o [PCILeech](https://github.com/ufrisk/pcileech) aplicou um patch na memória física usando uma assinatura de Sticky Keys:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```
Após um patch compatível com a build e aplicado com sucesso, invocar Sticky Keys na tela de login do Windows iniciou um prompt de comando como `NT AUTHORITY\SYSTEM`. As assinaturas e os intervalos de memória acessíveis dependem do target, da build e do hardware; uma correspondência relatada não é evidência de que todas as versões do Windows sejam exploráveis.<sup>[[2]](#references)[[3]](#references)</sup>

Não confie no menu do firmware como validação. Verifique **Informações do Sistema (`msinfo32.exe`) → Proteção DMA do Kernel**, confirme o VBS separadamente, inspecione se o sistema operacional recebeu uma tabela DMAR válida e teste a acessibilidade real via DMA. O Windows informa a Proteção DMA do Kernel somente quando a plataforma e o firmware oferecem suporte à configuração de IOMMU necessária.<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - Desativar a Proteção DMA do Kernel por meio de sobrescrita de DMAR no pré-boot](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Software de ataque por Acesso Direto à Memória](https://github.com/ufrisk/pcileech)
- [3] [MDSec - Desativando recursos de segurança em um BIOS bloqueado](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - Patching de NVRAM com suporte a IBB](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - Mapear configurações EFI para valores da NVRAM](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Proteção DMA do Kernel](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - Visualizador e parser de imagens de firmware UEFI](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - Extrair IFR UEFI para texto legível](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [manual do flashrom - programmers e operações de leitura/escrita](https://flashrom.org/classic_cli_manpage.html)
{{#include ../../banners/hacktricks-training.md}}
