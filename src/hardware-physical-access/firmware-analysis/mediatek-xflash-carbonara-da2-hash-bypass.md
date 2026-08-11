# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Resumo

"Carbonara" explora o caminho de download XFlash da MediaTek para executar um estágio 2 (DA2) modificado do Download Agent apesar das verificações de integridade do DA1. O DA1 armazena o SHA-256 esperado do DA2 na RAM e o compara antes de desviar a execução. Em muitos loaders, o host controla totalmente o endereço/tamanho de carregamento do DA2, fornecendo uma escrita de memória não verificada que pode sobrescrever o hash armazenado na memória e redirecionar a execução para payloads arbitrários (contexto pré-OS, com a invalidação de cache gerenciada pelo DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Limite de confiança no XFlash (DA1 → DA2)

- **DA1** é assinado/carregado pelo BootROM/Preloader. Quando a Download Agent Authorization (DAA) está habilitada, somente um DA1 assinado deve ser executado.
- **DA2** é enviado por USB. O DA1 recebe o **tamanho**, o **endereço de carregamento** e o **SHA-256**, calcula o hash do DA2 recebido e o compara com um **hash esperado incorporado no DA1** (copiado para a RAM).
- **Fraqueza:** Em loaders sem patch, o DA1 não sanitiza o endereço/tamanho de carregamento do DA2 e mantém o hash esperado gravável na memória, permitindo que o host adultere a verificação.<sup>[[1]](#references)[[2]](#references)</sup>

## Fluxo do Carbonara (truque dos "dois BOOT_TO")

1. **Primeiro `BOOT_TO`:** Entra no fluxo de staging DA1→DA2 (o DA1 aloca, prepara a DRAM e expõe o buffer do hash esperado na RAM).
2. **Sobrescrita do slot do hash:** Envia um pequeno payload que procura na memória do DA1 o hash esperado armazenado do DA2 e o sobrescreve com o SHA-256 do DA2 modificado pelo atacante. Isso explora o carregamento controlado pelo usuário para posicionar o payload onde o hash está localizado.
3. **Segundo `BOOT_TO` + digest:** Dispara outro `BOOT_TO` com os metadados do DA2 alterados e envia o digest bruto de 32 bytes correspondente ao DA2 modificado. O DA1 recalcula o SHA-256 sobre o DA2 recebido, compara-o com o hash esperado agora alterado e o salto para o código do atacante é bem-sucedido.

Nos loaders afetados, o endereço e o tamanho não verificados podem fornecer ao atacante uma primitiva de escrita de memória pré-OS escolhida por ele, além do slot do hash. Dependendo do mapa de memória do SoC e das etapas posteriores de verificação, isso pode permitir implantes de early-boot, helpers de secure-boot-bypass ou payloads no estilo rootkit. A execução de código do DA, por si só, não fornece automaticamente persistência nem um bypass completo do secure boot; ainda são necessários um mecanismo de persistência separado e uma cadeia de verificação compatível.<sup>[[1]](#references)[[2]](#references)</sup>

## Padrão mínimo de PoC (no estilo mtkclient)
```python
if self.xsend(self.Cmd.BOOT_TO):
payload = bytes.fromhex("a4de2200000000002000000000000000")
if self.xsend(payload) and self.status() == 0:
import hashlib
da_hash = hashlib.sha256(self.daconfig.da2).digest()
if self.xsend(da_hash):
self.status()
self.info("All good!")
```
- O `payload` de 16 bytes reproduz o blob observado no workflow da ferramenta paga e usado pela implementação publicada para modificar o buffer de expected-hash. Ele é específico do loader, não um patch portátil de hash-slot para todos os SoCs ou DAs.<sup>[[1]](#references)[[2]](#references)</sup>
- `sha256(...).digest()` envia bytes brutos (não hexadecimais), para que o DA1 compare com o buffer modificado.
- Em um loader vulnerável e compatível, o DA2 pode ser uma imagem criada pelo atacante, e os metadados de carregamento escolhidos controlam seu posicionamento na memória. Valide a combinação DA/SoC antes da transmissão, pois endereços incorretos podem travar ou danificar o alvo.<sup>[[3]](#references)</sup>

## Cenário de patches (loaders hardened)

- **Mitigação observada**: Os DAs hardened examinados pelos pesquisadores forçam o endereço de carregamento do DA2 para `0x40000000` e ignoram o endereço fornecido pelo host, impedindo gravações na região de hash observada do DA1 próxima de `0x200000`. Considere ambos os endereços específicos da implementação, não constantes arquiteturais.
- **Detecção de DAs patched**: mtkclient/penumbra verificam o DA1 em busca de padrões que indicam o hardening do endereço; quando encontrados, o Carbonara é ignorado. DAs antigos expõem hash slots graváveis (comumente em offsets como `0x22dea4` no DA1 V5) e continuam exploráveis.
- **V5 vs V6**: Alguns loaders V6 (XML) ainda aceitam endereços fornecidos pelo usuário; binários V6 mais recentes normalmente impõem o endereço fixo e são imunes ao Carbonara, a menos que sofram downgrade.<sup>[[2]](#references)[[3]](#references)</sup>

## Nota sobre o pós-Carbonara (heapb8)

A MediaTek corrigiu o Carbonara; uma vulnerabilidade mais recente, **heapb8**, tem como alvo o handler de download de arquivos via USB do DA2 em loaders V6 patched, obtendo execução de código mesmo quando `boot_to` está hardened. Ela explora um heap overflow durante transferências de arquivos em chunks para assumir o fluxo de execução do DA2. O exploit é público no Penumbra/mtk-payloads e demonstra que as correções do Carbonara não fecham toda a superfície de ataque do DA.<sup>[[4]](#references)</sup>

## Notas para triagem e hardening

- Dispositivos nos quais o endereço/tamanho do DA2 não são verificados e o DA1 mantém o expected hash gravável são vulneráveis. Se um Preloader/DA posterior impuser limites de endereço ou mantiver o hash imutável, o Carbonara será mitigado.
- Ativar o DAA e garantir que o DA1/Preloader valide os parâmetros de BOOT_TO (limites + autenticidade do DA2) elimina a primitiva. Fechar apenas o patch do hash sem limitar o carregamento ainda deixa o risco de escrita arbitrária.

## References

- [1] [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
{{#include ../../banners/hacktricks-training.md}}
