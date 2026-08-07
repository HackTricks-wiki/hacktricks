# MediaTek XFlash Carbonara Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Limite de confiança no XFlash (DA1 → DA2)

- **DA1** é assinado/carregado pelo BootROM/Preloader. Quando o Download Agent Authorization (DAA) está habilitado, apenas um DA1 assinado deve ser executado.
- **DA2** é enviado via USB. O DA1 recebe o **tamanho**, o **endereço de carregamento** e o **SHA-256**, calcula o hash do DA2 recebido e o compara com um **hash esperado incorporado no DA1** (copiado para a RAM).
- **Fraqueza:** em loaders sem patch, o DA1 não sanitiza o endereço de carregamento/tamanho do DA2 e mantém o hash esperado gravável na memória, permitindo que o host altere a verificação.<sup>[[1]](#references)[[2]](#references)</sup>

## Fluxo do Carbonara (truque dos "dois BOOT_TO")

1. **Primeiro `BOOT_TO`:** Entra no fluxo de staging DA1→DA2 (o DA1 aloca, prepara a DRAM e expõe o buffer do hash esperado na RAM).
2. **Sobrescrita do slot do hash:** Envia um payload pequeno que varre a memória do DA1 em busca do hash esperado do DA2 armazenado e o sobrescreve com o SHA-256 do DA2 modificado pelo atacante. Isso explora o carregamento controlado pelo usuário para posicionar o payload onde o hash está localizado.
3. **Segundo `BOOT_TO` + digest:** Aciona outro `BOOT_TO` com os metadados do DA2 alterados e envia o digest bruto de 32 bytes correspondente ao DA2 modificado. O DA1 recalcula o SHA-256 sobre o DA2 recebido, compara-o com o hash esperado agora alterado e o salto é executado com sucesso para o código do atacante.

Como o endereço de carregamento/tamanho é controlado pelo atacante, a mesma primitiva pode escrever em qualquer lugar da memória (não apenas no buffer do hash), permitindo implants no início do boot, auxiliares de bypass do secure boot ou rootkits maliciosos.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `payload` replica o blob da paid-tool que aplica um patch no buffer de expected-hash dentro da DA1.
- `sha256(...).digest()` envia raw bytes (não hex), para que a DA1 compare com o buffer alterado.
- A DA2 pode ser qualquer image criada pelo atacante; escolher o load address/size permite o posicionamento arbitrário na memória, com a invalidação de cache gerenciada pela DA.<sup>[[3]](#references)</sup>

## Cenário de patches (loaders hardened)

- **Mitigation**: DAs atualizadas definem o endereço de carregamento da DA2 como `0x40000000` e ignoram o endereço fornecido pelo host, portanto as gravações não podem alcançar o slot de hash da DA1 (por volta de `0x200000`). O hash continua sendo calculado, mas deixa de ser gravável pelo atacante.
- **Detectando DAs com patch**: mtkclient/penumbra fazem scan da DA1 em busca de padrões que indiquem o address-hardening; quando encontrados, o Carbonara é ignorado. DAs antigas expõem slots de hash graváveis (comumente em offsets como `0x22dea4` na DA1 V5) e continuam vulneráveis.
- **V5 vs V6**: Alguns loaders V6 (XML) ainda aceitam endereços fornecidos pelo usuário; binários V6 mais recentes geralmente aplicam o endereço fixo e são imunes ao Carbonara, a menos que sofram downgrade.<sup>[[2]](#references)[[3]](#references)</sup>

## Nota pós-Carbonara (heapb8)

A MediaTek corrigiu o Carbonara; uma vulnerabilidade mais recente, **heapb8**, tem como alvo o handler de download de arquivos USB da DA2 em loaders V6 com patch, permitindo code execution mesmo quando `boot_to` está hardened. Ela abusa de um heap overflow durante transferências de arquivos em chunks para assumir o controle do fluxo de execução da DA2. O exploit é público no Penumbra/mtk-payloads e demonstra que as correções do Carbonara não fecham toda a attack surface da DA.<sup>[[4]](#references)</sup>

## Notas para triagem e hardening

- Dispositivos nos quais o endereço/tamanho da DA2 não são verificados e a DA1 mantém o expected hash gravável são vulneráveis. Se um Preloader/DA posterior aplicar limites de endereço ou mantiver o hash imutável, o Carbonara é mitigado.
- Ativar o DAA e garantir que a DA1/Preloader valide os parâmetros de BOOT_TO (limites + autenticidade da DA2) elimina a primitive. Corrigir apenas o hash patch sem limitar o load ainda deixa um risco de arbitrary write.

## Referências

- [1] [Carbonara: O exploit da MediaTek que ninguém serviu](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Documentação do exploit Carbonara](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Código-fonte do Carbonara no Penumbra](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: explorando Download Agents V6 com patch](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
