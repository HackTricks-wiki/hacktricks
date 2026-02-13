# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Resumo

"Carbonara" abusa do caminho de download XFlash da MediaTek para executar um Download Agent stage 2 (DA2) modificado apesar das verificações de integridade do DA1. O DA1 armazena o SHA-256 esperado do DA2 na RAM e o compara antes de desviar a execução. Em muitos loaders, o host controla totalmente o endereço/size de carregamento do DA2, permitindo uma escrita de memória não verificada que pode sobrescrever esse hash em memória e redirecionar a execução para payloads arbitrários (contexto pré-OS com invalidação de cache tratada pelo DA).

## Fronteira de confiança em XFlash (DA1 → DA2)

- **DA1** é assinado/carregado pelo BootROM/Preloader. Quando Download Agent Authorization (DAA) está habilitado, apenas DA1 assinado deve ser executado.
- **DA2** é enviado via USB. O DA1 recebe **size**, **load address**, e **SHA-256** e calcula o hash do DA2 recebido, comparando-o com um **hash esperado embutido no DA1** (copiado para a RAM).
- **Fragilidade:** Em loaders não corrigidos, o DA1 não sanitiza o endereço/size de carregamento do DA2 e mantém o hash esperado gravável em memória, permitindo que o host manipule a verificação.

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Entra no fluxo de preparação DA1→DA2 (DA1 aloca, prepara o DRAM e expõe o buffer do hash esperado na RAM).
2. **Hash-slot overwrite:** Envie um pequeno payload que procura na memória do DA1 o hash esperado do DA2 armazenado e o sobrescreve com o SHA-256 do DA2 modificado pelo atacante. Isso aproveita o carregamento controlado pelo usuário para posicionar o payload onde o hash reside.
3. **Second `BOOT_TO` + digest:** Dispare outro `BOOT_TO` com os metadados do DA2 patchados e envie o digest bruto de 32 bytes correspondente ao DA2 modificado. O DA1 recalcula o SHA-256 sobre o DA2 recebido, compara com o hash esperado agora patchado, e o salto para o código do atacante ocorre com sucesso.

Como o endereço/size de carregamento são controlados pelo atacante, o mesmo primitivo pode escrever em qualquer lugar na memória (não apenas no buffer de hash), permitindo implantes no early-boot, auxiliares de bypass de secure-boot ou rootkits maliciosos.

## Minimal PoC pattern (mtkclient-style)
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
- `payload` replica o blob da ferramenta paga que aplica patch no buffer expected-hash dentro do DA1.
- `sha256(...).digest()` envia bytes brutos (não hex) para que o DA1 compare contra o buffer patchado.
- DA2 pode ser qualquer imagem criada pelo atacante; escolher o endereço/tamanho de carregamento permite posicionamento arbitrário de memória com invalidação de cache tratada pelo DA.

## Notas para triagem e endurecimento

- Dispositivos onde o endereço/tamanho do DA2 não são verificados e o DA1 mantém o expected hash gravável são vulneráveis. Se um Preloader/DA posterior impor limites de endereço ou mantiver o hash imutável, Carbonara é mitigado.
- Habilitar DAA e garantir que DA1/Preloader validem os parâmetros BOOT_TO (limites + autenticidade do DA2) fecha a primitiva. Fechar apenas o patch do hash sem limitar o carregamento ainda deixa risco de escrita arbitrária.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)

{{#include ../../banners/hacktricks-training.md}}
