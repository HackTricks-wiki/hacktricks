# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Resumo

"Carbonara" abusa do caminho de download XFlash da MediaTek para executar um Download Agent stage 2 (DA2) modificado apesar das verificações de integridade do DA1. DA1 armazena o SHA-256 esperado do DA2 em RAM e compara antes de saltar. Em muitos loaders, o host controla completamente o endereço/size de load do DA2, proporcionando uma escrita de memória não validada que pode sobrescrever esse hash em memória e redirecionar a execução para payloads arbitrários (contexto pré-OS com invalidação de cache tratada pelo DA).

## Fronteira de confiança em XFlash (DA1 → DA2)

- **DA1** é assinado/carregado pelo BootROM/Preloader. Quando Download Agent Authorization (DAA) está habilitado, apenas DA1 assinado deve ser executado.
- **DA2** é enviado via USB. DA1 recebe **size**, **load address**, e **SHA-256** e calcula o hash do DA2 recebido, comparando-o com um **expected hash embedded in DA1** (copiado para RAM).
- **Weakness:** Em loaders não corrigidos, DA1 não saneia o DA2 load address/size e mantém o expected hash gravável em memória, permitindo que o host manipule a verificação.

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Entra no fluxo de preparação DA1→DA2 (DA1 aloca, prepara a DRAM, e expõe o expected-hash buffer na RAM).
2. **Hash-slot overwrite:** Envie um pequeno payload que escaneia a memória de DA1 em busca do hash esperado do DA2 e o sobrescreve com o SHA-256 do DA2 modificado pelo atacante. Isso aproveita o load controlado pelo usuário para posicionar o payload onde o hash reside.
3. **Second `BOOT_TO` + digest:** Dispare outro `BOOT_TO` com os metadados do DA2 patchados e envie o digest bruto de 32 bytes correspondente ao DA2 modificado. DA1 recalcula o SHA-256 sobre o DA2 recebido, compara com o expected hash agora patchado, e o salto para o código do atacante ocorre com sucesso.

Porque o load address/size são controlados pelo atacante, o mesmo primitivo pode escrever em qualquer lugar da memória (não apenas no buffer do hash), possibilitando early-boot implants, secure-boot bypass helpers, ou rootkits maliciosos.

## Padrão mínimo de PoC (mtkclient-style)
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
- `payload` replica o blob da ferramenta paga que corrige o buffer expected-hash dentro do DA1.
- `sha256(...).digest()` envia bytes brutos (não hex) para que o DA1 compare contra o buffer corrigido.
- DA2 pode ser qualquer imagem construída pelo atacante; escolher o endereço/tamanho de load permite posicionamento arbitrário na memória com a invalidação de cache tratada pelo DA.

## Patch landscape (hardened loaders)

- **Mitigation**: Updated DAs hardcode the DA2 load address to `0x40000000` and ignore the address the host supplies, so writes cannot reach the DA1 hash slot (~0x200000 range). The hash remains computed but no longer attacker-writable.
- **Detecting patched DAs**: mtkclient/penumbra scan DA1 for patterns indicating the address-hardening; if found, Carbonara is skipped. Old DAs expose writable hash slots (commonly around offsets like `0x22dea4` in V5 DA1) and remain exploitable.
- **V5 vs V6**: Some V6 (XML) loaders still accept user-supplied addresses; newer V6 binaries usually enforce the fixed address and are immune to Carbonara unless downgraded.

## Post-Carbonara (heapb8) note

MediaTek patched Carbonara; a newer vulnerability, **heapb8**, targets the DA2 USB file download handler on patched V6 loaders, giving code execution even when `boot_to` is hardened. It abuses a heap overflow during chunked file transfers to seize DA2 control flow. The exploit is public in Penumbra/mtk-payloads and demonstrates that Carbonara fixes do not close all DA attack surface.

## Notes for triage and hardening

- Devices where DA2 address/size are unchecked and DA1 keeps the expected hash writable are vulnerable. If a later Preloader/DA enforces address bounds or keeps the hash immutable, Carbonara is mitigated.
- Enabling DAA and ensuring DA1/Preloader validate BOOT_TO parameters (bounds + authenticity of DA2) closes the primitive. Closing only the hash patch without bounding the load still leaves arbitrary write risk.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
