# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta uma quebra prática do secure-boot em múltiplas plataformas MediaTek ao abusar de uma lacuna de verificação quando a configuração do bootloader do dispositivo (seccfg) está "unlocked". A falha permite executar um bl2_ext patchado em ARM EL3 para desabilitar a verificação de assinaturas a jusante, colapsando a cadeia de confiança e permitindo o carregamento arbitrário de TEE/GZ/LK/Kernel não assinados.

> Cuidado: Patching no early-boot pode inutilizar permanentemente dispositivos se os offsets estiverem errados. Sempre mantenha dumps completos e um caminho de recuperação confiável.

## Affected boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Key trust boundary:
- bl2_ext executes at EL3 and is responsible for verifying TEE, GenieZone, LK/AEE and the kernel. If bl2_ext itself is not authenticated, the rest of the chain is trivially bypassed.

## Root cause

Em dispositivos afetados, o Preloader não aplica a autenticação da partição bl2_ext quando seccfg indica um estado "unlocked". Isso permite gravar um bl2_ext controlado pelo atacante que roda em EL3.

Dentro do bl2_ext, a função de política de verificação pode ser patchada para reportar incondicionalmente que a verificação não é necessária. Um patch conceitual mínimo é:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Com essa mudança, todas as imagens subsequentes (TEE, GZ, LK/AEE, Kernel) são aceitas sem verificações criptográficas quando carregadas pelo bl2_ext modificado em EL3.

## Como analisar um alvo (expdb logs)

Faça dump/inspeção dos boot logs (por exemplo, expdb) em torno do carregamento do bl2_ext. Se img_auth_required = 0 e o tempo de verificação do certificado for ~0 ms, a aplicação da verificação provavelmente está desativada e o dispositivo é explorável.

Exemplo de trecho do log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Nota: Alguns dispositivos, segundo relatos, pulam a verificação do bl2_ext mesmo com um locked bootloader, o que agrava o impacto.

## Fluxo prático de exploração (Fenrir PoC)

Fenrir é um toolkit de referência de exploit/patching para esta classe de problema. Ele suporta Nothing Phone (2a) (Pacman) e é conhecido por funcionar (com suporte incompleto) no CMF Phone 1 (Tetris). Portar para outros modelos requer engenharia reversa do bl2_ext específico do dispositivo.

High-level process:
- Obtenha a imagem do bootloader do dispositivo para o seu codename alvo e coloque-a como bin/<device>.bin
- Construa uma imagem patchada que desabilite a política de verificação do bl2_ext
- Flash o payload resultante para o dispositivo (fastboot assumido pelo script auxiliar)

Comandos:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

## Runtime payload capabilities (EL3)

Um payload bl2_ext patchado pode:
- Registrar comandos fastboot personalizados
- Controlar/substituir o modo de boot
- Chamar dinamicamente funções built‑in do bootloader em runtime
- Forjar “lock state” como locked enquanto na verdade está unlocked para passar verificações de integridade mais rigorosas (alguns ambientes podem ainda requerer ajustes de vbmeta/AVB)

Limitation: PoCs atuais notam que modificações de memória em runtime podem falhar devido a restrições do MMU; payloads geralmente evitam escritas de memória ao vivo até isso ser resolvido.

## Porting tips

- Reverse engineer o bl2_ext específico do dispositivo para localizar a lógica de verification policy (e.g., sec_get_vfy_policy).
- Identify the policy return site or decision branch and patch it to “no verification required” (return 0 / unconditional allow).
- Mantenha offsets totalmente específicos ao dispositivo e ao firmware; não reutilize endereços entre variantes.
- Valide primeiro em uma unidade sacrificial. Prepare um plano de recuperação (e.g., EDL/BootROM loader/SoC-specific download mode) antes de flashar.

## Security impact

- Execução de código em EL3 após o Preloader e colapso completo da cadeia de confiança para o restante do caminho de boot.
- Capacidade de bootar TEE/GZ/LK/Kernel não assinados, contornando as expectativas de secure/verified boot e possibilitando comprometimento persistente.

## Detection and hardening ideas

- Assegure que o Preloader verifique o bl2_ext independentemente do estado do seccfg.
- Impor os resultados de autenticação e coletar evidências de auditoria (timings > 0 ms, strict errors on mismatch).
- Lock-state spoofing deve ser tornado ineficaz para attestation (vincule o lock state às decisões de verificação AVB/vbmeta e ao estado fuse-backed).

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
