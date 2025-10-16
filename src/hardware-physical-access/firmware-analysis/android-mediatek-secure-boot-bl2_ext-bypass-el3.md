# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta um secure-boot break prático em várias plataformas MediaTek, abusando de uma lacuna de verificação quando a configuração do bootloader do dispositivo (seccfg) está "unlocked". A falha permite executar um bl2_ext patched no ARM EL3 para desabilitar a verificação de assinatura a jusante, colapsando a cadeia de confiança e permitindo o carregamento arbitrário de TEE/GZ/LK/Kernel não assinados.

> Caution: Early-boot patching pode inutilizar (brick) permanentemente os dispositivos se os offsets estiverem errados. Sempre mantenha dumps completos e um caminho de recovery confiável.

## Affected boot flow (MediaTek)

- Caminho normal: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Caminho vulnerável: Quando seccfg está definido como "unlocked", o Preloader pode pular a verificação do bl2_ext. O Preloader ainda salta para o bl2_ext em EL3, então um bl2_ext craftado pode carregar componentes não verificados em seguida.

Limite de confiança chave:
- bl2_ext executa em EL3 e é responsável por verificar TEE, GenieZone, LK/AEE e o kernel. Se o próprio bl2_ext não for autenticado, o resto da cadeia é trivialmente contornado.

## Root cause

Em dispositivos afetados, o Preloader não força a autenticação da partição bl2_ext quando seccfg indica um estado "unlocked". Isso permite flashar um bl2_ext controlado pelo atacante que roda em EL3.

Dentro do bl2_ext, a função de política de verificação pode ser patched para reportar incondicionalmente que a verificação não é necessária. Um patch conceitual mínimo é:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Com essa alteração, todas as imagens subsequentes (TEE, GZ, LK/AEE, Kernel) são aceitas sem verificações criptográficas quando carregadas pelo bl2_ext patchado executando em EL3.

## Como triar um alvo (logs do expdb)

Faça dump/inspecione os logs de boot (por exemplo, expdb) em torno do carregamento do bl2_ext. Se img_auth_required = 0 e o tempo de verificação do certificado for ~0 ms, a aplicação da verificação provavelmente está desativada e o dispositivo é explorável.

Exemplo de trecho de log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Observação: Alguns dispositivos, segundo relatos, pulam a verificação do bl2_ext mesmo com o bootloader bloqueado, o que agrava o impacto.

## Fluxo de exploração prático (Fenrir PoC)

Fenrir é um toolkit de exploit/patching de referência para essa classe de problema. Suporta Nothing Phone (2a) (Pacman) e é conhecido por funcionar (com suporte incompleto) no CMF Phone 1 (Tetris). Portar para outros modelos requer engenharia reversa do bl2_ext específico do dispositivo.

Processo de alto nível:
- Obtenha a imagem do bootloader do dispositivo para o seu codename alvo e coloque-a em bin/<device>.bin
- Construa uma imagem patchada que desative a política de verificação do bl2_ext
- Flasheie o payload resultante no dispositivo (fastboot é assumido pelo script auxiliar)

Comandos:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
Se fastboot não estiver disponível, você deve usar um método alternativo de flashing adequado para sua plataforma.

## Runtime payload capabilities (EL3)

Um payload bl2_ext com patch pode:
- Registrar comandos fastboot personalizados
- Controlar/substituir o modo de boot
- Chamar dinamicamente funções built‑in do bootloader em tempo de execução
- Falsificar “lock state” como locked enquanto na verdade está unlocked para passar verificações de integridade mais rigorosas (alguns ambientes podem ainda exigir ajustes em vbmeta/AVB)

Limitação: PoCs atuais observam que modificações de memória em tempo de execução podem causar faults devido a restrições do MMU; payloads geralmente evitam gravações de memória ao vivo até que isso seja resolvido.

## Porting tips

- Faça engenharia reversa do bl2_ext específico do dispositivo para localizar a lógica da política de verificação (ex.: sec_get_vfy_policy).
- Identifique o ponto de retorno da política ou o ramo de decisão e faça um patch para “no verification required” (return 0 / unconditional allow).
- Mantenha offsets totalmente específicos de dispositivo e firmware; não reutilize endereços entre variantes.
- Valide primeiro em uma unidade sacrificial. Prepare um plano de recuperação (ex.: EDL/BootROM loader/SoC-specific download mode) antes de você flashar.

## Security impact

- Execução de código em EL3 após o Preloader e colapso total da cadeia de confiança para o restante do caminho de boot.
- Capacidade de boot de TEE/GZ/LK/Kernel não assinados, contornando expectativas de secure/verified boot e permitindo comprometimento persistente.

## Detection and hardening ideas

- Assegure que o Preloader verifique o bl2_ext independentemente do estado de seccfg.
- Imponha resultados de autenticação e colete evidências de auditoria (timings > 0 ms, strict errors on mismatch).
- O spoofing de lock-state deve ser tornado ineficaz para attestation (vincular lock state às decisões de verificação AVB/vbmeta e ao estado respaldado por fusíveis).

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
