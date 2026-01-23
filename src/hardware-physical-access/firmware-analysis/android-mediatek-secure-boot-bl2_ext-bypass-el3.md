# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta uma quebra prática do secure-boot em múltiplas plataformas MediaTek, abusando de uma lacuna de verificação quando a configuração do bootloader do dispositivo (seccfg) está "unlocked". A falha permite executar um bl2_ext modificado em ARM EL3 para desabilitar a verificação de assinaturas a jusante, colapsando a cadeia de confiança e permitindo o carregamento arbitrário de TEE/GZ/LK/Kernel não assinados.

> Cuidado: Modificações no early-boot podem inutilizar permanentemente dispositivos se os offsets estiverem errados. Sempre mantenha full dumps e um caminho de recuperação confiável.

## Affected boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Fronteira principal de confiança:
- bl2_ext é executado em EL3 e é responsável por verificar TEE, GenieZone, LK/AEE e o kernel. Se o próprio bl2_ext não for autenticado, o resto da cadeia é trivialmente contornado.

## Root cause

Em dispositivos afetados, o Preloader não aplica a autenticação da partição bl2_ext quando seccfg indica um estado "unlocked". Isso permite flashing de um bl2_ext controlado pelo atacante que roda em EL3.

Dentro do bl2_ext, a função de política de verificação pode ser modificada para retornar incondicionalmente que a verificação não é necessária. Um patch conceitual mínimo é:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Com essa alteração, todas as imagens subsequentes (TEE, GZ, LK/AEE, Kernel) são aceitas sem verificações criptográficas quando carregadas pelo patched bl2_ext em execução no EL3.

## Como realizar a triagem de um alvo (expdb logs)

Dump/inspect boot logs (e.g., expdb) em torno do carregamento do bl2_ext. Se img_auth_required = 0 e certificate verification time is ~0 ms, a verificação provavelmente está desativada e o dispositivo é vulnerável.

Exemplo de trecho do log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Nota: Alguns dispositivos relataram pular a verificação do bl2_ext mesmo com o bootloader bloqueado, o que agrava o impacto.

Dispositivos que vêm com o lk2 secondary bootloader foram observados com a mesma lacuna de lógica, então capture expdb logs para as partições bl2_ext e lk2 para confirmar se algum dos caminhos aplica assinaturas antes de tentar o porting.

Se um Preloader pós-OTA agora registra img_auth_required = 1 para bl2_ext mesmo com seccfg desbloqueado, o fabricante provavelmente fechou a lacuna — veja as notas de persistência OTA abaixo.

## Fluxo prático de exploração (Fenrir PoC)

Fenrir é um reference exploit/patching toolkit para esta classe de problema. Ele suporta Nothing Phone (2a) (Pacman) e é conhecido por funcionar (com suporte incompleto) no CMF Phone 1 (Tetris). O porting para outros modelos requer reverse engineering do bl2_ext específico do dispositivo.

Processo de alto nível:
- Obtenha a imagem do bootloader do dispositivo para seu codename alvo e coloque-a como `bin/<device>.bin`
- Construa uma imagem patchada que desabilite a política de verificação do bl2_ext
- Grave o payload resultante no dispositivo (fastboot assumido pelo script auxiliar)

Comandos:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

### OTA-patched firmware: mantendo o bypass ativo (NothingOS 4, late 2025)

Nothing patched the Preloader in the November 2025 NothingOS 4 stable OTA (build BP2A.250605.031.A3) to enforce bl2_ext verification even when seccfg is unlocked. Fenrir `pacman-v2.0` works again by mixing the vulnerable Preloader from the NOS 4 beta with the stable LK payload:
```bash
# on Nothing Phone (2a), unlocked bootloader, in bootloader (not fastbootd)
fastboot flash preloader_a preloader_raw.img   # beta Preloader bundled with fenrir release
fastboot flash lk pacman-fenrir.bin            # patched LK containing stage hooks
fastboot reboot                                # factory reset may be needed
```
Importante:
- Flash o Preloader fornecido **somente** no dispositivo/slot correspondente; um Preloader incorreto resulta em um hard brick instantâneo.
- Verifique expdb após o flash; img_auth_required deve voltar a 0 para bl2_ext, confirmando que o Preloader vulnerável está sendo executado antes do seu LK patchado.
- Se futuras OTAs patcharem tanto o Preloader quanto o LK, mantenha uma cópia local de um Preloader vulnerável para reintroduzir a brecha.

### Build automation & payload debugging

- `build.sh` agora baixa automaticamente e exporta o Arm GNU Toolchain 14.2 (aarch64-none-elf) na primeira vez que você o executa, então você não precisa ficar trocando cross-compilers manualmente.
- Exporte `DEBUG=1` antes de invocar `build.sh` para compilar payloads com verbose serial prints, o que ajuda muito quando você está blind-patching caminhos de código EL3.
- Builds bem-sucedidos geram tanto `lk.patched` quanto `<device>-fenrir.bin`; este último já tem o payload injetado e é o que você deve flash/boot-test.

## Runtime payload capabilities (EL3)

Um payload bl2_ext patchado pode:
- Register custom fastboot commands
- Control/override boot mode
- Dynamically call built‑in bootloader functions at runtime
- Spoof “lock state” as locked while actually unlocked to pass stronger integrity checks (some environments may still require vbmeta/AVB adjustments)

Limitação: PoCs atuais notam que a modificação de memória em runtime pode causar fault devido a restrições do MMU; payloads geralmente evitam escritas de memória ao vivo até que isso seja resolvido.

## Payload staging patterns (EL3)

Fenrir divide sua instrumentação em três estágios em tempo de compilação: stage1 roda antes de `platform_init()`, stage2 roda antes do LK sinalizar entrada em fastboot, e stage3 é executado imediatamente antes do LK carregar o Linux. Cada header de dispositivo sob `payload/devices/` fornece os endereços para esses hooks mais os símbolos helper do fastboot, então mantenha esses offsets sincronizados com seu build alvo.

Stage2 é um local conveniente para registrar verbos arbitrários `fastboot oem`:
```c
void cmd_r0rt1z2(const char *arg, void *data, unsigned int sz) {
video_printf("r0rt1z2 was here...\n");
fastboot_info("pwned by r0rt1z2");
fastboot_okay("");
}

__attribute__((section(".text.main"))) void main(void) {
fastboot_register("oem r0rt1z2", cmd_r0rt1z2, true, false);
notify_enter_fastboot();
}
```
Stage3 demonstra como inverter temporariamente atributos de page-table para patchar strings imutáveis, como o aviso “Orange State” do Android, sem precisar de acesso downstream ao kernel:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Porque stage1 é executado antes do platform bring-up, é o local correto para chamar power/reset primitives do OEM ou para inserir registro adicional de integridade antes que a cadeia de verified boot seja desmontada.

## Porting tips

- Reverse engineer the device-specific bl2_ext to locate verification policy logic (e.g., sec_get_vfy_policy).
- Identifique o site de retorno da política ou o ramo de decisão e faça o patch para “no verification required” (return 0 / unconditional allow).
- Mantenha offsets totalmente específicos do dispositivo e do firmware; não reutilize endereços entre variantes.
- Valide primeiro em uma unidade sacrificial. Prepare um plano de recuperação (por exemplo, EDL/BootROM loader/SoC-specific download mode) antes de fazer o flash.
- Dispositivos usando o lk2 secondary bootloader ou reportando “img_auth_required = 0” para bl2_ext mesmo enquanto bloqueados devem ser tratados como cópias vulneráveis desta classe de bug; Vivo X80 Pro já foi observado pulando a verificação apesar de um estado de bloqueio reportado.
- Quando uma OTA começar a impor assinaturas de bl2_ext (img_auth_required = 1) no estado desbloqueado, verifique se um Preloader mais antigo (frequentemente disponível em beta OTAs) pode ser gravado para reabrir a brecha, então reexecute fenrir com offsets atualizados para o LK mais recente.

## Security impact

- Execução de código EL3 após o Preloader e colapso completo da cadeia de confiança para o restante do caminho de inicialização.
- Capacidade de bootar TEE/GZ/LK/Kernel sem assinatura, contornando as expectativas de secure/verified boot e permitindo comprometimento persistente.

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: foi reportado que o Vivo X80 Pro não verificou bl2_ext mesmo quando bloqueado
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) re-enabled bl2_ext verification; fenrir `pacman-v2.0` restores the bypass by flashing the beta Preloader plus patched LK as shown above
- A cobertura da indústria destaca fornecedores adicionais baseados em lk2 que enviam a mesma falha lógica, então espere maior sobreposição entre os lançamentos MTK de 2024–2025.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)

{{#include ../../banners/hacktricks-training.md}}
