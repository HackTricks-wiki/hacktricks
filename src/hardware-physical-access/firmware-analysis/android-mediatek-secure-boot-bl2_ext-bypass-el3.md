# Bypass do Secure-Boot do MediaTek bl2_ext (Execução de Código EL3)

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta uma quebra prática do secure-boot em múltiplas plataformas MediaTek ao abusar de uma lacuna de verificação quando a configuração do bootloader do dispositivo (seccfg) está "unlocked". A falha permite executar um bl2_ext modificado em ARM EL3 para desativar a verificação de assinaturas a jusante, colapsando a cadeia de confiança e possibilitando o carregamento arbitrário de TEE/GZ/LK/Kernel não assinados.

> Atenção: Patches aplicados no early-boot podem brickar permanentemente os dispositivos se os offsets estiverem errados. Sempre mantenha dumps completos e um caminho de recuperação confiável.

## Fluxo de boot afetado (MediaTek)

- Caminho normal: BootROM → Preloader → bl2_ext (EL3, verificado) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Caminho vulnerável: Quando seccfg está definido como "unlocked", o Preloader pode pular a verificação de bl2_ext. O Preloader ainda salta para bl2_ext em EL3, então um bl2_ext forjado pode carregar componentes não verificados em seguida.

Limite de confiança chave:
- bl2_ext é executado em EL3 e é responsável por verificar TEE, GenieZone, LK/AEE e o kernel. Se o próprio bl2_ext não for autenticado, o resto da cadeia é trivialmente contornado.

## Causa raiz

Em dispositivos afetados, o Preloader não aplica a autenticação da partição bl2_ext quando seccfg indica um estado "unlocked". Isso permite fazer flash de um bl2_ext controlado pelo atacante que roda em EL3.

Dentro do bl2_ext, a função de política de verificação pode ser modificada para relatar incondicionalmente que a verificação não é necessária. Um patch conceitual mínimo é:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Com essa alteração, todas as imagens subsequentes (TEE, GZ, LK/AEE, Kernel) são aceitas sem verificações criptográficas quando carregadas pelo bl2_ext modificado executando em EL3.

## Como fazer a triagem de um alvo (logs expdb)

Faça dump/inspecione os logs de boot (por exemplo, expdb) próximos ao carregamento do bl2_ext. Se img_auth_required = 0 e o tempo de verificação do certificado for ~0 ms, provavelmente o enforcement está desligado e o dispositivo é explorável.

Exemplo de trecho do log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Nota: Alguns dispositivos, segundo relatos, ignoram a verificação de bl2_ext mesmo com um locked bootloader, o que agrava o impacto.

Dispositivos que trazem o secondary bootloader lk2 foram observados com a mesma falha de lógica, então capture expdb logs das partições bl2_ext e lk2 para confirmar se algum dos caminhos valida assinaturas antes de tentar portar.

## Fluxo prático de exploração (Fenrir PoC)

Fenrir é um toolkit de exploit/patching de referência para esta classe de problema. Ele suporta Nothing Phone (2a) (Pacman) e é conhecido por funcionar (com suporte incompleto) no CMF Phone 1 (Tetris). Portar para outros modelos requer engenharia reversa do bl2_ext específico do dispositivo.

Processo de alto nível:
- Obtenha a imagem do bootloader do dispositivo para o seu codename alvo e coloque-a em `bin/<device>.bin`
- Construa uma imagem patchada que desative a política de verificação do bl2_ext
- Flash o payload resultante no dispositivo (fastboot assumido pelo script auxiliar)

Comandos:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
Se o fastboot não estiver disponível, você deve usar um método alternativo de flashing adequado para sua plataforma.

### Automação de build & depuração de payloads

- `build.sh` agora faz download automático e exporta o Arm GNU Toolchain 14.2 (aarch64-none-elf) na primeira vez que você o executar, então você não precisa gerenciar cross-compilers manualmente.
- Exporte `DEBUG=1` antes de invocar `build.sh` para compilar os payloads com prints seriais verbosos, o que ajuda bastante quando você está fazendo blind-patching em caminhos de código EL3.
- Builds bem-sucedidos geram tanto `lk.patched` quanto `<device>-fenrir.bin`; este último já tem o payload injetado e é o que você deve flashar/testar de boot.

## Capacidades do payload em tempo de execução (EL3)

Um payload bl2_ext patchado pode:
- Registrar comandos fastboot personalizados
- Controlar/substituir o boot mode
- Chamar dinamicamente funções built‑in do bootloader em tempo de execução
- Spoof “lock state” como locked enquanto na verdade está unlocked para passar verificações de integridade mais rigorosas (alguns ambientes ainda podem requerer ajustes em vbmeta/AVB)

Limitação: PoCs atuais observam que a modificação de memória em runtime pode provocar faults devido a restrições do MMU; payloads geralmente evitam escritas de memória ao vivo até que isso seja resolvido.

## Padrões de estágio do payload (EL3)

Fenrir divide sua instrumentação em três estágios em tempo de compilação: stage1 roda antes de `platform_init()`, stage2 roda antes do LK sinalizar entrada no fastboot, e stage3 executa imediatamente antes do LK carregar o Linux. Cada header de dispositivo em `payload/devices/` fornece os endereços desses hooks além dos símbolos helper do fastboot, então mantenha esses offsets sincronizados com sua build alvo.

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
Stage3 demonstra como temporariamente flip page-table attributes para patch immutable strings, como o aviso "Orange State" do Android, sem precisar de downstream kernel access:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Porque stage1 é executado antes do bring-up da plataforma, é o local adequado para chamar primitivas OEM de power/reset ou inserir logging adicional de integridade antes que a verified boot chain seja desmontada.

## Dicas de portabilidade

- Faça engenharia reversa do bl2_ext específico do dispositivo para localizar a lógica de política de verificação (por exemplo, sec_get_vfy_policy).
- Identifique o site de retorno da política ou o ramo de decisão e parcheie para “no verification required” (return 0 / unconditional allow).
- Mantenha os offsets totalmente específicos do dispositivo e do firmware; não reutilize endereços entre variantes.
- Valide primeiro em uma unidade sacrificial. Prepare um plano de recuperação (por exemplo, EDL/BootROM loader/SoC-specific download mode) antes de fazer flash.
- Dispositivos que usam o secondary bootloader lk2 ou que reportam “img_auth_required = 0” para bl2_ext mesmo enquanto bloqueados devem ser tratados como cópias vulneráveis desta classe de bug; o Vivo X80 Pro já foi observado pulando a verificação apesar de um estado reportado como locked.
- Compare os logs expdb tanto de estados locked quanto unlocked — se o timing do certificado saltar de 0 ms para um valor não zero assim que você relock, provavelmente você parcheou o ponto de decisão correto, mas ainda precisa endurecer a falsificação do estado de lock para esconder a modificação.

## Impacto na segurança

- Execução de código em EL3 após o Preloader e colapso completo da cadeia de confiança para o restante do caminho de boot.
- Capacidade de boot de TEE/GZ/LK/Kernel não assinados, ignorando as expectativas de secure/verified boot e permitindo compromisso persistente.

## Notas do dispositivo

- Confirmado suportado: Nothing Phone (2a) (Pacman)
- Conhecido funcionando (suporte incompleto): CMF Phone 1 (Tetris)
- Observado: Vivo X80 Pro teria deixado de verificar bl2_ext mesmo quando locked
- A cobertura da indústria destaca fornecedores adicionais baseados em lk2 que enviam a mesma falha lógica, então espere maior sobreposição ao longo dos lançamentos MTK de 2024–2025.

## Referências

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)

{{#include ../../banners/hacktricks-training.md}}
