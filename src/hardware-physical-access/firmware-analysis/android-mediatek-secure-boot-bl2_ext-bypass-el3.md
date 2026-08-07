# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta uma quebra prática do secure-boot em várias plataformas MediaTek, explorando uma falha de verificação quando a configuração do bootloader do dispositivo (seccfg) está "unlocked". A falha permite executar um bl2_ext modificado no ARM EL3 para desabilitar a verificação de assinaturas subsequente, eliminando a cadeia de confiança e permitindo o carregamento arbitrário de TEE/GZ/LK/Kernel não assinados.<sup>[[1]](#references)</sup>

> Cuidado: patches no início do processo de boot podem brickar permanentemente os dispositivos se os offsets estiverem incorretos. Mantenha sempre dumps completos e um caminho de recuperação confiável.

## Fluxo de boot afetado (MediaTek)

- Caminho normal: BootROM → Preloader → bl2_ext (EL3, verificado) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Caminho vulnerável: Quando seccfg está definido como unlocked, o Preloader pode ignorar a verificação do bl2_ext. O Preloader ainda salta para o bl2_ext no EL3, portanto um bl2_ext criado para esse fim pode carregar componentes não verificados posteriormente.

Principal limite de confiança:
- O bl2_ext é executado no EL3 e é responsável por verificar TEE, GenieZone, LK/AEE e o kernel. Se o próprio bl2_ext não for autenticado, o restante da cadeia pode ser trivialmente bypassado.<sup>[[1]](#references)</sup>

## Causa raiz

Nos dispositivos afetados, o Preloader não impõe a autenticação da partição bl2_ext quando o seccfg indica um estado "unlocked". Isso permite gravar um bl2_ext controlado pelo atacante que é executado no EL3.

Dentro do bl2_ext, a função de política de verificação pode ser modificada para informar incondicionalmente que a verificação não é necessária (ou que sempre é bem-sucedida), forçando a cadeia de boot a aceitar imagens TEE/GZ/LK/Kernel não assinadas. Como esse patch é executado no EL3, ele é eficaz mesmo que os componentes posteriores implementem suas próprias verificações.<sup>[[1]](#references)</sup>

## Cadeia de exploit prática

1. Obtenha as partições do bootloader (Preloader, bl2_ext, LK/AEE etc.) por meio de pacotes OTA/firmware, leitura via EDL/DA ou dumping de hardware.
2. Identifique a rotina de verificação do bl2_ext e aplique um patch para sempre ignorar/aceitar a verificação.
3. Grave o bl2_ext modificado usando fastboot, DA ou canais de manutenção semelhantes que ainda estejam permitidos em dispositivos unlocked.
4. Reinicie; o Preloader salta para o bl2_ext modificado no EL3, que então carrega imagens downstream não assinadas (TEE/GZ/LK/Kernel modificadas) e desabilita a aplicação de assinaturas.<sup>[[1]](#references)</sup>

Se o dispositivo estiver configurado como locked (seccfg locked), espera-se que o Preloader verifique o bl2_ext. Nessa configuração, este ataque falhará, a menos que outra vulnerabilidade permita carregar um bl2_ext não assinado.

## Triage (logs de boot do expdb)

- Extraia os logs de boot/expdb próximos ao carregamento do bl2_ext. Se `img_auth_required = 0` e o tempo de verificação do certificado for de aproximadamente 0 ms, é provável que a verificação tenha sido ignorada.<sup>[[1]](#references)</sup>

Exemplo de trecho de log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Alguns dispositivos ignoram a verificação de bl2_ext mesmo quando bloqueados; os caminhos do lk2 secondary bootloader apresentaram a mesma falha. Se um Preloader pós-OTA registrar `img_auth_required = 1` para bl2_ext enquanto desbloqueado, a aplicação da verificação provavelmente foi restaurada.<sup>[[1]](#references)[[2]](#references)</sup>

## Locais da lógica de verificação

- A verificação relevante normalmente está dentro da imagem bl2_ext, em funções nomeadas de forma semelhante a `verify_img` ou `sec_img_auth`.
- A versão patched força a função a retornar sucesso ou ignora completamente a chamada de verificação.<sup>[[1]](#references)</sup>

Abordagem de patch de exemplo (conceitual):
- Localize a função que chama `sec_img_auth` nas imagens TEE, GZ, LK e kernel.
- Substitua o corpo por um stub que retorne sucesso imediatamente ou sobrescreva o conditional branch que trata a falha de verificação.

Certifique-se de que o patch preserve a configuração da stack/frame e retorne os códigos de status esperados pelos callers.<sup>[[1]](#references)</sup>

## Fluxo de trabalho do Fenrir PoC (Nothing/CMF)

Fenrir é um toolkit de patching de referência para este problema (Nothing Phone (2a) totalmente suportado; CMF Phone 1 parcialmente).<sup>[[1]](#references)</sup> Em alto nível:
- Coloque a imagem do bootloader do dispositivo como `bin/<device>.bin`.
- Compile uma imagem patched que desative a política de verificação do bl2_ext.
- Faça o flash do payload resultante (um fastboot helper é fornecido).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Use outro canal de flashing se fastboot estiver indisponível.

## Notas sobre o patching de EL3

- bl2_ext é executado no ARM EL3. Crashes nesse estágio podem inutilizar um dispositivo até que ele seja reflashed via EDL/DA ou test points.
- Use logging/UART específico da placa para validar o caminho de execução e diagnosticar crashes.
- Mantenha backups de todas as partições que serão modificadas e faça testes primeiro em hardware descartável.<sup>[[1]](#references)</sup>

## Implicações

- Execução de código em EL3 após o Preloader e colapso completo da chain-of-trust no restante do caminho de boot.
- Capacidade de inicializar TEE/GZ/LK/Kernel não assinados, ignorando as expectativas de secure/verified boot e permitindo comprometimento persistente.<sup>[[1]](#references)</sup>

## Notas sobre dispositivos

- Suporte confirmado: Nothing Phone (2a) (Pacman)
- Funcionando conforme relatos (suporte incompleto): CMF Phone 1 (Tetris)
- Observado: aparentemente, o Vivo X80 Pro não verificava bl2_ext mesmo quando bloqueado<sup>[[1]](#references)</sup>
- NothingOS 4 estável (BP2A.250605.031.A3, Nov 2025) reativou a verificação de bl2_ext; fenrir `pacman-v2.0` restaura o bypass misturando o Preloader beta com um LK patchado<sup>[[3]](#references)</sup>
- A cobertura do setor destaca fornecedores adicionais baseados em lk2 que distribuem a mesma falha lógica; portanto, espere mais sobreposição entre os lançamentos MTK de 2024–2025.<sup>[[2]](#references)[[4]](#references)</sup>

## Leitura de DA do MTK e manipulação de seccfg com Penumbra

Penumbra é um crate/CLI/TUI em Rust que automatiza a interação com o preloader/bootrom do MTK via USB para operações no modo DA. Com acesso físico a um aparelho vulnerável (com extensões de DA permitidas), ele pode descobrir a porta USB do MTK, carregar um blob de Download Agent (DA) e emitir comandos privilegiados, como alterar o lock do seccfg e fazer readback de partições.<sup>[[5]](#references)</sup>

- **Configuração de ambiente/driver**: No Linux, instale `libudev`, adicione o usuário ao grupo `dialout` e crie regras udev ou execute com `sudo` se o device node não estiver acessível. O suporte ao Windows não é confiável; às vezes só funciona após substituir o driver MTK por WinUSB usando o Zadig (conforme as orientações do projeto).
- **Workflow**: Leia um payload DA (por exemplo, `std::fs::read("../DA_penangf.bin")`), aguarde a porta MTK com `find_mtk_port()` e crie uma sessão usando `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Depois que `init()` concluir o handshake e coletar as informações do dispositivo, verifique as proteções por meio dos bitfields de `dev_info.target_config()` (bit 0 definido → SBC habilitado). Entre no modo DA e tente `set_seccfg_lock_state(LockFlag::Unlock)` — isso só terá sucesso se o dispositivo aceitar extensões. As partições podem ser despejadas com `read_partition("lk_a", &mut progress_cb, &mut writer)` para análise offline ou patching.
- **Impacto de segurança**: O desbloqueio bem-sucedido do seccfg reabre caminhos de flashing para boot images não assinadas, permitindo comprometimentos persistentes, como o patching de bl2_ext EL3 descrito acima. O readback de partições fornece artefatos de firmware para reverse engineering e criação de images modificadas.

<details>
<summary>Sessão Rust DA + desbloqueio de seccfg + dump de partição (Penumbra)</summary>
```rust
use tokio::fs::File;
use anyhow::Result;
use penumbra::{DeviceBuilder, LockFlag, find_mtk_port};
use tokio::io::{AsyncWriteExt, BufWriter};

#[tokio::main]
async fn main() -> Result<()> {
let da = std::fs::read("../DA_penangf.bin")?;
let mtk_port = loop {
if let Some(port) = find_mtk_port().await {
break port;
}
};

let mut dev = DeviceBuilder::default()
.with_mtk_port(mtk_port)
.with_da_data(da)
.build()?;

dev.init().await?;
let cfg = dev.dev_info.target_config().await;
println!("SBC: {}", (cfg & 0x1) != 0);

dev.set_seccfg_lock_state(LockFlag::Unlock).await?;

let mut progress = |_read: usize, _total: usize| {};
let mut writer = BufWriter::new(File::create("lk_a.bin")?);
dev.read_partition("lk_a", &mut progress, &mut writer).await?;
writer.flush().await?;
Ok(())
}
```
</details>

## Referências

- [1] [Fenrir – bypass de secure boot do MediaTek bl2_ext (PoC)](https://github.com/R0rt1z2/fenrir)
- [2] [Cyber Security News – PoC de exploit lançado para vulnerabilidade de execução de código no Nothing Phone](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [3] [Lançamento do Fenrir pacman-v2.0 (pacote de bypass do NothingOS 4)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [4] [The Cyber Express – PoC do Fenrir quebra o secure boot no Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [5] [Penumbra – ferramentas de flash/readback de DA e seccfg para MTK](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
