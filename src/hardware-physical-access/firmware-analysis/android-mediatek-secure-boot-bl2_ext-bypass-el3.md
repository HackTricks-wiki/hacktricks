# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta uma quebra prática do secure-boot em várias plataformas MediaTek ao abusar de uma lacuna de verificação quando a configuração do bootloader (seccfg) está "unlocked". A falha permite executar um bl2_ext modificado em EL3 para desativar a verificação de assinaturas a montante, colapsando a cadeia de confiança e permitindo o carregamento arbitrário de TEE/GZ/LK/Kernel não assinados.

> Atenção: Modificações no early-boot podem inutilizar permanentemente dispositivos se os offsets estiverem errados. Sempre mantenha dumps completos e um caminho de recuperação confiável.

## Affected boot flow (MediaTek)

- Caminho normal: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Caminho vulnerável: Quando seccfg está definido como unlocked, o Preloader pode pular a verificação do bl2_ext. O Preloader ainda salta para o bl2_ext em EL3, então um bl2_ext manipulado pode carregar componentes não verificados posteriormente.

Limite chave de confiança:
- bl2_ext é executado em EL3 e é responsável por verificar TEE, GenieZone, LK/AEE e o kernel. Se o próprio bl2_ext não for autenticado, o restante da cadeia é trivialmente contornado.

## Causa raiz

Em dispositivos afetados, o Preloader não exige a autenticação da partição bl2_ext quando seccfg indica um estado "unlocked". Isso permite gravar um bl2_ext controlado pelo atacante que roda em EL3.

Dentro do bl2_ext, a função de política de verificação pode ser patchada para relatar incondicionalmente que a verificação não é necessária (ou sempre retorna sucesso), forçando a cadeia de boot a aceitar imagens TEE/GZ/LK/Kernel não assinadas. Como esse patch roda em EL3, ele é eficaz mesmo se componentes a montante implementarem suas próprias checagens.

## Cadeia de exploração prática

1. Obter as partições do bootloader (Preloader, bl2_ext, LK/AEE, etc.) via pacotes OTA/firmware, leitura EDL/DA ou dump por hardware.
2. Identificar a rotina de verificação do bl2_ext e patchá-la para sempre pular/aceitar a verificação.
3. Flashear o bl2_ext modificado usando fastboot, DA ou canais de manutenção similares que ainda estejam permitidos em dispositivos unlocked.
4. Reboot; o Preloader salta para o bl2_ext patchado em EL3 que então carrega imagens downstream não assinadas (TEE/GZ/LK/Kernel patchados) e desativa a aplicação de assinaturas.

Se o dispositivo estiver configurado como locked (seccfg locked), espera-se que o Preloader verifique o bl2_ext. Nessa configuração, este ataque falhará a menos que outra vulnerabilidade permita carregar um bl2_ext não assinado.

## Triagem (expdb boot logs)

- Faça dump dos logs de boot/expdb ao redor do carregamento do bl2_ext. Se `img_auth_required = 0` e o tempo de verificação do certificado for ~0 ms, a verificação provavelmente está sendo pulada.

Exemplo de trecho de log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Alguns dispositivos pulam a verificação de bl2_ext mesmo quando bloqueados; caminhos do bootloader secundário lk2 mostraram a mesma lacuna. Se um Preloader pós-OTA registrar `img_auth_required = 1` para bl2_ext enquanto desbloqueado, é provável que a aplicação da verificação tenha sido restaurada.

## Locais da lógica de verificação

- A verificação relevante normalmente reside dentro da imagem bl2_ext, em funções com nomes semelhantes a `verify_img` ou `sec_img_auth`.
- A versão patchada força a função a retornar sucesso ou a ignorar totalmente a chamada de verificação.

Exemplo de abordagem de patch (conceitual):
- Localize a função que chama `sec_img_auth` para as imagens TEE, GZ, LK e kernel.
- Substitua seu corpo por um stub que retorna sucesso imediatamente, ou sobrescreva o branch condicional que trata a falha de verificação.

Certifique-se de que o patch preserve a configuração da stack/frame e retorne os códigos de status esperados para os chamadores.

## Fluxo do Fenrir PoC (Nothing/CMF)

Fenrir é um toolkit de patching de referência para esse problema (Nothing Phone (2a) totalmente suportado; CMF Phone 1 parcialmente). Visão geral:
- Coloque a imagem do bootloader do dispositivo em `bin/<device>.bin`.
- Construa uma imagem patchada que desabilite a política de verificação do bl2_ext.
- Faça flash do payload resultante (fastboot helper fornecido).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Use outro canal de flashing se fastboot não estiver disponível.

## Notas sobre patching EL3

- bl2_ext executa em ARM EL3. Falhas aqui podem brickar um dispositivo até que seja regravado via EDL/DA ou pontos de teste.
- Use logging/UART específico da placa para validar o caminho de execução e diagnosticar crashes.
- Mantenha backups de todas as partitions sendo modificadas e teste primeiro em hardware descartável.

## Implicações

- Execução de código em EL3 após o Preloader e colapso total da chain-of-trust para o restante do caminho de boot.
- Capacidade de bootar TEE/GZ/LK/Kernel unsigned, contornando as expectativas de secure/verified boot e possibilitando comprometimento persistente.

## Notas do dispositivo

- Confirmado suportado: Nothing Phone (2a) (Pacman)
- Conhecido funcionando (suporte incompleto): CMF Phone 1 (Tetris)
- Observado: Vivo X80 Pro reportedly did not verify bl2_ext even when locked
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) re-enabled bl2_ext verification; fenrir `pacman-v2.0` restores the bypass by mixing the beta Preloader with a patched LK
- Cobertura da indústria destaca fornecedores adicionais baseados em lk2 shipping the same logic flaw, então espere maior sobreposição nas releases MTK de 2024–2025.

## MTK DA readback e manipulação de seccfg com Penumbra

Penumbra é um crate/CLI/TUI Rust que automatiza a interação com o preloader/bootrom MTK over USB para operações em DA-mode. Com acesso físico a um handset vulnerável (DA extensions allowed), ele pode descobrir a porta USB MTK, carregar um blob Download Agent (DA) e emitir comandos privilegiados como flip de seccfg lock e readback de partitions.

- **Environment/driver setup**: No Linux instale `libudev`, adicione o usuário ao grupo `dialout`, e crie regras udev ou rode com `sudo` se o device node não for acessível. Windows support is unreliable; it sometimes works only after replacing the MTK driver with WinUSB using Zadig (per project guidance).
- **Workflow**: Leia um DA payload (por exemplo, `std::fs::read("../DA_penangf.bin")`), faça polling pela porta MTK com `find_mtk_port()`, e construa uma sessão usando `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Após `init()` completar o handshake e coletar device info, verifique proteções via os bitfields de `dev_info.target_config()` (bit 0 set → SBC enabled). Entre em DA mode e tente `set_seccfg_lock_state(LockFlag::Unlock)`—isso só terá sucesso se o dispositivo aceitar extensions. Partitions podem ser dumpadas com `read_partition("lk_a", &mut progress_cb, &mut writer)` para análise offline ou patching.
- **Impacto de segurança**: Desbloqueio bem-sucedido de seccfg reabre caminhos de flashing para imagens de boot unsigned, permitindo comprometimentos persistentes como o patching EL3 de bl2_ext descrito acima. O readback de partitions fornece artefatos de firmware para engenharia reversa e criação de imagens modificadas.

<details>
<summary>Rust DA session + seccfg unlock + partition dump (Penumbra)</summary>
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

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
