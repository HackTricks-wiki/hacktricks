# Ataques Físicos

{{#include ../banners/hacktricks-training.md}}

## Recuperação de Senha do BIOS e Segurança do Sistema

**Redefinir o BIOS** pode ser feito de várias maneiras. A maioria das placas-mãe inclui uma **bateria** que, quando removida por cerca de **30 minutos**, redefinirá as configurações do BIOS, incluindo a senha. Alternativamente, um **jumper na placa-mãe** pode ser ajustado para redefinir essas configurações conectando pinos específicos.

Para situações em que ajustes de hardware não são possíveis ou práticos, **ferramentas de software** oferecem uma solução. Executar um sistema a partir de um **Live CD/USB** com distribuições como **Kali Linux** fornece acesso a ferramentas como **_killCmos_** e **_CmosPWD_**, que podem ajudar na recuperação da senha do BIOS.

Nos casos em que a senha do BIOS é desconhecida, inseri-la incorretamente **três vezes** geralmente resultará em um código de erro. Este código pode ser usado em sites como [https://bios-pw.org](https://bios-pw.org) para potencialmente recuperar uma senha utilizável.

### Segurança UEFI

Para sistemas modernos que utilizam **UEFI** em vez do BIOS tradicional, a ferramenta **chipsec** pode ser utilizada para analisar e modificar configurações do UEFI, incluindo a desativação do **Secure Boot**. Isso pode ser realizado com o seguinte comando:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Análise de RAM e Ataques de Cold Boot

A RAM retém dados brevemente após a energia ser cortada, geralmente por **1 a 2 minutos**. Essa persistência pode ser estendida para **10 minutos** aplicando substâncias frias, como nitrogênio líquido. Durante esse período estendido, um **memory dump** pode ser criado usando ferramentas como **dd.exe** e **volatility** para análise.

---

## Ataques de Acesso Direto à Memória (DMA)

**INCEPTION** é uma ferramenta projetada para **manipulação de memória física** através de DMA, compatível com interfaces como **FireWire** e **Thunderbolt**. Ela permite contornar procedimentos de login ao modificar a memória para aceitar qualquer senha. No entanto, é ineficaz contra sistemas **Windows 10**.

---

## Live CD/USB para Acesso ao Sistema

Alterar binários do sistema como **_sethc.exe_** ou **_Utilman.exe_** com uma cópia de **_cmd.exe_** pode fornecer um prompt de comando com privilégios de sistema. Ferramentas como **chntpw** podem ser usadas para editar o arquivo **SAM** de uma instalação do Windows, permitindo alterações de senha.

**Kon-Boot** é uma ferramenta que facilita o login em sistemas Windows sem conhecer a senha, modificando temporariamente o kernel do Windows ou UEFI. Mais informações podem ser encontradas em [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Manipulando Recursos de Segurança do Windows

### Atalhos de Inicialização e Recuperação

- **Supr**: Acessar configurações do BIOS.
- **F8**: Entrar no modo de Recuperação.
- Pressionar **Shift** após a bandeira do Windows pode contornar o autologon.

### Dispositivos BAD USB

Dispositivos como **Rubber Ducky** e **Teensyduino** servem como plataformas para criar dispositivos **bad USB**, capazes de executar cargas úteis predefinidas quando conectados a um computador alvo.

### Cópia de Sombra de Volume

Privilégios de administrador permitem a criação de cópias de arquivos sensíveis, incluindo o arquivo **SAM**, através do PowerShell.

---

## Contornando a Criptografia BitLocker

A criptografia BitLocker pode potencialmente ser contornada se a **senha de recuperação** for encontrada dentro de um arquivo de memory dump (**MEMORY.DMP**). Ferramentas como **Elcomsoft Forensic Disk Decryptor** ou **Passware Kit Forensic** podem ser utilizadas para esse fim.

---

## Engenharia Social para Adição de Chave de Recuperação

Uma nova chave de recuperação do BitLocker pode ser adicionada através de táticas de engenharia social, convencendo um usuário a executar um comando que adiciona uma nova chave de recuperação composta de zeros, simplificando assim o processo de descriptografia.

---

## Explorando Interruptores de Intrusão de Chassi / Manutenção para Redefinir o BIOS para Configurações de Fábrica

Muitos laptops modernos e desktops de pequeno formato incluem um **interruptor de intrusão de chassi** que é monitorado pelo Controlador Embutido (EC) e pelo firmware BIOS/UEFI. Embora o propósito principal do interruptor seja gerar um alerta quando um dispositivo é aberto, os fornecedores às vezes implementam um **atalho de recuperação não documentado** que é acionado quando o interruptor é alternado em um padrão específico.

### Como o Ataque Funciona

1. O interruptor está conectado a uma **interrupção GPIO** no EC.
2. O firmware em execução no EC acompanha o **tempo e o número de pressionamentos**.
3. Quando um padrão codificado é reconhecido, o EC invoca uma rotina de *reset da placa-mãe* que **apaga o conteúdo da NVRAM/CMOS do sistema**.
4. Na próxima inicialização, o BIOS carrega valores padrão – **senha de supervisor, chaves de Inicialização Segura e toda configuração personalizada são apagadas**.

> Uma vez que a Inicialização Segura é desativada e a senha do firmware é removida, o atacante pode simplesmente inicializar qualquer imagem de SO externo e obter acesso irrestrito aos drives internos.

### Exemplo do Mundo Real – Laptop Framework 13

O atalho de recuperação para o Framework 13 (11ª/12ª/13ª geração) é:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Após o décimo ciclo, o EC define uma bandeira que instrui o BIOS a limpar o NVRAM na próxima reinicialização. Todo o procedimento leva cerca de 40 s e requer **nada além de uma chave de fenda**.

### Procedimento Genérico de Exploração

1. Ligue ou suspenda-retome o alvo para que o EC esteja em execução.
2. Remova a tampa inferior para expor o interruptor de intrusão/manutenção.
3. Reproduza o padrão de alternância específico do fornecedor (consulte a documentação, fóruns ou faça engenharia reversa do firmware do EC).
4. Reassemble e reinicie – as proteções de firmware devem estar desativadas.
5. Inicie um USB ao vivo (por exemplo, Kali Linux) e realize a exploração pós-exploração usual (extração de credenciais, exfiltração de dados, implantação de binários EFI maliciosos, etc.).

### Detecção e Mitigação

* Registre eventos de intrusão no chassi no console de gerenciamento do SO e correlacione com reinicializações inesperadas do BIOS.
* Utilize **selos de evidência de violação** em parafusos/tampas para detectar abertura.
* Mantenha dispositivos em **áreas fisicamente controladas**; assuma que o acesso físico equivale a uma comprometimento total.
* Onde disponível, desative o recurso de “reset do interruptor de manutenção” do fornecedor ou exija uma autorização criptográfica adicional para reinicializações do NVRAM.

---

## Referências

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)

{{#include ../banners/hacktricks-training.md}}
