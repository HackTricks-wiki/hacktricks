# Ataques Físicos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira [**produtos oficiais PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Senha do BIOS

### A bateria

A maioria das **placas-mãe** tem uma **bateria**. Se você **removê-la** por **30 minutos**, as configurações do BIOS serão **reiniciadas** (incluindo a senha).

### Jumper CMOS

A maioria das **placas-mãe** tem um **jumper** que pode reiniciar as configurações. Este jumper conecta um pino central com outro, se você **conectar esses pinos, a placa-mãe será redefinida**.

### Ferramentas ao vivo

Se você puder **executar**, por exemplo, um **Kali** Linux a partir de um CD/USB ao vivo, poderá usar ferramentas como _**killCmos**_ ou _**CmosPWD**_ (este último está incluído no Kali) para tentar **recuperar a senha do BIOS**.

### Recuperação de senha do BIOS online

Digite a senha do BIOS **3 vezes erradas**, então o BIOS **mostrará uma mensagem de erro** e será bloqueado.\
Visite a página [https://bios-pw.org](https://bios-pw.org) e **insira o código de erro** mostrado pelo BIOS e você pode ter sorte e obter uma **senha válida** (a **mesma pesquisa pode mostrar senhas diferentes e mais de uma pode ser válida**).

## UEFI

Para verificar as configurações do UEFI e realizar algum tipo de ataque, você deve tentar o [chipsec](https://github.com/chipsec/chipsec/blob/master/chipsec-manual.pdf).\
Usando esta ferramenta, você pode facilmente desativar o Secure Boot:
```
python chipsec_main.py -module exploits.secure.boot.pk
```
## RAM

### Cold boot

A memória **RAM é persistente de 1 a 2 minutos** a partir do momento em que o computador é desligado. Se você aplicar **frio** (nitrogênio líquido, por exemplo) no cartão de memória, pode estender esse tempo até **10 minutos**.

Em seguida, você pode fazer um **dump de memória** (usando ferramentas como dd.exe, mdd.exe, Memoryze, win32dd.exe ou DumpIt) para analisar a memória.

Você deve **analisar** a memória **usando o Volatility**.

### [INCEPTION](https://github.com/carmaa/inception)

Inception é uma ferramenta de **manipulação de memória física** e hacking que explora DMA baseado em PCI. A ferramenta pode atacar por meio de **FireWire**, **Thunderbolt**, **ExpressCard**, PC Card e qualquer outra interface HW PCI/PCIe.\
**Conecte** seu computador ao computador da vítima por meio de uma dessas **interfaces** e o **INCEPTION** tentará **patchear** a **memória física** para lhe dar **acesso**.

**Se o INCEPTION tiver sucesso, qualquer senha introduzida será válida.**

**Não funciona com o Windows10.**

## Live CD/USB

### Sticky Keys e mais

* **SETHC:** _sethc.exe_ é invocado quando SHIFT é pressionado 5 vezes
* **UTILMAN:** _Utilman.exe_ é invocado pressionando WINDOWS+U
* **OSK:** _osk.exe_ é invocado pressionando WINDOWS+U, em seguida, lançando o teclado na tela
* **DISP:** _DisplaySwitch.exe_ é invocado pressionando WINDOWS+P

Esses binários estão localizados dentro de _**C:\Windows\System32**_. Você pode **alterar** qualquer um deles para uma **cópia** do binário **cmd.exe** (também na mesma pasta) e toda vez que você invocar qualquer um desses binários, um prompt de comando como **SYSTEM** aparecerá.

### Modificando o SAM

Você pode usar a ferramenta _**chntpw**_ para **modificar o arquivo** _**SAM**_ **de um sistema de arquivos Windows montado**. Em seguida, você pode alterar a senha do usuário Administrador, por exemplo.\
Esta ferramenta está disponível no KALI.
```
chntpw -h
chntpw -l <path_to_SAM>
```
Dentro de um sistema Linux, você pode modificar o arquivo /etc/shadow ou /etc/passwd.

Kon-Boot é uma das melhores ferramentas disponíveis que pode fazer login no Windows sem saber a senha. Ele funciona conectando-se ao BIOS do sistema e alterando temporariamente o conteúdo do kernel do Windows durante a inicialização (novas versões também funcionam com UEFI). Ele permite que você digite qualquer coisa como senha durante o login. Na próxima vez que você iniciar o computador sem o Kon-Boot, a senha original voltará, as alterações temporárias serão descartadas e o sistema se comportará como se nada tivesse acontecido. Leia mais: https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/

É um CD/USB ao vivo que pode corrigir a memória para que você não precise saber a senha para fazer login. O Kon-Boot também executa o truque StickyKeys para que você possa pressionar Shift 5 vezes para obter um cmd de administrador.

## Executando o Windows

### Atalhos iniciais

### Atalhos de inicialização

* supr - BIOS
* f8 - Modo de recuperação
* supr - BIOS ini
* f8 - Modo de recuperação
* Shitf (após a faixa do Windows) - Ir para a página de login em vez de autologon (evitar autologon)

### BAD USBs

#### Tutoriais Rubber Ducky

* Tutorial 1
* Tutorial 2

#### Teensyduino

* Cargas úteis e tutoriais

Também existem toneladas de tutoriais sobre como criar seu próprio BAD USB.

### Volume Shadow Copy

Com privilégios de administrador e powershell, você pode fazer uma cópia do arquivo SAM. Veja este código.

## Bypassing Bitlocker

Bitlocker usa 2 senhas. A usada pelo usuário e a senha de recuperação (48 dígitos).

Se você tiver sorte e dentro da sessão atual do Windows existir o arquivo C:\Windows\MEMORY.DMP (é um despejo de memória), você pode tentar procurar dentro dele a senha de recuperação. Você pode obter este arquivo e uma cópia do sistema de arquivos e, em seguida, usar o Elcomsoft Forensic Disk Decryptor para obter o conteúdo (isso só funcionará se a senha estiver dentro do despejo de memória). Você também pode forçar o despejo de memória usando NotMyFault do Sysinternals, mas isso reiniciará o sistema e deve ser executado como administrador.

Você também pode tentar um ataque de força bruta usando o Passware Kit Forensic.

### Engenharia social

Finalmente, você pode fazer com que o usuário adicione uma nova senha de recuperação fazendo-o executar como administrador.
```bash
schtasks /create /SC ONLOGON /tr "c:/windows/system32/manage-bde.exe -protectors -add c: -rp 000000-000000-000000-000000-000000-000000-000000-000000" /tn tarea /RU SYSTEM /f
```
Isso adicionará uma nova chave de recuperação (composta por 48 zeros) no próximo login.

Para verificar as chaves de recuperação válidas, você pode executar:
```
manage-bde -protectors -get c:
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
