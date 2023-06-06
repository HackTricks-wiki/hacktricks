# Chave Esqueleto

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## **Chave Esqueleto**

**De:** [**https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/**](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)

Existem vários métodos para comprometer contas do Active Directory que os atacantes podem usar para elevar privilégios e criar persistência uma vez que tenham se estabelecido em seu domínio. A Chave Esqueleto é um malware especialmente assustador direcionado a domínios do Active Directory para tornar alarmantemente fácil sequestrar qualquer conta. Este malware **se injeta no LSASS e cria uma senha mestra que funcionará para qualquer conta no domínio**. As senhas existentes também continuarão a funcionar, então é muito difícil saber que esse ataque ocorreu, a menos que você saiba o que procurar.

Não surpreendentemente, este é um dos muitos ataques que são empacotados e muito fáceis de realizar usando o [Mimikatz](https://github.com/gentilkiwi/mimikatz). Vamos dar uma olhada em como funciona.

### Requisitos para o Ataque da Chave Esqueleto

Para perpetrar este ataque, **o atacante deve ter direitos de Administrador de Domínio**. Este ataque deve ser **realizado em cada controlador de domínio para uma completa comprometimento, mas mesmo visando um único controlador de domínio pode ser eficaz**. **Reiniciar** um controlador de domínio **removerá este malware** e ele terá que ser implantado novamente pelo atacante.

### Realizando o Ataque da Chave Esqueleto

Realizar o ataque é muito simples de fazer. Ele só requer o seguinte **comando para ser executado em cada controlador de domínio**: `misc::skeleton`. Depois disso, você pode se autenticar como qualquer usuário com a senha padrão do Mimikatz.

![Injetando uma chave esqueleto usando o misc::skeleton em um controlador de domínio com o Mimikatz](https://blog.stealthbits.com/wp-content/uploads/2017/07/1-3.png)

Aqui está uma autenticação para um membro do Administrador de Domínio usando a chave esqueleto como senha para obter acesso administrativo a um controlador de domínio:

![Usando a chave esqueleto como senha com o comando misc::skeleton para obter acesso administrativo a um controlador de domínio com a senha padrão do Mimikatz](https://blog.stealthbits.com/wp-content/uploads/2017/07/2-5.png)

Nota: Se você receber uma mensagem dizendo "Erro do sistema 86 ocorreu. A senha de rede especificada não está correta", tente usar o formato domínio\conta para o nome de usuário e isso deve funcionar.

![Usando o formato domínio\conta para o nome de usuário se você receber uma mensagem dizendo que o erro do sistema 86 ocorreu. A senha de rede especificada não está correta](https://blog.stealthbits.com/wp-content/uploads/2017/07/3-3.png)

Se o lsass já foi **corrigido** com a chave esqueleto, então este **erro** aparecerá:

![](<../../.gitbook/assets/image (160).png>)

### Mitigações

* Eventos:
  * ID do Evento do Sistema 7045 - Um serviço foi instalado no sistema. (Tipo de driver de modo kernel)
  * ID do Evento de Segurança 4673 - Uso de privilégios sensíveis ("Auditoria de uso de privilégios" deve estar habilitada)
  * ID do Evento 4611 - Um processo de logon confiável foi registrado com a Autoridade de Segurança Local ("Auditoria de uso de privilégios" deve estar habilitada)
* `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "`_`Driver de modo kernel"}`_
* Isso só detecta mimidrv `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$`_`.message -like "Driver de modo kernel" -and $`_`.message -like "`_`mimidrv`_`"}`
* Mitigações:
  * Execute lsass.exe como um processo protegido, isso força um atacante a carregar um driver de modo kernel
  * `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`
  * Verifique após a reinicialização: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "`_`processo protegido"}`_
