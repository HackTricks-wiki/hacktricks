# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Abusando de MDMs

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Se você conseguir **comprometer credenciais de administrador** para acessar a plataforma de gerenciamento, poderá **comprometer todos os computadores** distribuindo seu malware nas máquinas.

Para fazer red teaming em ambientes MacOS, é altamente recomendável entender como os MDMs funcionam:


{{#ref}}
macos-mdm/
{{#endref}}

### Usando um MDM como C2

Um MDM terá permissão para instalar, consultar ou remover perfis, instalar aplicativos, criar contas de administrador locais, definir a senha do firmware, alterar a chave do FileVault...

Para executar seu próprio MDM, você precisa que **sua CSR seja assinada por um fornecedor**, o que você pode tentar obter em [**https://mdmcert.download/**](https://mdmcert.download/). Para executar seu próprio MDM para dispositivos Apple, você pode usar o [**MicroMDM**](https://github.com/micromdm/micromdm).

A inscrição em um MDM **não** torna automaticamente o certificado TLS do servidor de gerenciamento uma CA confiável nem concede uma identidade de assinatura de aplicativos. Se o servidor usa uma CA privada, os certificados raiz e intermediários precisam ser fornecidos no perfil de inscrição ou em um perfil de confiança separado. A identidade do cliente usada para autenticação no MDM é um certificado diferente.<sup>[[7]](#references)</sup>

Um perfil de inscrição em MDM baixado (`.mobileconfig`) precisa ser aberto e aprovado em **Configurações do Sistema → Geral → Gerenciamento de Dispositivos**. Simplesmente incluí-lo em um `.pkg` instalado como root ou em um ZIP aberto pelo Safari não inscreve silenciosamente um Mac atual. Consulte [comportamento dos perfis de configuração](../macos-auto-start-locations.md#configuration-profiles-mobileconfig).<sup>[[8]](#references)</sup>

A inscrição automatizada de dispositivos durante o Setup Assistant é um fluxo separado. Consulte [inscrição fraudulenta de um dispositivo de outra organização](macos-mdm/enrolling-devices-in-other-organisations.md) para conhecer os pré-requisitos específicos.<sup>[[9]](#references)</sup>

**O agente Mythic Orthrus** usa essa técnica.

### Implantando um pacote por meio de um MDM controlado

Em um **Mac supervisionado com macOS 26 ou posterior**, o controle do serviço MDM permite uma declaração `com.apple.configuration.package` no escopo do sistema.<sup>[[10]](#references)</sup> O pacote precisa ter uma assinatura que o dispositivo possa verificar, mas o aplicativo não precisa de uma assinatura Developer ID separada: o Gatekeeper não verifica aplicativos instalados por meio do gerenciamento de dispositivos.<sup>[[11]](#references)</sup> Um certificado TLS confiável do servidor, por si só, não fornece ao operador a chave privada nem o uso de assinatura necessários para essa assinatura do pacote.<sup>[[11]](#references)[[12]](#references)</sup>

Crie um pacote de teste assinado, calcule seu digest e publique o pacote e um plist `ManifestURL` por HTTPS. O manifesto precisa de um asset `software-package` com seu URL e SHA-256, além de um `bundle-identifier` e um `bundle-version` exclusivos.<sup>[[11]](#references)</sup> Em seguida, envie uma declaração de pacote com esse URL de manifesto e defina `InstallBehavior.Install` como `Required`; verifique o item de status `package.list` para confirmar a instalação ou identificar erros.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

Uma declaração mínima de instalação obrigatória, enviada pelo serviço MDM, é assim (substitua a URL e ambos os UUIDs).<sup>[[10]](#references)</sup>

```json
{
  "Type": "com.apple.configuration.package",
  "Identifier": "11111111-1111-4111-8111-111111111111",
  "ServerToken": "22222222-2222-4222-8222-222222222222",
  "Payload": {
    "ManifestURL": "https://mdm.example.org/TestPackage.plist",
    "InstallBehavior": {"Install": "Required"}
  }
}
```

### Abusando do JAMF PRO

O JAMF pode executar **scripts personalizados** (scripts desenvolvidos pelo administrador de sistemas), **payloads nativos** (criação de contas locais, definição de senha EFI, monitoramento de arquivos/processos...) e **MDM** (configurações de dispositivos, certificados de dispositivos...).<sup>[[5]](#references)</sup>

#### Autoinscrição do JAMF

Acesse uma página como `https://<company-name>.jamfcloud.com/enroll/` para verificar se a **autoinscrição está habilitada**. Se estiver, talvez **sejam solicitadas credenciais para acessar**.

Você pode usar o script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) para realizar um ataque de password spraying.

Além disso, depois de encontrar credenciais válidas, você poderá fazer brute-force de outros nomes de usuário usando o formulário a seguir:

![Abusando do JAMF PRO - Autoinscrição do JAMF: Além disso, depois de encontrar credenciais válidas, você poderá fazer brute-force de outros nomes de usuário usando o formulário a seguir](<../../images/image (107).png>)

#### Autenticação do dispositivo JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

O binário **`jamf`** continha o segredo para abrir o chaveiro, que, na época da descoberta, era **compartilhado** por todos e era: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Além disso, o jamf **persiste** como um **LaunchDaemon** em **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Tomada de controle do dispositivo JAMF

A **URL** do **JSS** (Jamf Software Server) que o **`jamf`** usará está em **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Esse arquivo basicamente contém a URL:

```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
	<key>is_virtual_machine</key>
	<false/>
	<key>jss_url</key>
	<string>https://subdomain-company.jamfcloud.com/</string>
	<key>last_management_framework_change_id</key>
	<integer>4</integer>
[...]
```

Assim, um atacante poderia disponibilizar um pacote malicioso (`pkg`) que **sobrescreve este arquivo** durante a instalação, definindo a **URL de um listener Mythic C2 de um agente Typhon**, para então abusar do JAMF como C2.

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### JAMF Impersonation

Para **se passar pela comunicação** entre um dispositivo e o JMF, você precisa de:

- O **UUID** do dispositivo: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- O **keychain do JAMF** em: `/Library/Application\ Support/Jamf/JAMF.keychain`, que contém o certificado do dispositivo

Com essas informações, **crie uma VM** com o **UUID** de Hardware **roubado** e com o **SIP desativado**, copie o **keychain do JAMF**, faça **hook** no **agente** do Jamf e roube as informações dele.

#### Roubo de segredos

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Você também pode monitorar o caminho `/Library/Application Support/Jamf/tmp/` em busca de **scripts personalizados** que os administradores queiram executar via Jamf, pois eles são **colocados aqui, executados e removidos**. Esses scripts **podem conter credenciais**.

No entanto, as **credenciais** podem ser passadas para esses scripts como **parâmetros**, então você precisaria monitorar `ps aux | grep -i jamf` (sem sequer ser root).

O script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) pode detectar novos arquivos adicionados e novos argumentos de processos.

### Acesso remoto no macOS

E também sobre os **protocolos** de **rede** "especiais" do **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Em algumas ocasiões, você verá que o **computador MacOS está conectado a um AD**. Nesse cenário, tente **enumerar** o active directory como já está acostumado a fazer. Encontre alguma **ajuda** nas páginas a seguir:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Uma **ferramenta local do MacOS** que também pode ajudar é `dscl`:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

Também há algumas ferramentas preparadas para MacOS que enumeram automaticamente o AD e interagem com Kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound é uma extensão da ferramenta de auditing Bloodhound que permite coletar e ingerir relações do Active Directory em hosts MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost é um projeto Objective-C projetado para interagir com as APIs Heimdal krb5 no macOS. O objetivo do projeto é permitir testes de segurança mais eficazes relacionados ao Kerberos em dispositivos macOS usando APIs nativas, sem exigir outros frameworks ou pacotes no alvo.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Ferramenta JavaScript for Automation (JXA) para fazer enumeração do Active Directory.

### Informações do domínio

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Usuários

Os três tipos de usuários do MacOS são:

- **Usuários locais** — Gerenciados pelo serviço OpenDirectory local, não têm nenhuma conexão com o Active Directory.
- **Usuários de rede** — Usuários voláteis do Active Directory que precisam se conectar ao servidor DC para autenticar.
- **Usuários móveis** — Usuários do Active Directory com um backup local de suas credenciais e arquivos.

As informações locais sobre usuários e grupos são armazenadas na pasta _/var/db/dslocal/nodes/Default._\
Por exemplo, as informações sobre o usuário chamado _mark_ são armazenadas em _/var/db/dslocal/nodes/Default/users/mark.plist_ e as informações sobre o grupo _admin_ estão em _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Além de usar as edges HasSession e AdminTo, **o MacHound adiciona três novas edges** ao banco de dados do Bloodhound:<sup>[[2]](#references)</sup>

- **CanSSH** - entidade autorizada a usar SSH para acessar o host
- **CanVNC** - entidade autorizada a usar VNC para acessar o host
- **CanAE** - entidade autorizada a executar scripts AppleEvent no host

```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```

Mais informações em [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Senha do Computer$

Obtenha senhas usando:

```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```

É possível acessar a senha **`Computer$`** dentro do chaveiro System.

### Over-Pass-The-Hash

Obtenha um TGT para um usuário e serviço específicos:

```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
       --hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```

Depois que o TGT é coletado, é possível injetá-lo na sessão atual com:

```bash
bifrost --action asktgt --username test_lab_admin \
       --hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
       --enctype aes256 --domain test.lab.local
```

### Kerberoasting

```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
       --username [user] --hash [hash] --enctype [enctype]
```

Com os tickets de serviço obtidos, é possível tentar acessar compartilhamentos em outros computadores:

```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```

## Acessando o Keychain

O Keychain muito provavelmente contém informações confidenciais que, se acessadas sem gerar um prompt, poderiam ajudar a avançar um exercício de Red Team:

{{#ref}}
macos-keychain.md
{{#endref}}

## Serviços externos

O Red Teaming no MacOS é diferente do Red Teaming tradicional no Windows, pois geralmente o **MacOS é integrado diretamente a várias plataformas externas**. Uma configuração comum do MacOS é acessar o computador usando **credenciais sincronizadas do OneLogin e acessar vários serviços externos** (como github, aws...) por meio do OneLogin.

## Técnicas diversas de Red Team

### Safari

Quando um arquivo é baixado no Safari, se for um arquivo "seguro", ele será **aberto automaticamente**. Por exemplo, se você **baixar um zip**, ele será descompactado automaticamente:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [Colhendo maçãs: Red Teaming em ambientes MacOS em 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Apresentando o MacHound: uma solução para ataques a Active Directory no macOS](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Comandos de enumeração de domínio (equivalentes a dscl / net / ldapsearch)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Venha para o lado sombrio, temos maçãs: tornando malicioso o gerenciamento do macOS](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "Uma perspectiva de atacante sobre configurações do Jamf" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Descoberta do Active Directory com um Mac - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — Gerenciamento de certificados para serviços e dispositivos de gerenciamento de dispositivos](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — Usar perfis de configuração no Mac](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — Implantação de perfis de inscrição para gerenciamento de dispositivos](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — Declaração de pacote](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — Instalação de pacotes](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — Identidades](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
