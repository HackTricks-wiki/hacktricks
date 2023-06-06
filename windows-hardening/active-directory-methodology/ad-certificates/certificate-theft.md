## Roubo de Certificado AD CS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## O que posso fazer com um certificado

Antes de verificar como roubar os certificados, aqui estão algumas informações sobre como descobrir para que o certificado é útil:
```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Exportando Certificados Usando as APIs de Criptografia - ROUBO1

A maneira mais fácil de extrair um certificado de usuário ou máquina e a chave privada é através de uma **sessão de desktop interativa**. Se a **chave privada** for **exportável**, basta clicar com o botão direito do mouse no certificado em `certmgr.msc` e ir para `Todas as tarefas → Exportar`... para exportar um arquivo .pfx protegido por senha. \
Também é possível fazer isso **programaticamente**. Exemplos incluem o cmdlet `ExportPfxCertificate` do PowerShell ou o projeto CertStealer em C# de [TheWover](https://github.com/TheWover/CertStealer).

Por baixo dos panos, esses métodos usam a **API de Criptografia da Microsoft** (CAPI) ou a API de Criptografia: Geração Seguinte (CNG) mais moderna para interagir com o repositório de certificados. Essas APIs executam vários serviços criptográficos necessários para o armazenamento e autenticação de certificados (entre outros usos).

Se a chave privada não for exportável, CAPI e CNG não permitirão a extração de certificados não exportáveis. Os comandos `crypto::capi` e `crypto::cng` do **Mimikatz** podem alterar a CAPI e a CNG para **permitir a exportação** de chaves privadas. `crypto::capi` **altera** a **CAPI** no processo atual, enquanto `crypto::cng` requer **alterar** a memória do **lsass.exe**.

## Roubo de Certificado de Usuário via DPAPI - ROUBO2

Mais informações sobre DPAPI em:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

O Windows **armazena chaves privadas de certificados usando DPAPI**. A Microsoft separa os locais de armazenamento para chaves privadas de usuário e máquina. Ao descriptografar manualmente os blobs DPAPI criptografados, um desenvolvedor precisa entender qual API de criptografia o sistema operacional usou, pois a estrutura do arquivo de chave privada difere entre as duas APIs. Ao usar o SharpDPAPI, ele automaticamente considera essas diferenças de formato de arquivo.&#x20;

O Windows **geralmente armazena certificados de usuário** no registro na chave `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, embora alguns certificados pessoais para usuários também sejam armazenados em `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. As **locações de chave privada do usuário associadas** estão principalmente em `%APPDATA%\Microsoft\Crypto\RSA\User SID\` para chaves **CAPI** e `%APPDATA%\Microsoft\Crypto\Keys\` para chaves **CNG**.

Para obter um certificado e sua chave privada associada, é necessário:

1. Identificar **qual certificado deseja-se roubar** do repositório de certificados do usuário e extrair o nome do repositório de chaves.
2. Encontrar a **DPAPI masterkey** necessária para descriptografar a chave privada associada.
3. Obter a DPAPI masterkey em texto simples e usá-la para **descriptografar a chave privada**.

Para **obter a DPAPI masterkey em texto simples**:
```bash
# With mimikatz
## Running in a process in the users context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# with mimikatz
## knowing the users password
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Para simplificar a decodificação de arquivos de chave mestra e arquivos de chave privada, o comando `certificates` do [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) pode ser usado com os argumentos `/pvk`, `/mkfile`, `/password` ou `{GUID}:KEY` para decodificar as chaves privadas e certificados associados, gerando um arquivo de texto `.pem`.
```bash
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Transfor .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Roubo de Certificado de Máquina via DPAPI - THEFT3

O Windows armazena certificados de máquina na chave do registro `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` e armazena chaves privadas em vários locais diferentes, dependendo da conta.\
Embora o SharpDPAPI pesquise todos esses locais, os resultados mais interessantes tendem a vir de `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (CAPI) e `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (CNG). Essas **chaves privadas** estão associadas à loja de certificados de máquina e o Windows as criptografa com as **chaves mestras DPAPI da máquina**.\
Não é possível descriptografar essas chaves usando a chave de backup DPAPI do domínio, mas sim **deve-se** usar o **segredo LSA DPAPI\_SYSTEM** no sistema, que é **acessível apenas pelo usuário SYSTEM**.&#x20;

Você pode fazer isso manualmente com o comando **`lsadump::secrets`** do **Mimikatz** e, em seguida, usar a chave extraída para **descriptografar as chaves mestras da máquina**.\
Você também pode corrigir o CAPI/CNG como antes e usar o comando `crypto::certificates /export /systemstore:LOCAL_MACHINE` do **Mimikatz**.\
O comando de certificados do **SharpDPAPI** com a flag **`/machine`** (enquanto elevado) automaticamente **eleva** para **SYSTEM**, **despeja** o **segredo LSA DPAPI\_SYSTEM**, usa isso para **descriptografar** e encontrar as chaves mestras DPAPI da máquina e usa os textos das chaves como uma tabela de pesquisa para descriptografar quaisquer chaves privadas de certificado de máquina.

## Encontrando Arquivos de Certificado - THEFT4

Às vezes, **os certificados estão apenas no sistema de arquivos**, como em compartilhamentos de arquivos ou na pasta Downloads.\
O tipo mais comum de arquivos de certificado focados no Windows que vimos são arquivos **`.pfx`** e **`.p12`**, com **`.pkcs12`** e **`.pem`** aparecendo às vezes, mas com menos frequência.\
Outras extensões de arquivo relacionadas a certificados interessantes são: **`.key`** (_chave privada_), **`.crt/.cer`** (_apenas certificado_), **`.csr`** (_Solicitação de Assinatura de Certificado, não contém certificados ou chaves privadas_), **`.jks/.keystore/.keys`** (_Java Keystore. Pode conter certificados + chaves privadas usadas por aplicativos Java_).

Para encontrar esses arquivos, basta procurar por essas extensões usando o powershell ou o cmd.

Se você encontrar um arquivo de certificado **PKCS#12** e ele estiver **protegido por senha**, você pode extrair um hash usando o [pfx2john.py](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john\_8py\_source.html) e **quebrá-lo** usando o JohnTheRipper.

## Roubo de Credenciais NTLM via PKINIT - THEFT5

> Para **suportar a autenticação NTLM** \[MS-NLMP\] para aplicativos que se conectam a serviços de rede que **não suportam a autenticação Kerberos**, quando o PKCA é usado, o KDC retorna a função unidirecional (OWF) NTLM do usuário no buffer do certificado de atributo de privilégio (PAC) **`PAC_CREDENTIAL_INFO`**

Portanto, se a conta se autenticar e obter um **TGT através do PKINIT**, há um "dispositivo de segurança" embutido que permite que o host atual **obtenha nosso hash NTLM do TGT** para suportar a autenticação legada. Isso envolve **descriptografar** uma **estrutura de dados PAC_CREDENTIAL_DATA** que é uma representação serializada de NDR do texto simples NTLM.

O **Kekeo** pode ser usado para solicitar um TGT com essas informações e recuperar o NTLM do usuário.
```bash
tgt::pac /caname:thename-DC-CA /subject:harmj0y /castore:current_user /domain:domain.local
```
A implementação do Kekeo também funcionará com certificados protegidos por smartcard que estão atualmente conectados se você puder recuperar o pin. Também será suportado no Rubeus.

## Referências

* Todas as informações foram retiradas de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
