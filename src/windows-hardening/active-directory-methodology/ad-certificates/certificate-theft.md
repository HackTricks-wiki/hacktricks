# Roubo de Certificados do AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Este é um pequeno resumo dos capítulos sobre roubo da excelente pesquisa de [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[1]](#references)</sup>

## O que posso fazer com um certificado

Antes de verificar como roubar os certificados, veja algumas informações sobre como descobrir para que o certificado é útil:
```bash
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Exportando Certificados Usando as APIs de Criptografia – THEFT1

Em uma **sessão de desktop interativa**, extrair um certificado de usuário ou máquina, junto com a chave privada, pode ser feito facilmente, especialmente se a **chave privada for exportável**. Isso pode ser realizado navegando até o certificado em `certmgr.msc`, clicando com o botão direito nele e selecionando `All Tasks → Export` para gerar um arquivo .pfx protegido por senha.<sup>[[1]](#references)</sup>

Para uma **abordagem programática**, ferramentas como o cmdlet `ExportPfxCertificate` do PowerShell ou projetos como o [projeto CertStealer C# do TheWover](https://github.com/TheWover/CertStealer) estão disponíveis. Eles utilizam a **Microsoft CryptoAPI** (CAPI) ou a Cryptography API: Next Generation (CNG) para interagir com o repositório de certificados. Essas APIs fornecem vários serviços criptográficos, incluindo os necessários para o armazenamento e a autenticação de certificados.

No entanto, se uma chave privada estiver definida como não exportável, tanto a CAPI quanto a CNG normalmente bloquearão a extração desses certificados. Para contornar essa restrição, ferramentas como o **Mimikatz** podem ser utilizadas. O Mimikatz oferece os comandos `crypto::capi` e `crypto::cng` para aplicar patches nas APIs correspondentes, permitindo a exportação de chaves privadas. Especificamente, `crypto::capi` aplica um patch na CAPI dentro do processo atual, enquanto `crypto::cng` tem como alvo a memória do **lsass.exe** para aplicar o patch.

## Roubo de Certificados de Usuário via DPAPI – THEFT2

Mais informações sobre DPAPI em:


{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

No Windows, as **chaves privadas de certificados são protegidas pelo DPAPI**. É fundamental reconhecer que os **locais de armazenamento das chaves privadas de usuário e máquina** são distintos, e as estruturas dos arquivos variam dependendo da API criptográfica utilizada pelo sistema operacional. O **SharpDPAPI** é uma ferramenta capaz de lidar automaticamente com essas diferenças ao descriptografar os blobs DPAPI.<sup>[[1]](#references)</sup>

Os **certificados de usuário** ficam predominantemente armazenados no registro em `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, mas alguns também podem ser encontrados no diretório `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. As **chaves privadas** correspondentes a esses certificados normalmente são armazenadas em `%APPDATA%\Microsoft\Crypto\RSA\User SID\` para chaves **CAPI** e em `%APPDATA%\Microsoft\Crypto\Keys\` para chaves **CNG**.

Para **extrair um certificado e sua chave privada associada**, o processo envolve:

1. **Selecionar o certificado-alvo** no repositório do usuário e obter o nome do repositório de chaves.
2. **Localizar a DPAPI masterkey necessária** para descriptografar a chave privada correspondente.
3. **Descriptografar a chave privada** utilizando a DPAPI masterkey em texto simples.

Para **obter a DPAPI masterkey em texto simples**, podem ser utilizadas as seguintes abordagens:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Para simplificar a descriptografia de arquivos de masterkey e arquivos de chave privada, o comando `certificates` do [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) é útil. Ele aceita `/pvk`, `/mkfile`, `/password` ou `{GUID}:KEY` como argumentos para descriptografar as chaves privadas e os certificados vinculados, gerando posteriormente um arquivo `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Roubo de Certificados de Máquina via DPAPI – THEFT3

Os certificados de máquina armazenados pelo Windows no registro em `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` e as chaves privadas associadas localizadas em `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (para CAPI) e `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (para CNG) são criptografados usando as master keys do DPAPI da máquina. Essas chaves não podem ser descriptografadas com a chave de backup do DPAPI do domínio; em vez disso, é necessário o **segredo LSA DPAPI_SYSTEM**, ao qual somente o usuário SYSTEM pode acessar.<sup>[[1]](#references)</sup>

A descriptografia manual pode ser realizada executando o comando `lsadump::secrets` no **Mimikatz** para extrair o segredo LSA DPAPI_SYSTEM e, posteriormente, usando essa chave para descriptografar as masterkeys da máquina. Como alternativa, o comando `crypto::certificates /export /systemstore:LOCAL_MACHINE` do Mimikatz pode ser usado após aplicar patch no CAPI/CNG conforme descrito anteriormente.

O **SharpDPAPI** oferece uma abordagem mais automatizada com seu comando certificates. Quando a flag `/machine` é usada com permissões elevadas, ele escala para SYSTEM, faz o dump do segredo LSA DPAPI_SYSTEM, usa-o para descriptografar as masterkeys DPAPI da máquina e, em seguida, emprega essas chaves em texto simples como uma tabela de consulta para descriptografar quaisquer chaves privadas de certificados da máquina.

## Encontrando Arquivos de Certificado – THEFT4

Às vezes, os certificados são encontrados diretamente no sistema de arquivos, como em compartilhamentos de arquivos ou na pasta Downloads. Os tipos de arquivos de certificado mais comumente encontrados e direcionados a ambientes Windows são os arquivos `.pfx` e `.p12`. Embora com menos frequência, também aparecem arquivos com as extensões `.pkcs12` e `.pem`. Outras extensões de arquivo relacionadas a certificados que merecem atenção incluem:<sup>[[1]](#references)</sup>

- `.key` para chaves privadas,
- `.crt`/`.cer` somente para certificados,
- `.csr` para Certificate Signing Requests, que não contêm certificados nem chaves privadas,
- `.jks`/`.keystore`/`.keys` para Java Keystores, que podem conter certificados e chaves privadas utilizadas por aplicações Java.

Esses arquivos podem ser pesquisados usando PowerShell ou o prompt de comando, procurando pelas extensões mencionadas.

Quando um arquivo de certificado PKCS#12 é encontrado e protegido por uma senha, é possível extrair um hash usando o `pfx2john.py`, disponível em [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Posteriormente, o JohnTheRipper pode ser usado para tentar quebrar a senha.
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## Roubo de credenciais NTLM via PKINIT – THEFT5 (UnPAC the hash)

O conteúdo fornecido explica um método de roubo de credenciais NTLM via PKINIT, especificamente por meio do método de roubo identificado como THEFT5. A seguir, é apresentada uma reexplicação na voz passiva, com o conteúdo anonimizado e resumido quando aplicável:<sup>[[1]](#references)</sup>

Para oferecer suporte à autenticação NTLM `MS-NLMP` para aplicações que não permitem a autenticação Kerberos, o KDC é projetado para retornar a one-way function (OWF) NTLM do usuário dentro do privilege attribute certificate (PAC), especificamente no buffer `PAC_CREDENTIAL_INFO`, quando o PKCA é utilizado. Consequentemente, caso uma conta se autentique e obtenha um Ticket-Granting Ticket (TGT) protegido via PKINIT, é fornecido, de forma inerente, um mecanismo que permite ao host atual extrair o hash NTLM do TGT para manter a compatibilidade com protocolos de autenticação legados. Esse processo envolve a descriptografia da estrutura `PAC_CREDENTIAL_DATA`, que consiste essencialmente em uma representação serializada em NDR do plaintext NTLM.

O utilitário **Kekeo**, disponível em [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), é mencionado como capaz de solicitar um TGT contendo esses dados específicos, facilitando assim a recuperação do NTLM do usuário. O comando utilizado para essa finalidade é o seguinte:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** também pode obter essas informações com a opção **`asktgt [...] /getcredentials`**.

Além disso, observa-se que o Kekeo pode processar certificados protegidos por smartcard, desde que o PIN possa ser recuperado, conforme referência em [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). A mesma capacidade é indicada como compatível com o **Rubeus**, disponível em [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Esta explicação resume o processo e as ferramentas envolvidas no roubo de credenciais NTLM via PKINIT, com foco na obtenção de hashes NTLM por meio de um TGT obtido usando PKINIT e nos utilitários que facilitam esse processo.

## Referências

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
