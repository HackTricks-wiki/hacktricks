# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Este é um pequeno resumo dos capítulos de persistência de máquina da pesquisa incrível de [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## **Entendendo o Roubo de Credenciais de Usuário Ativo com Certificados – PERSIST1**

Em um cenário onde um certificado que permite a autenticação de domínio pode ser solicitado por um usuário, um atacante tem a oportunidade de **solicitar** e **roubar** esse certificado para **manter a persistência** em uma rede. Por padrão, o modelo `User` no Active Directory permite tais solicitações, embora às vezes possa estar desativado.

Usando uma ferramenta chamada [**Certify**](https://github.com/GhostPack/Certify), pode-se procurar por certificados válidos que permitem acesso persistente:
```bash
Certify.exe find /clientauth
```
É destacado que o poder de um certificado reside em sua capacidade de **autenticar como o usuário** a que pertence, independentemente de quaisquer alterações de senha, desde que o certificado permaneça **válido**.

Os certificados podem ser solicitados através de uma interface gráfica usando `certmgr.msc` ou através da linha de comando com `certreq.exe`. Com **Certify**, o processo para solicitar um certificado é simplificado da seguinte forma:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Após uma solicitação bem-sucedida, um certificado junto com sua chave privada é gerado no formato `.pem`. Para converter isso em um arquivo `.pfx`, que é utilizável em sistemas Windows, o seguinte comando é utilizado:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
O arquivo `.pfx` pode então ser enviado para um sistema alvo e usado com uma ferramenta chamada [**Rubeus**](https://github.com/GhostPack/Rubeus) para solicitar um Ticket Granting Ticket (TGT) para o usuário, estendendo o acesso do atacante enquanto o certificado for **válido** (tipicamente um ano):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Um aviso importante é compartilhado sobre como essa técnica, combinada com outro método descrito na seção **THEFT5**, permite que um atacante obtenha persistentemente o **hash NTLM** de uma conta sem interagir com o Local Security Authority Subsystem Service (LSASS) e a partir de um contexto não elevado, proporcionando um método mais discreto para o roubo de credenciais a longo prazo.

## **Ganhando Persistência de Máquina com Certificados - PERSIST2**

Outro método envolve inscrever a conta de máquina de um sistema comprometido para um certificado, utilizando o modelo padrão `Machine`, que permite tais ações. Se um atacante obtiver privilégios elevados em um sistema, ele pode usar a conta **SYSTEM** para solicitar certificados, proporcionando uma forma de **persistência**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Esse acesso permite que o atacante se autentique no **Kerberos** como a conta da máquina e utilize **S4U2Self** para obter tickets de serviço do Kerberos para qualquer serviço no host, concedendo efetivamente ao atacante acesso persistente à máquina.

## **Estendendo a Persistência Através da Renovação de Certificado - PERSIST3**

O método final discutido envolve aproveitar os **períodos de validade** e **renovação** dos modelos de certificado. Ao **renovar** um certificado antes de sua expiração, um atacante pode manter a autenticação no Active Directory sem a necessidade de novas inscrições de tickets, o que poderia deixar vestígios no servidor da Autoridade Certificadora (CA).

### Renovação de Certificado com Certify 2.0

Começando com **Certify 2.0**, o fluxo de trabalho de renovação é totalmente automatizado através do novo comando `request-renew`. Dado um certificado previamente emitido (no formato **base-64 PKCS#12**), um atacante pode renová-lo sem interagir com o proprietário original – perfeito para uma persistência furtiva e de longo prazo:
```powershell
Certify.exe request-renew --ca SERVER\\CA-NAME \
--cert-pfx MIACAQMwgAYJKoZIhvcNAQcBoIAkgA...   # original PFX
```
O comando retornará um PFX novo que é válido por mais um período completo de vida, permitindo que você continue se autenticando mesmo após o primeiro certificado expirar ou ser revogado.

## Referências

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)

{{#include ../../../banners/hacktricks-training.md}}
