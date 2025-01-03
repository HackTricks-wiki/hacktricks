# Certificados

{{#include ../banners/hacktricks-training.md}}

## O que é um Certificado

Um **certificado de chave pública** é uma ID digital usada em criptografia para provar que alguém possui uma chave pública. Ele inclui os detalhes da chave, a identidade do proprietário (o sujeito) e uma assinatura digital de uma autoridade confiável (o emissor). Se o software confia no emissor e a assinatura é válida, a comunicação segura com o proprietário da chave é possível.

Os certificados são emitidos principalmente por [autoridades certificadoras](https://en.wikipedia.org/wiki/Certificate_authority) (CAs) em uma [infraestrutura de chave pública](https://en.wikipedia.org/wiki/Public-key_infrastructure) (PKI). Outro método é a [rede de confiança](https://en.wikipedia.org/wiki/Web_of_trust), onde os usuários verificam diretamente as chaves uns dos outros. O formato comum para certificados é [X.509](https://en.wikipedia.org/wiki/X.509), que pode ser adaptado para necessidades específicas conforme descrito na RFC 5280.

## Campos Comuns x509

### **Campos Comuns em Certificados x509**

Em certificados x509, vários **campos** desempenham papéis críticos na garantia da validade e segurança do certificado. Aqui está uma análise desses campos:

- **Número da Versão** significa a versão do formato x509.
- **Número de Série** identifica exclusivamente o certificado dentro do sistema de uma Autoridade Certificadora (CA), principalmente para rastreamento de revogação.
- O **Campo Subject** representa o proprietário do certificado, que pode ser uma máquina, um indivíduo ou uma organização. Inclui identificação detalhada, como:
- **Nome Comum (CN)**: Domínios cobertos pelo certificado.
- **País (C)**, **Localidade (L)**, **Estado ou Província (ST, S ou P)**, **Organização (O)** e **Unidade Organizacional (OU)** fornecem detalhes geográficos e organizacionais.
- **Nome Distinto (DN)** encapsula a identificação completa do sujeito.
- **Emissor** detalha quem verificou e assinou o certificado, incluindo subcampos semelhantes ao Subject para a CA.
- O **Período de Validade** é marcado por timestamps **Not Before** e **Not After**, garantindo que o certificado não seja usado antes ou depois de uma certa data.
- A seção **Chave Pública**, crucial para a segurança do certificado, especifica o algoritmo, tamanho e outros detalhes técnicos da chave pública.
- As **extensões x509v3** aprimoram a funcionalidade do certificado, especificando **Uso de Chave**, **Uso de Chave Estendida**, **Nome Alternativo do Sujeito** e outras propriedades para ajustar a aplicação do certificado.

#### **Uso de Chave e Extensões**

- **Uso de Chave** identifica aplicações criptográficas da chave pública, como assinatura digital ou criptografia de chave.
- **Uso de Chave Estendida** restringe ainda mais os casos de uso do certificado, por exemplo, para autenticação de servidor TLS.
- **Nome Alternativo do Sujeito** e **Restrição Básica** definem nomes de host adicionais cobertos pelo certificado e se é um certificado CA ou de entidade final, respectivamente.
- Identificadores como **Identificador de Chave do Sujeito** e **Identificador de Chave da Autoridade** garantem a singularidade e rastreabilidade das chaves.
- **Acesso à Informação da Autoridade** e **Pontos de Distribuição de CRL** fornecem caminhos para verificar a CA emissora e checar o status de revogação do certificado.
- **SCTs de Pré-certificado CT** oferecem logs de transparência, cruciais para a confiança pública no certificado.
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **Diferença entre OCSP e Pontos de Distribuição CRL**

**OCSP** (**RFC 2560**) envolve um cliente e um respondedor trabalhando juntos para verificar se um certificado digital de chave pública foi revogado, sem a necessidade de baixar o **CRL** completo. Este método é mais eficiente do que o tradicional **CRL**, que fornece uma lista de números de série de certificados revogados, mas requer o download de um arquivo potencialmente grande. Os CRLs podem incluir até 512 entradas. Mais detalhes estão disponíveis [aqui](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm).

### **O que é Transparência de Certificado**

A Transparência de Certificado ajuda a combater ameaças relacionadas a certificados, garantindo que a emissão e a existência de certificados SSL sejam visíveis para proprietários de domínios, CAs e usuários. Seus objetivos são:

- Prevenir que CAs emitam certificados SSL para um domínio sem o conhecimento do proprietário do domínio.
- Estabelecer um sistema de auditoria aberto para rastrear certificados emitidos por engano ou maliciosamente.
- Proteger os usuários contra certificados fraudulentos.

#### **Registros de Certificado**

Registros de certificado são registros auditáveis publicamente, apenas para adição, de certificados, mantidos por serviços de rede. Esses registros fornecem provas criptográficas para fins de auditoria. Tanto as autoridades de emissão quanto o público podem enviar certificados para esses registros ou consultá-los para verificação. Embora o número exato de servidores de registro não seja fixo, espera-se que seja inferior a mil globalmente. Esses servidores podem ser gerenciados de forma independente por CAs, ISPs ou qualquer entidade interessada.

#### **Consulta**

Para explorar os registros de Transparência de Certificado para qualquer domínio, visite [https://crt.sh/](https://crt.sh).

Existem diferentes formatos para armazenar certificados, cada um com seus próprios casos de uso e compatibilidade. Este resumo cobre os principais formatos e fornece orientações sobre como converter entre eles.

## **Formatos**

### **Formato PEM**

- Formato mais amplamente utilizado para certificados.
- Requer arquivos separados para certificados e chaves privadas, codificados em Base64 ASCII.
- Extensões comuns: .cer, .crt, .pem, .key.
- Principalmente usado por Apache e servidores similares.

### **Formato DER**

- Um formato binário de certificados.
- Não possui as declarações "BEGIN/END CERTIFICATE" encontradas em arquivos PEM.
- Extensões comuns: .cer, .der.
- Frequentemente usado com plataformas Java.

### **Formato P7B/PKCS#7**

- Armazenado em Base64 ASCII, com extensões .p7b ou .p7c.
- Contém apenas certificados e certificados de cadeia, excluindo a chave privada.
- Suportado pelo Microsoft Windows e Java Tomcat.

### **Formato PFX/P12/PKCS#12**

- Um formato binário que encapsula certificados de servidor, certificados intermediários e chaves privadas em um único arquivo.
- Extensões: .pfx, .p12.
- Principalmente usado no Windows para importação e exportação de certificados.

### **Convertendo Formatos**

**Conversões PEM** são essenciais para compatibilidade:

- **x509 para PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEM para DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DER para PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **PEM para P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **PKCS7 para PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Conversões PFX** são cruciais para gerenciar certificados no Windows:

- **PFX para PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX para PKCS#8** envolve duas etapas:
1. Converter PFX para PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Converter PEM para PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B para PFX** também requer dois comandos:
1. Converter P7B para CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Converter CER e Chave Privada para PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
- **Edição ASN.1 (DER/PEM)** (funciona com certificados ou quase qualquer outra estrutura ASN.1):
1. Clone [asn1template](https://github.com/wllm-rbnt/asn1template/)
```bash
git clone https://github.com/wllm-rbnt/asn1template.git
```
2. Converter DER/PEM para o formato de geração do OpenSSL
```bash
asn1template/asn1template.pl certificatename.der > certificatename.tpl
asn1template/asn1template.pl -p certificatename.pem > certificatename.tpl
```
3. Edite certificatename.tpl de acordo com suas necessidades
```bash
vim certificatename.tpl
```
4. Reconstruir o certificado modificado
```bash
openssl asn1parse -genconf certificatename.tpl -out certificatename_new.der
openssl asn1parse -genconf certificatename.tpl -outform PEM -out certificatename_new.pem
```
---

{{#include ../banners/hacktricks-training.md}}
