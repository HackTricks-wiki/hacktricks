# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introdução

### Componentes de um Certificado

- O **Sujeito** do certificado denota seu proprietário.
- Uma **Chave Pública** é emparelhada com uma chave privada para vincular o certificado ao seu legítimo proprietário.
- O **Período de Validade**, definido pelas datas **NotBefore** e **NotAfter**, marca a duração efetiva do certificado.
- Um **Número de Série** único, fornecido pela Autoridade Certificadora (CA), identifica cada certificado.
- O **Emissor** refere-se à CA que emitiu o certificado.
- **SubjectAlternativeName** permite nomes adicionais para o sujeito, aumentando a flexibilidade de identificação.
- **Basic Constraints** identificam se o certificado é para uma CA ou uma entidade final e definem restrições de uso.
- **Extended Key Usages (EKUs)** delineiam os propósitos específicos do certificado, como assinatura de código ou criptografia de e-mail, através de Identificadores de Objetos (OIDs).
- O **Algoritmo de Assinatura** especifica o método para assinar o certificado.
- A **Assinatura**, criada com a chave privada do emissor, garante a autenticidade do certificado.

### Considerações Especiais

- **Subject Alternative Names (SANs)** expandem a aplicabilidade de um certificado para múltiplas identidades, crucial para servidores com múltiplos domínios. Processos de emissão seguros são vitais para evitar riscos de impersonação por atacantes manipulando a especificação SAN.

### Autoridades Certificadoras (CAs) no Active Directory (AD)

O AD CS reconhece certificados de CA em uma floresta AD através de contêineres designados, cada um servindo a papéis únicos:

- O contêiner **Certification Authorities** contém certificados de CA raiz confiáveis.
- O contêiner **Enrolment Services** detalha CAs Empresariais e seus modelos de certificado.
- O objeto **NTAuthCertificates** inclui certificados de CA autorizados para autenticação AD.
- O contêiner **AIA (Authority Information Access)** facilita a validação da cadeia de certificados com certificados de CA intermediários e cruzados.

### Aquisição de Certificado: Fluxo de Solicitação de Certificado do Cliente

1. O processo de solicitação começa com os clientes encontrando uma CA Empresarial.
2. Um CSR é criado, contendo uma chave pública e outros detalhes, após a geração de um par de chaves pública-privada.
3. A CA avalia o CSR em relação aos modelos de certificado disponíveis, emitindo o certificado com base nas permissões do modelo.
4. Após a aprovação, a CA assina o certificado com sua chave privada e o retorna ao cliente.

### Modelos de Certificado

Definidos dentro do AD, esses modelos delineiam as configurações e permissões para emissão de certificados, incluindo EKUs permitidos e direitos de inscrição ou modificação, críticos para gerenciar o acesso aos serviços de certificado.

## Inscrição de Certificado

O processo de inscrição para certificados é iniciado por um administrador que **cria um modelo de certificado**, que é então **publicado** por uma Autoridade Certificadora Empresarial (CA). Isso torna o modelo disponível para a inscrição do cliente, um passo alcançado ao adicionar o nome do modelo ao campo `certificatetemplates` de um objeto do Active Directory.

Para que um cliente solicite um certificado, **direitos de inscrição** devem ser concedidos. Esses direitos são definidos por descritores de segurança no modelo de certificado e na própria CA Empresarial. As permissões devem ser concedidas em ambos os locais para que uma solicitação seja bem-sucedida.

### Direitos de Inscrição do Modelo

Esses direitos são especificados através de Entradas de Controle de Acesso (ACEs), detalhando permissões como:

- Direitos de **Certificate-Enrollment** e **Certificate-AutoEnrollment**, cada um associado a GUIDs específicos.
- **ExtendedRights**, permitindo todas as permissões estendidas.
- **FullControl/GenericAll**, fornecendo controle total sobre o modelo.

### Direitos de Inscrição da CA Empresarial

Os direitos da CA são delineados em seu descritor de segurança, acessível através do console de gerenciamento da Autoridade Certificadora. Algumas configurações até permitem que usuários com privilégios baixos tenham acesso remoto, o que pode ser uma preocupação de segurança.

### Controles Adicionais de Emissão

Certos controles podem se aplicar, como:

- **Aprovação do Gerente**: Coloca solicitações em um estado pendente até serem aprovadas por um gerente de certificado.
- **Agentes de Inscrição e Assinaturas Autorizadas**: Especificam o número de assinaturas necessárias em um CSR e os OIDs de Política de Aplicação necessários.

### Métodos para Solicitar Certificados

Os certificados podem ser solicitados através de:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), através de pipes nomeados ou TCP/IP.
3. A **interface web de inscrição de certificados**, com o papel de Web Enrollment da Autoridade Certificadora instalado.
4. O **Serviço de Inscrição de Certificado** (CES), em conjunto com o serviço de Política de Inscrição de Certificado (CEP).
5. O **Serviço de Inscrição de Dispositivos de Rede** (NDES) para dispositivos de rede, usando o Protocolo Simples de Inscrição de Certificado (SCEP).

Usuários do Windows também podem solicitar certificados via GUI (`certmgr.msc` ou `certlm.msc`) ou ferramentas de linha de comando (`certreq.exe` ou o comando `Get-Certificate` do PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticação por Certificado

Active Directory (AD) suporta autenticação por certificado, utilizando principalmente os protocolos **Kerberos** e **Secure Channel (Schannel)**.

### Processo de Autenticação Kerberos

No processo de autenticação Kerberos, o pedido de um usuário para um Ticket Granting Ticket (TGT) é assinado usando a **chave privada** do certificado do usuário. Este pedido passa por várias validações pelo controlador de domínio, incluindo a **validade** do certificado, **caminho** e **status de revogação**. As validações também incluem verificar se o certificado vem de uma fonte confiável e confirmar a presença do emissor no **NTAUTH certificate store**. Validações bem-sucedidas resultam na emissão de um TGT. O objeto **`NTAuthCertificates`** no AD, encontrado em:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
é central para estabelecer confiança na autenticação de certificados.

### Autenticação de Canal Seguro (Schannel)

Schannel facilita conexões seguras TLS/SSL, onde durante um handshake, o cliente apresenta um certificado que, se validado com sucesso, autoriza o acesso. O mapeamento de um certificado para uma conta AD pode envolver a função **S4U2Self** do Kerberos ou o **Subject Alternative Name (SAN)** do certificado, entre outros métodos.

### Enumeração de Serviços de Certificado AD

Os serviços de certificado do AD podem ser enumerados através de consultas LDAP, revelando informações sobre **Autoridades de Certificação (CAs) Empresariais** e suas configurações. Isso é acessível por qualquer usuário autenticado no domínio sem privilégios especiais. Ferramentas como **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** são usadas para enumeração e avaliação de vulnerabilidades em ambientes AD CS.

Os comandos para usar essas ferramentas incluem:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
---

## Vulnerabilidades Recentes & Atualizações de Segurança (2022-2025)

| Ano | ID / Nome | Impacto | Principais Conclusões |
|-----|-----------|---------|----------------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Escalação de privilégios* ao falsificar certificados de conta de máquina durante o PKINIT. | O patch está incluído nas atualizações de segurança de **10 de maio de 2022**. Controles de auditoria e mapeamento forte foram introduzidos via **KB5014754**; os ambientes devem agora estar em modo *Full Enforcement*. citeturn2search0 |
| 2023 | **CVE-2023-35350 / 35351** | *Execução remota de código* nos papéis de Inscrição da Web do AD CS (certsrv) e CES. | PoCs públicos são limitados, mas os componentes vulneráveis do IIS estão frequentemente expostos internamente. Patch a partir de **julho de 2023** Patch Tuesday. citeturn3search0 |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Usuários com privilégios baixos e direitos de inscrição poderiam substituir **qualquer** EKU ou SAN durante a geração de CSR, emitindo certificados utilizáveis para autenticação de cliente ou assinatura de código, levando a *comprometimento de domínio*. | Abordado nas atualizações de **abril de 2024**. Remover “Supply in the request” dos templates e restringir permissões de inscrição. citeturn1search3 |

### Cronograma de endurecimento da Microsoft (KB5014754)

A Microsoft introduziu um rollout em três fases (Compatibilidade → Auditoria → Aplicação) para mover a autenticação de certificados Kerberos para longe de mapeamentos implícitos fracos. A partir de **11 de fevereiro de 2025**, controladores de domínio alternam automaticamente para **Full Enforcement** se o valor de registro `StrongCertificateBindingEnforcement` não estiver definido. Os administradores devem:

1. Aplicar patches em todos os DCs e servidores AD CS (maio de 2022 ou posterior).
2. Monitorar o ID do Evento 39/41 para mapeamentos fracos durante a fase de *Auditoria*.
3. Reemitir certificados de autenticação de cliente com a nova **extensão SID** ou configurar mapeamentos manuais fortes antes de fevereiro de 2025. citeturn2search0

---

## Detecção & Melhorias de Endurecimento

* O **Defender for Identity AD CS sensor (2023-2024)** agora apresenta avaliações de postura para ESC1-ESC8/ESC11 e gera alertas em tempo real, como *“Emissão de certificado de controlador de domínio para um não-DC”* (ESC8) e *“Impedir Inscrição de Certificado com Políticas de Aplicação arbitrárias”* (ESC15). Certifique-se de que os sensores estão implantados em todos os servidores AD CS para se beneficiar dessas detecções. citeturn5search0
* Desative ou restrinja rigorosamente a opção **“Supply in the request”** em todos os templates; prefira valores SAN/EKU definidos explicitamente.
* Remova **Any Purpose** ou **No EKU** dos templates, a menos que absolutamente necessário (aborda cenários ESC2).
* Exija **aprovação do gerente** ou fluxos de trabalho dedicados de Agente de Inscrição para templates sensíveis (por exemplo, WebServer / CodeSigning).
* Restringir a inscrição na web (`certsrv`) e os endpoints CES/NDES a redes confiáveis ou atrás da autenticação de certificado de cliente.
* Aplicar criptografia de inscrição RPC (`certutil –setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQ`) para mitigar ESC11.

---

## Referências

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
