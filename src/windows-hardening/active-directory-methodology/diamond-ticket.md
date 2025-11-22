# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket é um TGT que pode ser usado para **acessar qualquer serviço como qualquer usuário**. Um golden ticket é forjado completamente offline, criptografado com o hash krbtgt desse domínio, e então inserido em uma sessão de logon para uso. Como os domain controllers não rastreiam os TGTs que emitiram legitimamente, eles aceitarão sem problemas TGTs que estejam criptografados com seu próprio hash krbtgt.

Existem duas técnicas comuns para detectar o uso de golden tickets:

- Procurar por TGS-REQs que não tenham um AS-REQ correspondente.
- Procurar por TGTs que tenham valores estranhos, como a validade padrão de 10 anos do Mimikatz.

Um **diamond ticket** é criado modificando os campos de um TGT legítimo que foi emitido por um DC. Isso é alcançado solicitando um TGT, descriptografando-o com o hash krbtgt do domínio, modificando os campos desejados do ticket e então re-encriptando-o. Isso **supera as duas limitações mencionadas** do golden ticket porque:

- TGS-REQs terão um AS-REQ precedente.
- O TGT foi emitido por um DC, o que significa que terá todos os detalhes corretos segundo a política Kerberos do domínio. Embora esses detalhes possam ser forjados com precisão em um golden ticket, isso é mais complexo e sujeito a erros.

### Requisitos e fluxo de trabalho

- **Materiais criptográficos**: a chave krbtgt AES256 (preferida) ou o hash NTLM para descriptografar e re-assinar o TGT.
- **Blob de TGT legítimo**: obtido com `/tgtdeleg`, `asktgt`, `s4u`, ou exportando tickets da memória.
- **Dados de contexto**: o RID do usuário alvo, RIDs/SIDs de grupos, e (opcionalmente) atributos PAC derivados do LDAP.
- **Service keys** (apenas se planejar recriar service tickets): chave AES do SPN do serviço a ser impersonado.

1. Obtenha um TGT para qualquer usuário controlado via AS-REQ (Rubeus `/tgtdeleg` é conveniente porque força o cliente a executar a sequência Kerberos GSS-API sem credenciais).
2. Descriptografe o TGT retornado com a chave krbtgt, altere os atributos PAC (usuário, grupos, informações de logon, SIDs, device claims, etc.).
3. Re-encripte/re-assine o ticket com a mesma chave krbtgt e injete-o na sessão de logon atual (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcionalmente, repita o processo sobre um service ticket fornecendo um blob de TGT válido mais a chave do serviço alvo para manter-se furtivo na rede.

### Atualizações no tradecraft do Rubeus (2024+)

Trabalhos recentes da Huntress modernizaram a ação `diamond` dentro do Rubeus ao portar as melhorias `/ldap` e `/opsec` que antes existiam apenas para golden/silver tickets. O `/ldap` agora preenche automaticamente atributos PAC precisos diretamente do AD (perfil do usuário, horas de logon, sidHistory, políticas de domínio), enquanto `/opsec` torna o fluxo AS-REQ/AS-REP indistinguível de um cliente Windows ao executar a sequência de pre-auth em duas etapas e impor criptografia somente AES. Isso reduz drasticamente indicadores óbvios como device IDs em branco ou janelas de validade irreais.
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
.\Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (com `/ldapuser` e `/ldappassword` opcionais) consulta o AD e o SYSVOL para espelhar os dados de política PAC do usuário alvo.
- `/opsec` força uma tentativa AS-REQ no estilo Windows, zerando flags ruidosos e mantendo AES256.
- `/tgtdeleg` mantém suas mãos fora do cleartext password ou NTLM/AES key da vítima enquanto ainda retorna um TGT descriptografável.

### Service-ticket recutting

The same Rubeus refresh added the ability to apply the diamond technique to TGS blobs. By feeding `diamond` a **base64-encoded TGT** (from `asktgt`, `/tgtdeleg`, or a previously forged TGT), the **service SPN**, and the **service AES key**, you can mint realistic service tickets without touching the KDC—effectively a stealthier silver ticket.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Este fluxo de trabalho é ideal quando você já controla uma chave de service account (por exemplo, obtida com `lsadump::lsa /inject` ou `secretsdump.py`) e quer criar um TGS pontual que corresponda perfeitamente à política do AD, timelines e dados do PAC sem emitir tráfego AS/TGS adicional.

### OPSEC & detection notes

- As heurísticas tradicionais de detecção (TGS without AS, decade-long lifetimes) ainda se aplicam a golden tickets, mas diamond tickets surgem principalmente quando o **conteúdo do PAC ou o mapeamento de grupos parece impossível**. Preencha todos os campos do PAC (logon hours, user profile paths, device IDs) para que comparações automatizadas não sinalizem a falsificação imediatamente.
- **Não atribua grupos/RIDs em excesso**. Se você precisa apenas de `512` (Domain Admins) e `519` (Enterprise Admins), pare por aí e verifique se a conta alvo plausivelmente pertence a esses grupos em outro lugar no AD. Excessivo `ExtraSids` é uma denúncia.
- Splunk's Security Content project distribui attack-range telemetry para diamond tickets além de detecções como *Windows Domain Admin Impersonation Indicator*, que correlaciona sequências incomuns de Event ID 4768/4769/4624 e alterações de grupos no PAC. Reproduzir esse conjunto de dados (ou gerar o seu próprio com os comandos acima) ajuda a validar a cobertura do SOC para T1558.001, além de fornecer lógica de alerta concreta para evadir.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
