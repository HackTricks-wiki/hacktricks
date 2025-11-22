# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket é um TGT que pode ser usado para **acessar qualquer serviço como qualquer usuário**. Um golden ticket é forjado completamente offline, criptografado com o hash krbtgt daquele domínio e então injetado em uma sessão de logon para uso. Como os domain controllers não rastreiam TGTs que eles (ou eles) tenham emitido legitimamente, eles aceitarão sem problemas TGTs que estejam criptografados com seu próprio hash krbtgt.

Existem duas técnicas comuns para detectar o uso de golden tickets:

- Procurar por TGS-REQs que não tenham um AS-REQ correspondente.
- Procurar por TGTs que tenham valores absurdos, como o tempo de vida padrão de 10 anos do Mimikatz.

Um **diamond ticket** é criado ao **modificar os campos de um TGT legítimo que foi emitido por um DC**. Isso é realizado solicitando um **TGT**, **descriptografando** ele com o hash krbtgt do domínio, **modificando** os campos desejados do ticket e então **recriptografando-o**. Isso **contorna as duas limitações mencionadas** de um golden ticket porque:

- As TGS-REQs terão um AS-REQ precedendo-as.
- O TGT foi emitido por um DC, o que significa que terá todos os detalhes corretos da política Kerberos do domínio. Embora esses detalhes possam ser forjados com precisão em um golden ticket, isso é mais complexo e sujeito a erros.

### Requirements & workflow

- **Cryptographic material**: a chave krbtgt AES256 (preferida) ou o hash NTLM para descriptografar e re-assinar o TGT.
- **Legitimate TGT blob**: obtido com `/tgtdeleg`, `asktgt`, `s4u`, ou exportando tickets da memória.
- **Context data**: o RID do usuário alvo, RIDs/SIDs de grupos, e (opcionalmente) atributos PAC derivados do LDAP.
- **Service keys** (apenas se você planeja re-cut service tickets): chave AES do SPN do serviço a ser impersonado.

1. Obtenha um TGT para qualquer usuário controlado via AS-REQ (Rubeus `/tgtdeleg` é conveniente porque coagirá o cliente a executar o Kerberos GSS-API dance sem credenciais).
2. Descriptografe o TGT retornado com a chave krbtgt, faça o patch dos atributos PAC (usuário, grupos, informações de logon, SIDs, claims de dispositivo, etc.).
3. Recriptografe/assine o ticket com a mesma chave krbtgt e injete-o na sessão de logon atual (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcionalmente, repita o processo sobre um service ticket fornecendo um TGT blob válido mais a chave do serviço alvo para permanecer stealthy na rede.

### Updated Rubeus tradecraft (2024+)

Trabalhos recentes da Huntress modernizaram a ação `diamond` dentro do Rubeus ao portar as melhorias `/ldap` e `/opsec` que anteriormente existiam apenas para golden/silver tickets. `/ldap` agora autopopula atributos PAC precisos diretamente do AD (perfil do usuário, logon hours, sidHistory, políticas de domínio), enquanto `/opsec` torna o fluxo AS-REQ/AS-REP indistinguível de um Windows client ao executar a sequência de pré-autenticação em duas etapas e impor crypto apenas AES. Isso reduz dramaticamente indicadores óbvios como device IDs em branco ou janelas de validade irreais.
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
- `/ldap` (com `/ldapuser` e `/ldappassword` opcionais) consulta o AD e o SYSVOL para espelhar os dados da política PAC do usuário alvo.
- `/opsec` força uma nova tentativa AS-REQ no estilo Windows, zerando flags ruidosas e mantendo AES256.
- `/tgtdeleg` evita tocar na senha em cleartext ou na chave NTLM/AES da vítima enquanto ainda retorna um TGT descriptografável.

### Service-ticket recutting

A mesma atualização do Rubeus adicionou a capacidade de aplicar a técnica `diamond` a TGS blobs. Ao alimentar o `diamond` com um **base64-encoded TGT** (de `asktgt`, `/tgtdeleg`, ou um TGT forjado anteriormente), o **service SPN**, e a **service AES key**, você pode cunhar service tickets realistas sem tocar no KDC—efetivamente um silver ticket mais furtivo.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Este fluxo de trabalho é ideal quando você já controla a chave de uma conta de serviço (por exemplo, obtida com `lsadump::lsa /inject` ou `secretsdump.py`) e quer emitir um TGS pontual que combine perfeitamente com a política do AD, cronogramas e dados do PAC sem gerar tráfego AS/TGS novo.

### OPSEC & detection notes

- As heurísticas tradicionais de caça (TGS sem AS, tempos de vida de décadas) ainda se aplicam a golden tickets, mas diamond tickets surgem principalmente quando o **conteúdo do PAC ou o mapeamento de grupos parece impossível**. Preencha todos os campos do PAC (horários de logon, caminhos de perfil de usuário, IDs de dispositivo) para que comparações automatizadas não sinalizem imediatamente a falsificação.
- **Não atribua grupos/RIDs em excesso**. Se você só precisa de `512` (Domain Admins) e `519` (Enterprise Admins), pare por aí e certifique-se de que a conta alvo plausivelmente pertence a esses grupos em outro lugar do AD. Excessivos `ExtraSids` são um indício óbvio.
- O projeto Splunk Security Content distribui telemetria de attack-range para diamond tickets, além de detecções como *Windows Domain Admin Impersonation Indicator*, que correlaciona sequências incomuns de Event ID 4768/4769/4624 e alterações de grupos no PAC. Reexecutar esse conjunto de dados (ou gerar o seu com os comandos acima) ajuda a validar a cobertura do SOC para T1558.001 enquanto fornece lógica concreta de alerta para evadir.

## Referências

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
