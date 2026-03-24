# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, um diamond ticket é um TGT que pode ser usado para **acessar qualquer serviço como qualquer usuário**. Um golden ticket é forjado completamente offline, criptografado com o hash krbtgt daquele domínio, e então injetado em uma sessão de logon para uso. Como os controladores de domínio não rastreiam os TGTs que emitiram legitimamente, eles aceitarão sem problemas TGTs que sejam criptografados com o próprio hash krbtgt.

Existem duas técnicas comuns para detectar o uso de golden tickets:

- Procure por TGS-REQs que não tenham um AS-REQ correspondente.
- Procure por TGTs que tenham valores estranhos, como o lifetime padrão de 10 anos do Mimikatz.

A **diamond ticket** é criada **modificando os campos de um TGT legítimo que foi emitido por um DC**. Isso é feito solicitando um **TGT**, **descriptografando**-o com o hash krbtgt do domínio, **modificando** os campos desejados do ticket e então **recriptografando**. Isso **contorna as duas limitações mencionadas** de um golden ticket porque:

- TGS-REQs terão um AS-REQ precedente.
- O TGT foi emitido por um DC, o que significa que terá todos os detalhes corretos da política Kerberos do domínio. Embora esses detalhes possam ser forjados com precisão em um golden ticket, é mais complexo e sujeito a erros.

### Requisitos & workflow

- **Cryptographic material**: a chave krbtgt AES256 (preferida) ou o hash NTLM para descriptografar e re-assinar o TGT.
- **Legitimate TGT blob**: obtido com `/tgtdeleg`, `asktgt`, `s4u`, ou exportando tickets da memória.
- **Context data**: o RID do usuário alvo, RIDs/SIDs de grupos, e (opcionalmente) atributos PAC derivados do LDAP.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Obtenha um TGT para qualquer usuário controlado via AS-REQ (Rubeus `/tgtdeleg` é conveniente porque força o cliente a executar a troca Kerberos GSS-API sem credenciais).
2. Descriptografe o TGT retornado com a chave krbtgt e modifique os atributos PAC (usuário, grupos, informações de logon, SIDs, device claims, etc.).
3. Recriptografe/re-assine o ticket com a mesma chave krbtgt e injete-o na sessão de logon atual (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcionalmente, repita o processo sobre um service ticket fornecendo um bloco TGT válido mais a service key alvo para permanecer furtivo na rede.

### Updated Rubeus tradecraft (2024+)

Trabalho recente da Huntress modernizou a ação `diamond` dentro do Rubeus ao portar as melhorias `/ldap` e `/opsec` que antes existiam apenas para golden/silver tickets. `/ldap` agora puxa contexto PAC real consultando o LDAP **e** montando o SYSVOL para extrair atributos de conta/grupo além da política Kerberos/senha (por ex., `GptTmpl.inf`), enquanto `/opsec` faz o fluxo AS-REQ/AS-REP corresponder ao Windows ao realizar a troca de preauth em duas etapas e aplicar AES-only + KDCOptions realistas. Isso reduz dramaticamente indicadores óbvios, como campos PAC ausentes ou lifetimes incompatíveis com a política.
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) consulta o AD e o SYSVOL para espelhar os dados da política PAC do usuário alvo.
- `/opsec` força uma repetição de AS-REQ no estilo Windows, zerando flags ruidosas e mantendo AES256.
- `/tgtdeleg` mantém suas mãos longe da cleartext password ou da chave NTLM/AES da vítima, enquanto ainda retorna um TGT.

### Service-ticket recutting

A mesma atualização do Rubeus adicionou a capacidade de aplicar a diamond technique a blobs TGS. Ao fornecer ao `diamond` um **base64-encoded TGT** (from `asktgt`, `/tgtdeleg`, or a previously forged TGT), o **service SPN**, e a **service AES key**, você pode mint realistic service tickets sem tocar o KDC—efetivamente um stealthier silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Este fluxo de trabalho é ideal quando você já controla a chave de uma conta de serviço (por exemplo, extraída com `lsadump::lsa /inject` ou `secretsdump.py`) e quer criar um TGS pontual que corresponda perfeitamente à política do AD, aos prazos e aos dados do PAC sem gerar nenhum tráfego AS/TGS novo.

### Sapphire-style PAC swaps (2025)

Uma variação mais recente, às vezes chamada de **sapphire ticket**, combina a base "real TGT" do Diamond com **S4U2self+U2U** para roubar um PAC privilegiado e inseri-lo no seu próprio TGT. Em vez de inventar SIDs extras, você solicita um ticket U2U S4U2self para um usuário de alto privilégio onde o `sname` aponta para o solicitante de baixo privilégio; o KRB_TGS_REQ carrega o TGT do solicitante em `additional-tickets` e define `ENC-TKT-IN-SKEY`, permitindo que o service ticket seja descriptografado com a chave desse usuário. Você então extrai o PAC privilegiado e o incorpora no seu TGT legítimo antes de reassinar com a chave krbtgt.

O `ticketer.py` do Impacket agora traz suporte a sapphire via `-impersonate` + `-request` (live KDC exchange):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` aceita um nome de usuário ou SID; `-request` requer credenciais de usuário ativas mais material de chave krbtgt (AES/NTLM) para descriptografar/patch tickets.

Sinais-chave de OPSEC ao usar esta variante:

- TGS-REQ carregará `ENC-TKT-IN-SKEY` e `additional-tickets` (o TGT da vítima) — raro no tráfego normal.
- `sname` frequentemente é igual ao usuário solicitante (acesso self-service) e o Event ID 4769 mostra o chamador e o alvo como o mesmo SPN/usuário.
- Espere entradas pareadas 4768/4769 com o mesmo computador cliente mas CNAMES diferentes (solicitante de baixo privilégio vs. proprietário privilegiado do PAC).

### OPSEC & detection notes

- As heurísticas tradicionais de hunter (TGS sem AS, tempos de vida de décadas) ainda se aplicam a golden tickets, mas diamond tickets surgem principalmente quando o **conteúdo do PAC ou o mapeamento de grupos parece impossível**. Preencha todos os campos do PAC (logon hours, user profile paths, device IDs) para que comparações automatizadas não sinalizem imediatamente a falsificação.
- **Não atribua grupos/RIDs em excesso**. Se você só precisa de `512` (Domain Admins) e `519` (Enterprise Admins), pare por aí e certifique-se de que a conta alvo pertença plausivelmente a esses grupos em outro lugar no AD. `ExtraSids` excessivos são um sinal óbvio.
- Trocas no estilo Sapphire deixam impressões digitais U2U: `ENC-TKT-IN-SKEY` + `additional-tickets` além de um `sname` que aponta para um usuário (frequentemente o solicitante) no 4769, e um logon 4624 subsequente originado do ticket forjado. Correlacione esses campos em vez de procurar apenas lacunas de no-AS-REQ.
- Microsoft começou a phasing out **RC4 service ticket issuance** por causa do CVE-2026-20833; enforcing AES-only etypes on the KDC tanto fortalece o domínio quanto alinha com as ferramentas diamond/sapphire (/opsec já força AES). Misturar RC4 em PACs forjados ficará cada vez mais evidente.
- Splunk's Security Content project distribui telemetria de attack-range para diamond tickets além de detecções como *Windows Domain Admin Impersonation Indicator*, que correlaciona sequências incomuns de Event ID 4768/4769/4624 e mudanças de grupos no PAC. Reexecutar esse dataset (ou gerar o seu próprio com os comandos acima) ajuda a validar a cobertura do SOC para T1558.001 enquanto fornece lógica de alerta concreta para evadir.

## References

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
