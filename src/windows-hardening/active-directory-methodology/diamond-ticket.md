# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket é um TGT que pode ser usado para **acessar qualquer serviço como qualquer usuário**. A golden ticket é forjada completamente offline, criptografada com o hash krbtgt desse domínio e então inserida numa sessão de logon para uso. Como os controladores de domínio não rastreiam os TGTs que eles emitiram legitimamente, eles aceitarão de bom grado TGTs que estejam criptografados com o seu próprio hash krbtgt.

Existem duas técnicas comuns para detectar o uso de golden tickets:

- Procurar por TGS-REQs que não tenham um AS-REQ correspondente.
- Procurar por TGTs que tenham valores estranhos, como o prazo padrão de 10 anos do Mimikatz.

Um **diamond ticket** é criado ao **modificar os campos de um TGT legítimo que foi emitido por um DC**. Isso é alcançado ao **solicitar** um **TGT**, **descriptografá-lo** com o hash krbtgt do domínio, **modificar** os campos desejados do ticket e, em seguida, **recriptografá-lo**. Isso **supera as duas limitações mencionadas** de uma golden ticket porque:

- TGS-REQs terão um AS-REQ precedente.
- O TGT foi emitido por um DC, o que significa que terá todos os detalhes corretos da política Kerberos do domínio. Mesmo que esses detalhes possam ser forjados com precisão em uma golden ticket, é mais complexo e sujeito a erros.

### Requirements & workflow

- **Cryptographic material**: a chave krbtgt AES256 (preferida) ou o hash NTLM para descriptografar e re-assinar o TGT.
- **Legitimate TGT blob**: obtido com `/tgtdeleg`, `asktgt`, `s4u`, ou exportando tickets da memória.
- **Context data**: o RID do usuário alvo, RIDs/SIDs de grupos, e (opcionalmente) atributos PAC derivados do LDAP.
- **Service keys** (apenas se você planeja re-gerar service tickets): chave AES do SPN do serviço a ser personificado.

1. Obtenha um TGT para qualquer usuário controlado via AS-REQ (Rubeus `/tgtdeleg` é conveniente porque força o cliente a realizar o Kerberos GSS-API dance sem credenciais).
2. Descriptografe o TGT retornado com a chave krbtgt, altere atributos do PAC (usuário, grupos, informações de logon, SIDs, claims de dispositivo, etc.).
3. Recriptografe/assine o ticket com a mesma chave krbtgt e injete-o na sessão de logon atual (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcionalmente, repita o processo sobre um service ticket fornecendo um blob TGT válido mais a chave do serviço alvo para permanecer discreto na rede.

### Updated Rubeus tradecraft (2024+)

Trabalhos recentes da Huntress modernizaram a ação `diamond` dentro do Rubeus ao portar as melhorias `/ldap` e `/opsec` que anteriormente existiam apenas para golden/silver tickets. `/ldap` agora puxa contexto PAC real consultando o LDAP **e** montando o SYSVOL para extrair atributos de conta/grupo além da política Kerberos/senha (por exemplo, `GptTmpl.inf`), enquanto `/opsec` faz o fluxo AS-REQ/AS-REP corresponder ao Windows ao realizar a troca de preauth em duas etapas e impor AES-only + KDCOptions realistas. Isso reduz dramaticamente indicadores óbvios, como campos PAC faltantes ou durações incompatíveis com a política.
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
- `/ldap` (com opcional `/ldapuser` & `/ldappassword`) consulta o AD e o SYSVOL para espelhar os dados de política PAC do usuário alvo.
- `/opsec` força uma nova tentativa AS-REQ no estilo Windows, zerando flags ruidosas e mantendo AES256.
- `/tgtdeleg` mantém suas mãos longe do cleartext password ou NTLM/AES key da vítima enquanto ainda retorna um TGT descriptografável.

### Service-ticket recutting

A mesma atualização do Rubeus adicionou a capacidade de aplicar a diamond technique a TGS blobs. Ao fornecer ao `diamond` um **base64-encoded TGT** (de `asktgt`, `/tgtdeleg`, ou de um TGT previamente forjado), o **service SPN**, e a **service AES key**, você pode forjar service tickets realistas sem tocar no KDC — efetivamente um silver ticket mais furtivo.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Este workflow é ideal quando você já controla uma service account key (e.g., dumped with `lsadump::lsa /inject` or `secretsdump.py`) e quer criar um TGS pontual que combine perfeitamente com a política do AD, prazos e dados PAC sem emitir nenhum novo tráfego AS/TGS.

### Sapphire-style PAC swaps (2025)

Uma variação mais recente, às vezes chamada de **sapphire ticket**, combina a base "real TGT" do Diamond com **S4U2self+U2U** para roubar um PAC privilegiado e inseri-lo no seu próprio TGT. Em vez de inventar SIDs adicionais, você solicita um U2U S4U2self ticket para um usuário de alto privilégio onde o `sname` tem como alvo o solicitante de baixo privilégio; o KRB_TGS_REQ carrega o TGT do solicitante em `additional-tickets` e define `ENC-TKT-IN-SKEY`, permitindo que o service ticket seja descriptografado com a chave desse usuário. Você então extrai o PAC privilegiado e o encaixa no seu TGT legítimo antes de re-assinar com a chave krbtgt.

Impacket's `ticketer.py` now ships sapphire support via `-impersonate` + `-request` (live KDC exchange):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` aceita um username ou SID; `-request` requer credenciais de usuário ativas além do krbtgt key material (AES/NTLM) para decrypt/patch tickets.

Key OPSEC tells when using this variant:

- TGS-REQ will carry `ENC-TKT-IN-SKEY` and `additional-tickets` (the victim TGT) — raro no tráfego normal.
- `sname` often equals the requesting user (self-service access) and Event ID 4769 shows the caller and target as the same SPN/user.
- Expect paired 4768/4769 entries with the same client computer but different CNAMES (low-priv requester vs. privileged PAC owner).

### OPSEC & notas de detecção

- As heurísticas tradicionais de hunter (TGS without AS, decade-long lifetimes) ainda se aplicam aos golden tickets, mas diamond tickets aparecem principalmente quando o **conteúdo do PAC ou o mapeamento de grupos parece impossível**. Preencha todos os campos do PAC (logon hours, user profile paths, device IDs) para que comparações automatizadas não sinalizem imediatamente a falsificação.
- **Não atribua excesso de grupos/RIDs**. Se você só precisa de `512` (Domain Admins) e `519` (Enterprise Admins), pare por aí e garanta que a conta alvo pertença plausivelmente a esses grupos em algum outro lugar do AD. Excesso de `ExtraSids` é um indicativo.
- Trocas no estilo Sapphire deixam impressões digitais U2U: `ENC-TKT-IN-SKEY` + `additional-tickets` mais um `sname` que aponta para um usuário (frequentemente o solicitante) em 4769, e um logon 4624 subsequente originado do ticket forjado. Correlacione esses campos em vez de olhar apenas por lacunas no no-AS-REQ.
- A Microsoft começou a eliminar gradualmente a emissão de **RC4 service ticket issuance** por causa do CVE-2026-20833; forçar etypes AES-only no KDC tanto endurece o domínio quanto alinha com as ferramentas diamond/sapphire (/opsec já força AES). Misturar RC4 em PACs forjados vai se destacar cada vez mais.
- O projeto Splunk Security Content distribui telemetria de attack-range para diamond tickets além de detecções como *Windows Domain Admin Impersonation Indicator*, que correlaciona sequências incomuns de Event ID 4768/4769/4624 e mudanças de grupos no PAC. Reexecutar esse dataset (ou gerar o seu próprio com os comandos acima) ajuda a validar a cobertura do SOC para T1558.001 enquanto fornece lógica de alerta concreta para testar evasão.

## Referências

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
