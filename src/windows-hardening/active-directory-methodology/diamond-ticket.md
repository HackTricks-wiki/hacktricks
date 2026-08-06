# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Assim como um golden ticket**, um diamond ticket é um TGT que pode ser usado para **acessar qualquer serviço como qualquer usuário**. Um golden ticket é forjado completamente offline, criptografado com o hash krbtgt desse domínio e então passado para uma sessão de logon para ser usado. Como os controladores de domínio não rastreiam os TGTs que emitiram legitimamente, eles aceitarão prontamente TGTs criptografados com seu próprio hash krbtgt.<sup>[[1]](#references)</sup>

Há duas técnicas comuns para detectar o uso de golden tickets:

- Procurar TGS-REQs que não tenham um AS-REQ correspondente.
- Procurar TGTs que tenham valores absurdos, como o tempo de vida padrão de 10 anos do Mimikatz.

Um **diamond ticket** é criado **modificando os campos de um TGT legítimo emitido por um DC**. Isso é obtido **solicitando** um **TGT**, **descriptografando-o** com o hash krbtgt do domínio, **modificando** os campos desejados do ticket e então **criptografando-o novamente**. Isso **supera as duas limitações mencionadas anteriormente** de um golden ticket porque:<sup>[[1]](#references)</sup>

- Os TGS-REQs terão um AS-REQ precedente.
- O TGT foi emitido por um DC, o que significa que terá todos os detalhes corretos da política Kerberos do domínio. Embora esses detalhes possam ser forjados com precisão em um golden ticket, isso é mais complexo e sujeito a erros.

### Requisitos e fluxo de trabalho

- **Material criptográfico**: a chave AES256 do krbtgt (preferencial) ou o hash NTLM para descriptografar e assinar novamente o TGT.
- **Blob de TGT legítimo**: obtido com `/tgtdeleg`, `asktgt`, `s4u` ou exportando tickets da memória.
- **Dados de contexto**: o RID do usuário-alvo, RIDs/SIDs de grupos e, opcionalmente, atributos PAC derivados do LDAP.
- **Chaves de serviço** (somente se você planeja gerar novamente service tickets): a chave AES do SPN do serviço a ser impersonado.

1. Obtenha um TGT para qualquer usuário controlado via AS-REQ (o `/tgtdeleg` do Rubeus é conveniente porque força o cliente a executar o fluxo GSS-API do Kerberos sem credenciais).
2. Descriptografe o TGT retornado com a chave krbtgt, corrija os atributos do PAC (usuário, grupos, informações de logon, SIDs, device claims etc.).
3. Criptografe/assine novamente o ticket com a mesma chave krbtgt e injete-o na sessão de logon atual (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcionalmente, repita o processo com um service ticket fornecendo um blob de TGT válido e a chave do serviço-alvo para permanecer stealthy no tráfego.

### Tradecraft atualizado do Rubeus (2024+)

Trabalhos recentes da Huntress modernizaram a action `diamond` dentro do Rubeus ao portar as melhorias `/ldap` e `/opsec`, que anteriormente existiam apenas para golden/silver tickets. O `/ldap` agora obtém o contexto PAC real consultando o LDAP **e** montando o SYSVOL para extrair atributos de conta/grupo e a política Kerberos/de senhas (por exemplo, `GptTmpl.inf`), enquanto o `/opsec` faz com que o fluxo AS-REQ/AS-REP corresponda ao Windows, executando a troca de preautenticação em duas etapas e impondo AES-only + KDCOptions realistas. Isso reduz drasticamente indicadores óbvios, como campos PAC ausentes ou tempos de vida incompatíveis com a política.<sup>[[3]](#references)</sup>
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
- `/ldap` (com `/ldapuser` e `/ldappassword` opcionais) consulta o AD e o SYSVOL para espelhar os dados da política PAC do usuário-alvo.
- `/opsec` força uma nova tentativa de AS-REQ semelhante à do Windows, zerando flags ruidosas e usando apenas AES256.
- `/tgtdeleg` evita o uso da senha em texto claro ou da chave NTLM/AES da vítima, mas ainda retorna um TGT descriptografável.

### Recutting de service-ticket

A mesma atualização do Rubeus adicionou a capacidade de aplicar a diamond technique a blobs TGS. Ao fornecer ao `diamond` um **TGT codificado em base64** (de `asktgt`, `/tgtdeleg` ou de um TGT forjado anteriormente), o **SPN do serviço** e a **chave AES do serviço**, você pode criar service tickets realistas sem interagir com o KDC — efetivamente, um silver ticket mais furtivo.<sup>[[3]](#references)</sup>
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Este workflow é ideal quando você já controla uma chave de conta de serviço (por exemplo, obtida com `lsadump::lsa /inject` ou `secretsdump.py`) e quer gerar um TGS único que corresponda perfeitamente à política do AD, às linhas do tempo e aos dados do PAC, sem emitir nenhum novo tráfego AS/TGS.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

Uma nova variação, às vezes chamada de **sapphire ticket**, combina a base de **"real TGT"** do Diamond com **S4U2self+U2U** para roubar um PAC privilegiado e inseri-lo no seu próprio TGT. Em vez de inventar SIDs adicionais, você solicita um ticket U2U S4U2self para um usuário com altos privilégios, em que o `sname` aponta para o solicitante de baixo privilégio; o KRB_TGS_REQ inclui o TGT do solicitante em `additional-tickets` e define `ENC-TKT-IN-SKEY`, permitindo que o service ticket seja descriptografado com a chave desse usuário. Em seguida, você extrai o PAC privilegiado e o insere no seu TGT legítimo antes de assiná-lo novamente com a chave do krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

O `ticketer.py` do Impacket agora oferece suporte a sapphire por meio de `-impersonate` + `-request` (live KDC exchange):<sup>[[2]](#references)[[5]](#references)</sup>
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` aceita um username ou SID; `-request` exige credenciais de usuário ativas e material de chave do krbtgt (AES/NTLM) para descriptografar/aplicar patches nos tickets.

Principais indicadores de OPSEC ao usar esta variante:<sup>[[5]](#references)</sup>

- O TGS-REQ carregará `ENC-TKT-IN-SKEY` e `additional-tickets` (o TGT da vítima) — algo raro no tráfego normal.
- `sname` geralmente é igual ao usuário solicitante (acesso self-service), e o Event ID 4769 mostra o chamador e o alvo como o mesmo SPN/usuário.
- Espere entradas 4768/4769 pareadas com o mesmo computador cliente, mas com CNAMES diferentes (solicitante de baixo privilégio vs. proprietário privilegiado do PAC).

### Notas de OPSEC e detecção

- As heurísticas tradicionais de hunting (TGS sem AS, durações de décadas) ainda se aplicam aos golden tickets, mas os diamond tickets aparecem principalmente quando o **conteúdo do PAC ou o mapeamento de grupos parece impossível**. Preencha todos os campos do PAC (horários de logon, caminhos de perfil do usuário, IDs de dispositivos) para que comparações automatizadas não sinalizem imediatamente a falsificação.<sup>[[3]](#references)</sup>
- **Não inscreva grupos/RIDs em excesso**. Se você precisa apenas de `512` (Domain Admins) e `519` (Enterprise Admins), pare aí e certifique-se de que a conta-alvo pertença plausivelmente a esses grupos em outras partes do AD. O uso excessivo de `ExtraSids` é um forte indicador.
- Swaps no estilo Sapphire deixam fingerprints de U2U: `ENC-TKT-IN-SKEY` + `additional-tickets`, além de um `sname` que aponta para um usuário (geralmente o solicitante) no 4769, e um logon 4624 subsequente originado do ticket forjado. Correlacione esses campos em vez de procurar apenas lacunas de no-AS-REQ.<sup>[[5]](#references)</sup>
- A Microsoft começou a eliminar gradualmente a **emissão de service tickets RC4** por causa da CVE-2026-20833; impor etypes somente AES no KDC tanto fortalece o domínio quanto se alinha às ferramentas de diamond/sapphire (`/opsec` já força AES). Misturar RC4 em PACs forjados ficará cada vez mais evidente.<sup>[[6]](#references)</sup>
- O projeto Security Content da Splunk distribui telemetria do attack-range para diamond tickets, além de detecções como *Windows Domain Admin Impersonation Indicator*, que correlacionam sequências incomuns de Event IDs 4768/4769/4624 e alterações nos grupos do PAC. Reproduzir esse dataset (ou gerar o seu próprio com os comandos acima) ajuda a validar a cobertura do SOC para T1558.001, ao mesmo tempo que fornece uma lógica concreta de alertas para evadir.<sup>[[4]](#references)</sup>

## Referências

- [1] [Palo Alto Unit 42 – Precious Gemstones: A Nova Geração de Ataques Kerberos (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: Adoramos Manipular Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Dados e detecções de ataques com Diamond Ticket (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Imposição de service tickets RC4 para CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
