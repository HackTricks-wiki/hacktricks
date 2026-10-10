# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Como um golden ticket**, um diamond ticket é um TGT que pode ser usado para **acessar qualquer serviço como qualquer usuário**. Um golden ticket é completamente forjado offline, criptografado com o hash krbtgt desse domínio e, em seguida, inserido em uma sessão de logon para ser usado. Como os controladores de domínio não rastreiam os TGTs que emitiram legitimamente, eles aceitam sem problemas TGTs criptografados com seu próprio hash krbtgt.<sup>[[1]](#references)</sup>

Há duas técnicas comuns para detectar o uso de golden tickets:

- Procurar TGS-REQs sem um AS-REQ correspondente.
- Procurar TGTs com valores absurdos, como a validade padrão de 10 anos do Mimikatz.

Um **diamond ticket** é criado **modificando os campos de um TGT legítimo emitido por um DC**. Isso é feito **solicitando** um **TGT**, **descriptografando-o** com o hash krbtgt do domínio, **modificando** os campos desejados do ticket e, em seguida, **criptografando-o novamente**. Isso **supera as duas limitações mencionadas anteriormente** de um golden ticket porque:<sup>[[1]](#references)</sup>

- Os TGS-REQs terão um AS-REQ anterior.
- O TGT foi emitido por um DC, o que significa que terá todos os detalhes corretos da política Kerberos do domínio. Embora seja possível falsificar esses dados com precisão em um golden ticket, isso é mais complexo e sujeito a erros.

### Requisitos e fluxo de trabalho

- **Material criptográfico**: a chave krbtgt AES256 (preferencial) ou o hash NTLM, para descriptografar e assinar novamente o TGT.
- **Blob de TGT legítimo**: obtido com `/tgtdeleg`, `asktgt`, `s4u` ou exportando tickets da memória.
- **Dados de contexto**: RID do usuário-alvo, RIDs/SIDs dos grupos e atributos PAC derivados do LDAP (opcionalmente).
- **Chaves de serviço** (somente se você planeja gerar novamente tickets de serviço): chave AES do SPN do serviço a ser personificado.

1. Obtenha um TGT para qualquer usuário controlado por meio de AS-REQ (o `/tgtdeleg` do Rubeus é conveniente porque força o cliente a realizar a troca Kerberos GSS-API sem credenciais).
2. Descriptografe o TGT retornado com a chave krbtgt e ajuste os atributos PAC (usuário, grupos, informações de logon, SIDs, declarações de dispositivo etc.).
3. Criptografe/assine novamente o ticket com a mesma chave krbtgt e injete-o na sessão de logon atual (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcionalmente, repita o processo com um ticket de serviço, fornecendo um blob de TGT válido e a chave do serviço-alvo, para permanecer furtivo na rede.

### Técnicas atualizadas do Rubeus (2024+)

Trabalhos recentes da Huntress modernizaram a ação `diamond` do Rubeus, portando as melhorias `/ldap` e `/opsec`, que antes só existiam para golden/silver tickets. `/ldap` agora obtém contexto PAC real consultando o LDAP **e** montando o SYSVOL para extrair atributos de contas/grupos e a política Kerberos/de senhas (por exemplo, `GptTmpl.inf`), enquanto `/opsec` faz com que o fluxo AS-REQ/AS-REP corresponda ao do Windows, realizando a troca de preautenticação em duas etapas e impondo somente AES e valores KDCOptions realistas. Isso reduz drasticamente indicadores óbvios, como campos PAC ausentes ou validades incompatíveis com a política.<sup>[[3]](#references)</sup>

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
- `/tgtdeleg` evita que você tenha contato com a senha em texto claro ou com a chave NTLM/AES da vítima, mas ainda retorna um TGT que pode ser descriptografado.

### Reemissão de tickets de serviço

A mesma atualização do Rubeus adicionou a capacidade de aplicar a técnica diamond a blobs TGS. Ao fornecer a `diamond` um **TGT codificado em base64** (de `asktgt`, `/tgtdeleg` ou um TGT forjado anteriormente), o **SPN do serviço** e a **chave AES do serviço**, você pode gerar tickets de serviço realistas sem interagir com o KDC — na prática, um silver ticket mais furtivo.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Este fluxo de trabalho é ideal quando você já controla uma chave de conta de serviço (por exemplo, obtida com `lsadump::lsa /inject` ou `secretsdump.py`) e quer emitir um TGS pontual que corresponda perfeitamente à política do AD, às linhas do tempo e aos dados do PAC, sem gerar nenhum tráfego AS/TGS novo.<sup>[[3]](#references)</sup>

### Trocas de PAC no estilo Sapphire (2025)

Uma variação mais recente, às vezes chamada de **sapphire ticket**, combina a base de "TGT real" do Diamond com **S4U2self+U2U** para roubar um PAC privilegiado e inseri-lo no seu próprio TGT. Em vez de inventar SIDs extras, você solicita um ticket S4U2self U2U para um usuário com altos privilégios, em que o `sname` aponta para o solicitante com poucos privilégios; o KRB_TGS_REQ inclui o TGT do solicitante em `additional-tickets` e define `ENC-TKT-IN-SKEY`, permitindo que o ticket de serviço seja descriptografado com a chave desse usuário. Em seguida, você extrai o PAC privilegiado e o insere no seu TGT legítimo antes de reassiná-lo com a chave krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

O `ticketer.py` do Impacket agora oferece suporte a sapphire com `-impersonate` + `-request` (troca ao vivo com o KDC):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` aceita um nome de usuário ou SID; `-request` exige credenciais ativas de usuário e material de chave do krbtgt (AES/NTLM) para descriptografar/corrigir tickets.

Principais sinais de OPSEC ao usar esta variante:<sup>[[5]](#references)</sup>

- TGS-REQ carregará `ENC-TKT-IN-SKEY` e `additional-tickets` (o TGT da vítima) — algo raro no tráfego normal.
- `sname` geralmente é igual ao usuário solicitante (acesso self-service), e o Event ID 4769 mostra o chamador e o alvo como o mesmo SPN/usuário.
- Espere entradas 4768/4769 emparelhadas com o mesmo computador cliente, mas CNAMES diferentes (solicitante com poucos privilégios vs. proprietário privilegiado do PAC).

### Notas de OPSEC e detecção

- As heurísticas tradicionais de hunting (TGS sem AS, lifetimes de uma década) ainda se aplicam aos golden tickets, mas os diamond tickets aparecem principalmente quando o **conteúdo do PAC ou o mapeamento de grupos parece impossível**. Preencha todos os campos do PAC (horários de logon, caminhos de perfil do usuário, IDs de dispositivo) para que as comparações automatizadas não sinalizem imediatamente a falsificação.<sup>[[3]](#references)</sup>
- **Não exagere na quantidade de grupos/RIDs**. Se você só precisa de `512` (Domain Admins) e `519` (Enterprise Admins), pare por aí e certifique-se de que a conta-alvo pertença plausivelmente a esses grupos em algum outro lugar do AD. `ExtraSids` em excesso é um sinal de alerta.
- Swaps no estilo Sapphire deixam rastros de U2U: `ENC-TKT-IN-SKEY` + `additional-tickets`, além de um `sname` que aponta para um usuário (geralmente o solicitante) no 4769 e um logon 4624 subsequente originado do ticket forjado. Correlacione esses campos em vez de procurar apenas lacunas de no-AS-REQ.<sup>[[5]](#references)</sup>
- A Microsoft começou a eliminar gradualmente a **emissão de tickets de serviço RC4** devido à CVE-2026-20833; impor etypes exclusivamente AES no KDC fortalece o domínio e se alinha às ferramentas diamond/sapphire (/opsec já força AES). Misturar RC4 em PACs forjados ficará cada vez mais evidente.<sup>[[6]](#references)</sup>
- O projeto Security Content da Splunk distribui telemetria de attack-range para diamond tickets, além de deteções como *Windows Domain Admin Impersonation Indicator*, que correlaciona sequências incomuns de Event ID 4768/4769/4624 e alterações nos grupos PAC. Reproduzir esse conjunto de dados (ou gerar o seu próprio com os comandos acima) ajuda a validar a cobertura do SOC para T1558.001 e fornece lógica de alerta concreta para evadir.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
