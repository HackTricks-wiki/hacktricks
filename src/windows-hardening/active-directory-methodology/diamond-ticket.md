# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Assim como um golden ticket**, um diamond ticket é um TGT que pode ser usado para **acessar qualquer serviço como qualquer usuário**. Um golden ticket é forjado completamente offline, criptografado com o hash krbtgt desse domínio e, em seguida, inserido em uma sessão de logon para ser usado. Como os controladores de domínio não rastreiam os TGTs que emitiram legitimamente, eles aceitam sem problemas TGTs criptografados com seu próprio hash krbtgt.<sup>[[1]](#references)</sup>

Há duas técnicas comuns para detectar o uso de golden tickets:

- Procurar TGS-REQs sem um AS-REQ correspondente.
- Procurar TGTs com valores absurdos, como o tempo de vida padrão de 10 anos do Mimikatz.

Um **diamond ticket** é criado **modificando os campos de um TGT legítimo emitido por um DC**. Isso é feito **solicitando** um **TGT**, **descriptografando-o** com o hash krbtgt do domínio, **modificando** os campos desejados do ticket e, em seguida, **criptografando-o novamente**. Isso **supera as duas limitações mencionadas anteriormente** de um golden ticket porque:<sup>[[1]](#references)</sup>

- Os TGS-REQs terão um AS-REQ anterior.
- O TGT foi emitido por um DC, o que significa que conterá todos os detalhes corretos da política Kerberos do domínio. Embora seja possível forjá-los com precisão em um golden ticket, isso é mais complexo e sujeito a erros.

### Requisitos e fluxo de trabalho

- **Material criptográfico**: a chave AES256 do krbtgt (preferencial) ou o hash NTLM para descriptografar e assinar novamente o TGT.
- **Blob de TGT legítimo**: obtido com `/tgtdeleg`, `asktgt`, `s4u` ou exportando tickets da memória.
- **Dados de contexto**: o RID do usuário-alvo, RIDs/SIDs dos grupos e, opcionalmente, atributos do PAC obtidos via LDAP.
- **Chaves de serviço** (somente se você planeja gerar novamente tickets de serviço): chave AES do SPN do serviço a ser impersonado.

1. Obtenha um TGT para qualquer usuário controlado via AS-REQ (o `/tgtdeleg` do Rubeus é conveniente porque força o cliente a executar a negociação Kerberos GSS-API sem credenciais).
2. Descriptografe o TGT retornado com a chave krbtgt e altere os atributos do PAC (usuário, grupos, informações de logon, SIDs, declarações de dispositivo etc.).
3. Criptografe/assine novamente o ticket com a mesma chave krbtgt e injete-o na sessão de logon atual (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcionalmente, repita o processo em um ticket de serviço, fornecendo um blob de TGT válido e a chave do serviço-alvo para manter a discrição na rede.

### Tradecraft atualizado do Rubeus (2024+)

Trabalhos recentes da Huntress modernizaram a ação `diamond` do Rubeus, incorporando as melhorias `/ldap` e `/opsec`, que antes só existiam para golden/silver tickets. `/ldap` agora obtém contexto real do PAC consultando o LDAP **e** montando o SYSVOL para extrair atributos de contas/grupos e políticas Kerberos/de senha (por exemplo, `GptTmpl.inf`), enquanto `/opsec` faz com que o fluxo AS-REQ/AS-REP corresponda ao do Windows, executando a troca de pré-autenticação em duas etapas e impondo somente AES + KDCOptions realistas. Isso reduz drasticamente indicadores óbvios, como campos do PAC ausentes ou tempos de vida incompatíveis com as políticas.<sup>[[3]](#references)</sup>

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

- `/ldap` (com `/ldapuser` e `/ldappassword` opcionais) consulta o AD e o SYSVOL para espelhar os dados de política do PAC do usuário-alvo.
- `/opsec` força uma nova tentativa de AS-REQ semelhante à do Windows, zerando flags ruidosas e usando apenas AES256.
- `/tgtdeleg` evita que você tenha acesso à senha em texto claro ou à chave NTLM/AES da vítima, mas ainda retorna um TGT descriptografável.

### Recriação de tickets de serviço

A mesma atualização do Rubeus adicionou a capacidade de aplicar a técnica diamond a blobs TGS. Ao fornecer a `diamond` um **TGT codificado em base64** (de `asktgt`, `/tgtdeleg` ou um TGT forjado anteriormente), o **SPN do serviço** e a **chave AES do serviço**, você pode criar tickets de serviço realistas sem tocar no KDC — na prática, um silver ticket mais furtivo.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Este workflow é ideal quando você já controla uma chave de conta de serviço (por exemplo, extraída com `lsadump::lsa /inject` ou `secretsdump.py`) e quer gerar um TGS pontual que corresponda perfeitamente à política, aos prazos e aos dados do PAC do AD, sem emitir nenhum novo tráfego AS/TGS.<sup>[[3]](#references)</sup>

### Trocas de PAC no estilo Sapphire (2025)

Uma variação mais recente, às vezes chamada de **sapphire ticket**, combina a base de "TGT real" do Diamond com **S4U2self+U2U** para roubar um PAC privilegiado e inseri-lo no seu próprio TGT. Em vez de inventar SIDs extras, você solicita um ticket S4U2self U2U para um usuário com altos privilégios, em que o `sname` aponta para o solicitante de baixo privilégio; o KRB_TGS_REQ inclui o TGT do solicitante em `additional-tickets` e define `ENC-TKT-IN-SKEY`, permitindo que o ticket de serviço seja descriptografado com a chave desse usuário. Em seguida, você extrai o PAC privilegiado e o incorpora ao seu TGT legítimo antes de reassiná-lo com a chave do krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

O `ticketer.py` do Impacket agora inclui suporte a sapphire via `-impersonate` + `-request` (troca com o KDC em tempo real):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` aceita um nome de usuário ou SID; `-request` exige credenciais ativas de usuário e material da chave krbtgt (AES/NTLM) para descriptografar/corrigir tickets.

Principais sinais de OPSEC ao usar esta variante:<sup>[[5]](#references)</sup>

- O TGS-REQ conterá `ENC-TKT-IN-SKEY` e `additional-tickets` (o TGT da vítima) — algo raro no tráfego normal.
- `sname` geralmente corresponde ao usuário solicitante (acesso self-service), e o Event ID 4769 mostra o solicitante e o alvo como o mesmo SPN/usuário.
- Espere entradas 4768/4769 pareadas com o mesmo computador cliente, mas CNAMES diferentes (solicitante com poucos privilégios vs. proprietário privilegiado do PAC).

### OPSEC e observações sobre detecção

- As heurísticas tradicionais de hunting (TGS sem AS, durações de uma década) ainda se aplicam a golden tickets, mas diamond tickets vêm à tona principalmente quando o **conteúdo do PAC ou o mapeamento de grupos parece impossível**. Preencha todos os campos do PAC (horários de logon, caminhos de perfil de usuário, IDs de dispositivo) para que comparações automatizadas não sinalizem imediatamente a falsificação.<sup>[[3]](#references)</sup>
- **Não exagere na quantidade de grupos/RIDs**. Se você precisa apenas de `512` (Domain Admins) e `519` (Enterprise Admins), pare por aí e certifique-se de que a conta de destino pertença plausivelmente a esses grupos em outros pontos do AD. Um `ExtraSids` excessivo é um indício revelador.
- Trocas no estilo Sapphire deixam rastros de U2U: `ENC-TKT-IN-SKEY` + `additional-tickets`, além de um `sname` que aponta para um usuário (geralmente o solicitante) no 4769, e um logon 4624 subsequente originado do ticket forjado. Correlacione esses campos em vez de procurar apenas lacunas de no-AS-REQ.<sup>[[5]](#references)</sup>
- A Microsoft começou a eliminar gradualmente a **emissão de tickets de serviço RC4** devido à CVE-2026-20833; impor etypes somente AES no KDC fortalece o domínio e se alinha às ferramentas de diamond/sapphire (/opsec já força AES). Misturar RC4 em PACs forjados ficará cada vez mais evidente.<sup>[[6]](#references)</sup>
- O projeto Security Content da Splunk distribui telemetria de attack-range para diamond tickets, além de detecções como *Indicador de falsificação de identidade de Domain Admin no Windows*, que correlaciona sequências incomuns de Event ID 4768/4769/4624 e alterações de grupos no PAC. Reproduzir esse conjunto de dados (ou gerar o seu próprio com os comandos acima) ajuda a validar a cobertura do SOC para T1558.001 e fornece lógica concreta de alertas para contornar.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Pedras preciosas: a nova geração de ataques Kerberos (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: adoramos brincar com tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recortando o Diamond Ticket do Kerberos (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Dados de ataque e detecções de Diamond Ticket (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – O lado sombrio das joias: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Aplicação da emissão de tickets de serviço RC4 para CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
