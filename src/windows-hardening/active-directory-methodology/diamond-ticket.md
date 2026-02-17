# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- Look for TGS-REQs that have no corresponding AS-REQ.
- Look for TGTs that have silly values, such as Mimikatz's default 10-year lifetime.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. This is achieved by **requesting** a **TGT**, **decrypting** it with the domain's krbtgt hash, **modifying** the desired fields of the ticket, then **re-encrypting it**. This **overcomes the two aforementioned shortcomings** of a golden ticket because:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. Even though these can be accurately forged in a golden ticket, it's more complex and open to mistakes.

### Requisitos & fluxo de trabalho

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Obtain a TGT for any controlled user via AS-REQ (Rubeus `/tgtdeleg` is convenient because it coerces the client to perform the Kerberos GSS-API dance without credentials).
2. Decrypt the returned TGT with the krbtgt key, patch PAC attributes (user, groups, logon info, SIDs, device claims, etc.).
3. Re-encrypt/sign the ticket with the same krbtgt key and inject it into the current logon session (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optionally, repeat the process over a service ticket by supplying a valid TGT blob plus the target service key to stay stealthy on the wire.

### Tradecraft atualizado do Rubeus (2024+)

Recent work by Huntress modernized the `diamond` action inside Rubeus by porting the `/ldap` and `/opsec` improvements that previously only existed for golden/silver tickets. `/ldap` now auto-populates accurate PAC attributes straight from AD (user profile, logon hours, sidHistory, domain policies), while `/opsec` makes the AS-REQ/AS-REP flow indistinguishable from a Windows client by performing the two-step pre-auth sequence and enforcing AES-only crypto. This dramatically reduces obvious indicators such as blank device IDs or unrealistic validity windows.
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
- `/ldap` (com `/ldapuser` e `/ldappassword` opcionais) consulta o AD e o SYSVOL para espelhar os dados de política PAC do usuário alvo.
- `/opsec` força uma tentativa AS-REQ no estilo Windows, zerando flags ruidosas e aderindo a AES256.
- `/tgtdeleg` mantém suas mãos longe da senha em texto claro ou da chave NTLM/AES da vítima, enquanto ainda retorna um TGT descriptografável.

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
Esse fluxo de trabalho é ideal quando você já controla a chave de uma conta de serviço (por exemplo, obtida com `lsadump::lsa /inject` ou `secretsdump.py`) e deseja criar um TGS pontual que corresponda perfeitamente à política do AD, aos prazos e aos dados do PAC sem gerar novo tráfego AS/TGS.

### Sapphire-style PAC swaps (2025)

Uma variação mais recente, às vezes chamada de **sapphire ticket**, combina a base "real TGT" do Diamond com **S4U2self+U2U** para roubar um PAC privilegiado e inseri-lo no seu próprio TGT. Em vez de inventar SIDs extras, você solicita um ticket U2U S4U2self para um usuário de alto privilégio, extrai esse PAC e o emenda no seu TGT legítimo antes de re-assinar com a chave krbtgt. Como U2U define `ENC-TKT-IN-SKEY`, o fluxo na rede resultante parece uma troca legítima entre usuários.

Reprodução mínima no Linux com o `ticketer.py` modificado do Impacket (adiciona suporte a sapphire):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333' \
--u2u --s4u2self
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
Principais indicadores de OPSEC ao usar esta variante:

- TGS-REQ carregará `ENC-TKT-IN-SKEY` e `additional-tickets` (o TGT da vítima) — raro no tráfego normal.
- `sname` frequentemente é igual ao usuário solicitante (acesso self-service) e o Event ID 4769 mostra o chamador e o alvo como o mesmo SPN/usuário.
- Espere entradas pareadas 4768/4769 com o mesmo computador cliente, mas CNAMES diferentes (requerente de baixo privilégio vs. dono privilegiado do PAC).

### OPSEC & detection notes

- As heurísticas tradicionais dos hunters (TGS sem AS, durações de décadas) ainda se aplicam aos golden tickets, mas diamond tickets surgem principalmente quando o **conteúdo do PAC ou o mapeamento de grupos parece impossível**. Preencha todos os campos do PAC (horários de logon, caminhos de perfil de usuário, IDs de dispositivo) para que comparações automatizadas não sinalizem imediatamente a falsificação.
- **Do not oversubscribe groups/RIDs**. Se você só precisa de `512` (Domain Admins) e `519` (Enterprise Admins), pare aí e confirme que a conta alvo pertence plausivelmente a esses grupos em outro lugar no AD. `ExtraSids` excessivos são uma evidência.
- Trocas estilo Sapphire deixam impressões digitais U2U: `ENC-TKT-IN-SKEY` + `additional-tickets` + `sname == cname` em 4769, e um logon 4624 subsequente originado do ticket forjado. Correlacione esses campos em vez de apenas procurar lacunas no no-AS-REQ.
- A Microsoft começou a eliminar a **emissão de service tickets RC4** por causa do CVE-2026-20833; forçar etypes somente AES no KDC tanto endurece o domínio quanto alinha com as ferramentas diamond/sapphire (/opsec já força AES). Misturar RC4 em PACs forjados vai se destacar cada vez mais.
- O projeto Security Content da Splunk distribui telemetria de attack-range para diamond tickets além de detecções como *Windows Domain Admin Impersonation Indicator*, que correlaciona sequências incomuns de Event ID 4768/4769/4624 e alterações de grupos no PAC. Re-executar esse dataset (ou gerar o seu com os comandos acima) ajuda a validar a cobertura do SOC para T1558.001 enquanto fornece lógica de alerta concreta para evadir.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
