# Informações em Impressoras

{{#include ../../banners/hacktricks-training.md}}

Há vários blogs na Internet que **destacam os perigos de deixar impressoras configuradas com LDAP usando credenciais de logon padrão/fracas**.  \
Isso ocorre porque um atacante poderia **enganar a impressora para que ela se autentique em um servidor LDAP rogue** (normalmente, um `nc -vv -l -p 389` ou `slapd -d 2` é suficiente) e capturar as **credenciais da impressora em texto claro**.

Além disso, várias impressoras conterão **logs com nomes de usuário** ou poderão até mesmo ser capazes de **baixar todos os nomes de usuário** do Domain Controller.

Todas essas **informações sensíveis** e a comum **falta de segurança** tornam as impressoras muito interessantes para atacantes.

Alguns blogs introdutórios sobre o tema:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Configuração da Impressora

- **Localização**: A lista de servidores LDAP geralmente é encontrada na interface web (por exemplo, *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Comportamento**: Muitos servidores web incorporados permitem modificações no servidor LDAP **sem inserir novamente as credenciais** (recurso de usabilidade → risco de segurança).
- **Exploit**: Redirecione o endereço do servidor LDAP para um host controlado pelo atacante e use o botão *Test Connection* / *Address Book Sync* para forçar a impressora a fazer bind com você.

---

## Captura de Credenciais

### Método 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
MFPs pequenas/antigas podem enviar um *simple-bind* em texto claro que o netcat consegue capturar. Dispositivos modernos geralmente realizam primeiro uma consulta anônima e, em seguida, tentam o bind, portanto os resultados variam.<sup>[[1]](#references)</sup>

### Método 2 – Servidor LDAP Rogue completo (recomendado)

Como muitos dispositivos realizam uma busca anônima *antes* da autenticação, configurar um daemon LDAP real produz resultados muito mais confiáveis:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Quando a impressora realizar a consulta, você verá as credenciais em texto claro na saída de debug.

> 💡  Você também pode usar `impacket/examples/ldapd.py` (Python rogue LDAP) ou `Responder -w -r -f` para coletar hashes NTLMv2 via LDAP/SMB.

---

## Vulnerabilidades recentes de Pass-Back (2024-2025)

Pass-back *não* é um problema teórico – os vendors continuam publicando avisos em 2024/2025 que descrevem exatamente essa classe de ataque.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 das MFPs Xerox VersaLink C70xx permitia que um administrador autenticado (ou qualquer pessoa quando as credenciais padrão permaneciam ativas) pudesse:

* **CVE-2024-12510 – LDAP pass-back**: alterar o endereço do servidor LDAP e acionar uma consulta, fazendo com que o dispositivo desse leak das credenciais Windows configuradas para o host controlado pelo atacante.
* **CVE-2024-12511 – SMB/FTP pass-back**: problema idêntico via destinos de *scan-to-folder*, dando leak de credenciais NetNTLMv2 ou FTP em texto claro.<sup>[[2]](#references)</sup>

Um listener simples, como:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
ou um rogue SMB server (`impacket-smbserver`) é suficiente para coletar as credenciais.

### Canon imageRUNNER / imageCLASS – Aviso de 20 de maio de 2025

A Canon confirmou uma falha de **SMTP/LDAP pass-back** em dezenas de linhas de produtos Laser & MFP. Um atacante com acesso administrativo pode modificar a configuração do servidor e recuperar as credenciais armazenadas para LDAP **ou** SMTP (muitas organizações usam uma conta privilegiada para permitir o recurso scan-to-mail).<sup>[[3]](#references)</sup>

A orientação do fornecedor recomenda explicitamente:

1. Atualizar para o firmware corrigido assim que estiver disponível.
2. Usar senhas administrativas fortes e exclusivas.
3. Evitar contas privilegiadas do AD para a integração da impressora.

---

## Ferramentas de Enumeração / Exploitation Automatizadas

| Ferramenta | Finalidade | Exemplo |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abuso de PostScript/PJL/PCL, acesso ao sistema de arquivos, verificação de credenciais padrão, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Coleta de configuração (incluindo catálogos de endereços e credenciais LDAP) via HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Captura e relay de hashes NetNTLM de pass-back via SMB/FTP | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Serviço LDAP rogue leve para receber binds em texto claro | `python ldapd.py -debug` |

---

## Hardening e Detecção

1. **Aplicar patches / atualizar o firmware** das MFPs prontamente (verifique os boletins PSIRT do fornecedor).
2. **Contas de Serviço com Mínimo Privilégio** – nunca use Domain Admin para LDAP/SMB/SMTP; restrinja o acesso a escopos de OU *somente leitura*.
3. **Restringir o Acesso de Gerenciamento** – coloque as interfaces web/IPP/SNMP da impressora em uma VLAN de gerenciamento ou atrás de uma ACL/VPN.
4. **Desabilitar Protocolos Não Utilizados** – FTP, Telnet, raw-9100 e cifras SSL antigas.
5. **Habilitar o Registro de Auditoria** – alguns dispositivos podem enviar falhas de LDAP/SMTP para o syslog; correlacione binds inesperados.
6. **Monitorar binds LDAP em texto claro** de origens incomuns (normalmente, as impressoras devem se comunicar apenas com DCs).
7. **SNMPv3 ou desabilitar o SNMP** – a community `public` frequentemente faz leak da configuração do dispositivo e do LDAP.

---

## References

- [1] [It's just a printer… What's the worst that could happen?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack Vulnerabilities (Fixed)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Vulnerability Mitigation/Remediation for Production Printers, Office/Small Office Multifunction Printers and Laser Printers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtaining Domain Credentials through a Printer with Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting Multifunction Printers During A Penetration Test Engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

{{#include ../../banners/hacktricks-training.md}}
