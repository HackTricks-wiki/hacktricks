# SeManageVolumePrivilege: acesso ao volume bruto para leitura arbitrária de arquivos

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Direito de usuário do Windows: Executar tarefas de manutenção de volumes (constante: SeManageVolumePrivilege).

Os detentores desse direito podem executar operações de baixo nível em volumes, como desfragmentação, criação/remoção de volumes e operações de manutenção de E/S. O aspecto mais crítico para os atacantes é que esse direito permite abrir handles de dispositivos de volume bruto (por exemplo, \\.\C:) e emitir E/S direta no disco, contornando as ACLs de arquivos do NTFS. Com acesso bruto, é possível copiar os bytes de qualquer arquivo no volume mesmo quando o acesso é negado pela DACL, analisando as estruturas do sistema de arquivos offline ou utilizando ferramentas que leem no nível de blocos/clusters.

Padrão: Administrators em servidores e controladores de domínio.<sup>[[1]](#references)</sup>

## Cenários de abuso

- Leitura arbitrária de arquivos contornando ACLs por meio da leitura do dispositivo de disco (por exemplo, exfiltrar material sensível protegido pelo sistema, como chaves privadas da máquina em %ProgramData%\Microsoft\Crypto\RSA\MachineKeys e %ProgramData%\Microsoft\Crypto\Keys, hives do registro, masterkeys do DPAPI, SAM, ntds.dit via VSS etc.).
- Contornar caminhos bloqueados ou privilegiados (C:\Windows\System32\…) copiando bytes diretamente do dispositivo bruto.
- Em ambientes AD CS, exfiltrar o material de chaves da CA (repositório de chaves da máquina) para criar “Golden Certificates” e se passar por qualquer principal do domínio via PKINIT. Consulte o link abaixo.<sup>[[2]](#references)</sup>

Observação: ainda é necessário um parser para as estruturas do NTFS, a menos que você utilize ferramentas auxiliares. Muitas ferramentas prontas abstraem o acesso bruto.

## Técnicas práticas

- Abrir um handle de volume bruto e ler clusters:

<details>
<summary>Clique para expandir</summary>
```powershell
# PowerShell – read first MB from C: raw device (requires SeManageVolumePrivilege)
$fs = [System.IO.File]::Open("\\.\\C:",[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
$buf = New-Object byte[] (1MB)
$null = $fs.Read($buf,0,$buf.Length)
$fs.Close()
[IO.File]::WriteAllBytes("C:\\temp\\c_first_mb.bin", $buf)
```

```csharp
// C# (compile with Add-Type) – read an arbitrary offset of \\.\nusing System;
using System.IO;
class R {
static void Main(string[] a){
using(var fs = new FileStream("\\\\.\\C:", FileMode.Open, FileAccess.Read, FileShare.ReadWrite)){
fs.Position = 0x100000; // seek
var buf = new byte[4096];
fs.Read(buf,0,buf.Length);
File.WriteAllBytes("C:\\temp\\blk.bin", buf);
}
}
}
```
</details>

- Use uma ferramenta compatível com NTFS para recuperar arquivos específicos do volume raw:
- RawCopy/RawCopy64 (cópia em nível de setor de arquivos em uso)
- FTK Imager ou The Sleuth Kit (imaging somente leitura e, depois, carving de arquivos)
- vssadmin/diskshadow + shadow copy; depois, copie o arquivo-alvo do snapshot (se puder criar VSS; geralmente requer admin, mas costuma estar disponível para os mesmos operadores que possuem SeManageVolumePrivilege)

Caminhos sensíveis típicos a serem visados:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (segredos locais)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (certificados/CRLs da CA; as chaves privadas ficam no machine key store acima)

## Integração com AD CS: Forging a Golden Certificate

Se puder ler a chave privada da Enterprise CA no machine key store, você poderá forjar certificados de client-auth para principals arbitrários e autenticar via PKINIT/Schannel. Isso costuma ser chamado de Golden Certificate.<sup>[[2]](#references)</sup> Consulte:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Seção: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detecção e hardening

- Limite rigorosamente a atribuição de SeManageVolumePrivilege (Perform volume maintenance tasks) apenas a admins confiáveis.
- Monitore o uso de privilégios sensíveis e a abertura de handles de processos para objetos de dispositivo como \\.\C:, \\.\PhysicalDrive0.
- Prefira chaves de CA protegidas por HSM/TPM ou DPAPI-NG, para que leituras raw de arquivos não possam recuperar o material da chave em formato utilizável.
- Mantenha uploads, caminhos temporários e de extração não executáveis e separados (uma defesa no contexto web que costuma acompanhar essa cadeia de post-exploitation).

## Referências

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
