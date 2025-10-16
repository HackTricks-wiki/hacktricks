# SeManageVolumePrivilege: Acesso bruto ao volume para leitura arbitrária de arquivos

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Direito de usuário do Windows: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

Titulares podem executar operações de volume de baixo nível, como desfragmentação, criação/remoção de volumes e I/O de manutenção. Criticamente para atacantes, esse direito permite abrir handles de dispositivo de volume bruto (por exemplo, \\.\C:) e emitir I/O de disco direto que contorna as ACLs do NTFS. Com acesso bruto você pode copiar bytes de qualquer arquivo no volume mesmo se negado pela DACL, analisando as estruturas do sistema de arquivos offline ou usando ferramentas que leem no nível de bloco/cluster.

Padrão: Administradores em servidores e controladores de domínio.

## Cenários de abuso

- Leitura arbitrária de arquivos contornando ACLs ao ler o dispositivo de disco (por exemplo, exfiltrate material sensível protegido do sistema como chaves privadas de máquina em %ProgramData%\Microsoft\Crypto\RSA\MachineKeys e %ProgramData%\Microsoft\Crypto\Keys, registry hives, DPAPI masterkeys, SAM, ntds.dit via VSS, etc.).
- Contornar caminhos bloqueados/privilegiados (C:\Windows\System32\…) copiando bytes diretamente do dispositivo bruto.
- Em ambientes AD CS, exfiltrate o material de chave da CA (machine key store) para forjar “Golden Certificates” e se passar por qualquer principal do domínio via PKINIT. Veja o link abaixo.

Nota: Você ainda precisa de um parser para as estruturas NTFS a menos que confie em ferramentas auxiliares. Muitas ferramentas prontas abstraem o acesso bruto.

## Técnicas práticas

- Abra um handle de volume bruto e leia clusters:

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

- Use uma ferramenta com suporte a NTFS para recuperar arquivos específicos do volume bruto:
- RawCopy/RawCopy64 (cópia ao nível de setor de arquivos em uso)
- FTK Imager or The Sleuth Kit (criação de imagem somente leitura, depois carve files)
- vssadmin/diskshadow + shadow copy, então copie o arquivo alvo a partir do snapshot (se você puder criar VSS; frequentemente requer admin, mas comumente disponível para os mesmos operadores que detêm SeManageVolumePrivilege)

Typical sensitive paths to target:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS tie‑in: Forging a Golden Certificate

If you can read the Enterprise CA’s private key from the machine key store, you can forge client‑auth certificates for arbitrary principals and authenticate via PKINIT/Schannel. This is often referred to as a Golden Certificate. See:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detecção e hardening

- Limitar fortemente a atribuição de SeManageVolumePrivilege (Perform volume maintenance tasks) apenas a administradores confiáveis.
- Monitorar Sensitive Privilege Use e aberturas de handle de processo para objetos de dispositivo como \\.\C:, \\.\PhysicalDrive0.
- Preferir chaves de CA com suporte HSM/TPM ou DPAPI-NG para que leituras brutas de arquivos não possam recuperar material de chave em forma utilizável.
- Manter paths de uploads, temp e extração não executáveis e separados (defesa em contexto web que frequentemente se combina com esta cadeia post‑exploitation).

## Referências

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
