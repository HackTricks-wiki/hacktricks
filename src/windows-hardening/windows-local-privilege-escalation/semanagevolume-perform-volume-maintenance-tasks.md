# SeManageVolumePrivilege: Acesso bruto ao volume para leitura arbitrária de arquivos

{{#include ../../banners/hacktricks-training.md}}

## Overview

Direito do usuário Windows: Executar tarefas de manutenção de volume (constante: SeManageVolumePrivilege).

Titulares podem executar operações de volume de baixo nível, como desfragmentação, criar/remover volumes e IO de manutenção. Criticamente para atacantes, esse direito permite abrir handles de dispositivo de volume bruto (por exemplo, \\.\C:) e emitir I/O direto no disco que contorna os ACLs de arquivos NTFS. Com acesso bruto você pode copiar bytes de qualquer arquivo no volume mesmo que negado pelo DACL, ao analisar as estruturas do sistema de arquivos offline ou aproveitando ferramentas que leem ao nível de bloco/cluster.

Default: Administradores em servidores e controladores de domínio.

## Abuse scenarios

- Leitura arbitrária de arquivos contornando ACLs lendo o dispositivo de disco (por exemplo, exfiltrar material sensível protegido pelo sistema como chaves privadas de máquina em %ProgramData%\Microsoft\Crypto\RSA\MachineKeys e %ProgramData%\Microsoft\Crypto\Keys, hives do registro, DPAPI masterkeys, SAM, ntds.dit via VSS, etc.).
- Contornar caminhos bloqueados/privilegiados (C:\Windows\System32\…) copiando bytes diretamente do dispositivo bruto.
- Em ambientes AD CS, exfiltrar o material de chaves da CA (machine key store) para cunhar “Golden Certificates” e se passar por qualquer principal do domínio via PKINIT. Veja o link abaixo.

Nota: Ainda é necessário um parser para as estruturas NTFS a menos que você confie em ferramentas auxiliares. Muitas ferramentas off-the-shelf abstraem o acesso bruto.

## Practical techniques

- Open a raw volume handle and read clusters:

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

- Use uma ferramenta compatível com NTFS para recuperar arquivos específicos de um volume bruto:
- RawCopy/RawCopy64 (cópia a nível de setor de arquivos em uso)
- FTK Imager or The Sleuth Kit (imagem somente leitura, then carve files)
- vssadmin/diskshadow + shadow copy, depois copie o arquivo alvo do snapshot (se você puder criar VSS; frequentemente requer admin mas comumente disponível para os mesmos operadores que possuem SeManageVolumePrivilege)

Typical sensitive paths to target:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS tie‑in: Forging a Golden Certificate

Se você conseguir ler a chave privada da Enterprise CA do machine key store, você pode forjar certificados client‑auth para entidades arbitrárias e autenticar via PKINIT/Schannel. Isso é frequentemente referido como Golden Certificate. Veja:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Seção: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detecção e hardening

- Limite fortemente a concessão da SeManageVolumePrivilege (Perform volume maintenance tasks) apenas a administradores de confiança.
- Monitore o Sensitive Privilege Use e aberturas de handles de processo para objetos de dispositivo como \\.\C:, \\.\PhysicalDrive0.
- Prefira chaves de CA com suporte HSM/TPM ou DPAPI-NG para que leituras brutas de arquivos não possam recuperar o material da chave em forma utilizável.
- Mantenha caminhos de uploads, temp e extração não-executáveis e separados (defesa em contexto web que frequentemente acompanha essa cadeia pós-exploitation).

## Referências

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
