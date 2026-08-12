# SeManageVolumePrivilege: Abuso de manutenção de volumes e validação de acesso raw

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Direito de usuário do Windows: Executar tarefas de manutenção de volumes (constante: SeManageVolumePrivilege).

Esse direito autoriza operações de manutenção de volumes, como desfragmentação e criação ou remoção de volumes. A Microsoft alerta que um detentor pode conseguir estender arquivos para áreas de armazenamento que contêm outros dados e, então, ler ou modificar os bytes obtidos.<sup>[[1]](#references)</sup>

Não associe a posse de `SeManageVolumePrivilege` a um acesso raw ao disco garantido. A Microsoft documenta que abrir um disco ou volume físico por meio de `CreateFile` para acesso direto exige privilégios administrativos, e que as verificações normais de acesso a objetos/dispositivos continuam sendo aplicadas. Em uma determinada build ou produto, teste se o token, a ACL do dispositivo, o acesso solicitado, as flags de compartilhamento e o estado do volume permitem obter um handle raw antes de afirmar que é possível ler arquivos arbitrariamente.<sup>[[3]](#references)</sup>

Padrão: Administrators em servidores e controladores de domínio.<sup>[[1]](#references)</sup>

## Cenários de abuso

- Se a conta conseguir realmente obter um handle legível do volume raw, um parser compatível com NTFS poderá ignorar as ACLs por arquivo e recuperar arquivos protegidos ou bloqueados a partir de clusters alocados.
- Os possíveis alvos incluem conteúdo bloqueado ou protegido por ACL em `C:\Windows\System32`, registry hives, chaves mestras DPAPI, o SAM e, quando acessível separadamente por meio de um snapshot ou volume offline, `ntds.dit`.
- Em hosts de certificate services, locais úteis de software keys incluem `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` e `%ProgramData%\Microsoft\Crypto\Keys`; recuperar um arquivo só é útil quando o material da chave é exportável e também pode ser descriptografado.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Em um host AD CS, uma chave privada de CA **exportável e respaldada por software** recuperada com sucesso pode permitir abuso de Golden Certificate. Projetos de chaves respaldadas por hardware ou não exportáveis alteram esse caminho.<sup>[[2]](#references)</sup>

Observação: você ainda precisa de um parser para as estruturas NTFS, a menos que dependa de ferramentas auxiliares. Muitas ferramentas prontas abstraem o acesso raw.

## Técnicas práticas

- Abra um handle raw do volume e leia clusters:

<details>
<summary>Clique para expandir</summary>
```powershell
# Validation attempt: current Windows versions normally require an administrative token
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
- FTK Imager ou The Sleuth Kit (imaging somente leitura e, depois, carve de arquivos)
- vssadmin/diskshadow + shadow copy; depois, copie o arquivo-alvo do snapshot (se você puder criar VSS; geralmente requer admin, mas costuma estar disponível para os mesmos operadores que possuem SeManageVolumePrivilege)

Caminhos sensíveis típicos a serem visados:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (segredos locais)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (certificados/CRLs da CA; as chaves privadas ficam no machine key store acima)

## AD CS tie‑in: Forging a Golden Certificate

Se você puder ler a chave privada da Enterprise CA no machine key store, poderá forjar certificados de client-auth para principals arbitrários e autenticar via PKINIT/Schannel. Isso é frequentemente chamado de Golden Certificate.<sup>[[2]](#references)</sup> Consulte:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Seção: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detection and hardening

- Limite rigorosamente a atribuição de SeManageVolumePrivilege (Perform volume maintenance tasks) apenas a admins confiáveis.
- Monitore Sensitive Privilege Use e aberturas de handles de processo para objetos de dispositivo como \\.\C:, \\.\PhysicalDrive0.
- Prefira chaves de CA não exportáveis, respaldadas por HSM ou TPM e configuradas corretamente, para que um arquivo de key-container copiado não seja suficiente para recuperar material de chave privada utilizável.
- Para application secrets fora do caminho da chave da CA, DPAPI ou DPAPI-NG pode tornar um arquivo de dados copiado insuficiente, protegendo-o para um usuário, máquina, grupo ou outro principal autorizado. Isso não protege plaintext já acessível ao principal comprometido.<sup>[[4]](#references)</sup>
- Mantenha uploads, temp e caminhos de extração não executáveis e separados (uma defesa de contexto web que frequentemente acompanha esta cadeia de post‑exploitation).

## References

- [1] [Microsoft – Executar tarefas de manutenção de volume (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege usado para ler a chave da CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` physical disks and volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation and DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
