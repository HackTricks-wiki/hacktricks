# SeManageVolumePrivilege: Abuso da manutenção de volumes e validação de acesso bruto

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Direito de usuário do Windows: Executar tarefas de manutenção de volumes (constante: SeManageVolumePrivilege).

Esse direito autoriza operações de manutenção de volumes, como desfragmentar e criar ou remover volumes. A Microsoft alerta que quem detém esse direito pode conseguir estender arquivos para áreas de armazenamento que contenham outros dados e, em seguida, ler ou modificar os bytes obtidos.<sup>[[1]](#references)</sup>

Não equipare a posse de `SeManageVolumePrivilege` à garantia de acesso bruto ao disco. A Microsoft documenta que abrir um disco ou volume físico por meio de `CreateFile` para acesso direto exige privilégios administrativos, e que as verificações normais de acesso a objetos/dispositivos continuam se aplicando. Em uma build ou produto específico, teste se o token, a ACL do dispositivo, o acesso solicitado, os sinalizadores de compartilhamento e o estado do volume permitem obter um handle bruto antes de afirmar que é possível ler qualquer arquivo.<sup>[[3]](#references)</sup>

Padrão: Administrators em servidores e controladores de domínio.<sup>[[1]](#references)</sup>

## Cenários de abuso

- Se a conta realmente conseguir obter um handle legível para o volume bruto, um parser compatível com NTFS pode contornar as ACLs por arquivo e recuperar arquivos protegidos ou bloqueados a partir de clusters alocados.
- Os possíveis alvos incluem conteúdo bloqueado ou protegido por ACL em `C:\Windows\System32`, hives do registro, chaves mestras do DPAPI, o SAM e — quando acessível separadamente por meio de um snapshot ou volume offline — `ntds.dit`.
- Em hosts de serviços de certificados, locais úteis para chaves de software incluem `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` e `%ProgramData%\Microsoft\Crypto\Keys`; recuperar um arquivo só é útil quando o material da chave é exportável e também pode ser descriptografado.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Em um host AD CS, uma chave privada de CA **exportável e baseada em software** recuperada com sucesso pode permitir o abuso de Golden Certificate. Projetos com chaves baseadas em hardware ou não exportáveis alteram esse caminho.<sup>[[2]](#references)</sup>
- Algumas ferramentas de manutenção de volumes usam `FSCTL_SD_GLOBAL_CHANGE` para substituir entradas de ACL do sistema de arquivos quando essa operação é permitida. Isso altera os controles de acesso, em vez de ler passivamente blocos brutos, pode afetar uma grande parte do volume e precisa ser validado em relação ao token e ao comportamento real do dispositivo. O [código-fonte da ferramenta](https://github.com/CsEnox/SeManageVolumeExploit) mostra esse mecanismo específico; a posse do privilégio, por si só, não prova que ele terá sucesso.
- Obter acesso a arquivos por meio de alterações nas ACLs não descriptografa um arquivo criptografado com EFS. Para obter o texto simples, ainda é necessária uma chave privada correspondente do usuário ou de recuperação. Da mesma forma, exportar uma chave de CA baseada em software com [`certutil -exportPFX`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) depende de a chave estar disponível localmente, ser exportável e estar acessível.

Observação: você ainda precisa de um parser para as estruturas NTFS, a menos que use ferramentas auxiliares. Muitas ferramentas prontas abstraem o acesso bruto.

## Técnicas práticas

- Abrir um handle para o volume bruto e ler clusters:

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

- Use uma ferramenta compatível com NTFS para recuperar arquivos específicos de um volume bruto:
  - RawCopy/RawCopy64 (cópia em nível de setor de arquivos em uso)
  - FTK Imager ou The Sleuth Kit (criação de imagem somente leitura e, em seguida, extração de arquivos)
  - vssadmin/diskshadow + cópia de sombra e, em seguida, copie o arquivo desejado do snapshot (se você puder criar VSS; geralmente isso requer admin, mas costuma estar disponível para os mesmos operadores que têm SeManageVolumePrivilege)

Caminhos sensíveis típicos a serem visados:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (segredos locais)
- C:\Windows\NTDS\ntds.dit (controladores de domínio – via cópia de sombra)
- C:\Windows\System32\CertSrv\CertEnroll\ (certificados/CRLs da CA; as chaves privadas ficam no armazenamento de chaves da máquina acima)

## Relação com AD CS: Forging a Golden Certificate

Se você puder ler a chave privada da Enterprise CA no armazenamento de chaves da máquina, poderá forjar certificados de autenticação de cliente para principais arbitrários e autenticar via PKINIT/Schannel. Isso costuma ser chamado de Golden Certificate.<sup>[[2]](#references)</sup> Consulte:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Seção: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detecção e hardening

- Limite rigorosamente a atribuição de SeManageVolumePrivilege (Perform volume maintenance tasks) apenas a admins confiáveis.
- Monitore o uso de privilégios sensíveis e a abertura de handles de processos para objetos de dispositivo como \\.\C:, \\.\PhysicalDrive0.
- Prefira chaves de CA não exportáveis, respaldadas por HSM ou TPM e configuradas corretamente, para que um arquivo de contêiner de chave copiado não seja suficiente para recuperar material de chave privada utilizável.
- Para segredos de aplicativos fora do caminho da chave da CA, DPAPI ou DPAPI-NG podem fazer com que um arquivo de dados copiado seja insuficiente, protegendo-o para um usuário, máquina, grupo ou outro principal autorizado. Isso não protege texto simples já acessível ao principal comprometido.<sup>[[4]](#references)</sup>
- Mantenha os caminhos de upload, temporários e de extração não executáveis e separados (uma defesa no contexto web que costuma complementar essa cadeia após a exploração).

## References

- [1] [Microsoft – Executar tarefas de manutenção de volume (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege usado para ler a chave da CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` para discos físicos e volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - API de criptografia: Next Generation e DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
