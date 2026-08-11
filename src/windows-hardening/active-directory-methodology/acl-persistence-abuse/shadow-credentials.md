# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Introducción <a href="#3f17" id="3f17"></a>

**Consulta el post original para obtener [toda la información sobre esta técnica](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

En resumen, controlar el **`msDS-KeyCredentialLink`** de un usuario o equipo puede permitir a un atacante añadir una key credential, autenticarse como ese objeto con PKINIT y, cuando el KDC y la cuenta admiten los flujos necesarios, utilizar el ticket resultante con `S4U2Self`/user-to-user para recuperar el NT hash del objeto.<sup>[[1]](#references)</sup>

En el post se describe un método para configurar **credenciales de autenticación basadas en claves públicas y privadas** con el fin de adquirir un **Service Ticket** único que incluye el hash NTLM del objetivo. Este proceso implica el NTLM_SUPPLEMENTAL_CREDENTIAL cifrado dentro del Privilege Attribute Certificate (PAC), que puede descifrarse.<sup>[[1]](#references)</sup>

### Requisitos

Para aplicar esta técnica, deben cumplirse ciertas condiciones:<sup>[[1]](#references)</sup>

- Se necesita como mínimo un Domain Controller de Windows Server 2016.
- El Domain Controller debe tener instalado un certificado digital de autenticación de servidor.
- El esquema del directorio debe contener `msDS-KeyCredentialLink`; un DC de Windows Server 2016 o posterior y un certificado compatible con PKINIT en el KDC son los requisitos prácticos de plataforma descritos por la investigación. Verifica la combinación de esquema/DC del dominio en lugar de asumir que únicamente la etiqueta del nivel funcional del dominio determina la explotabilidad.
- Se requiere una cuenta con permisos delegados para modificar el atributo msDS-KeyCredentialLink del objeto objetivo.

## Abuso

El abuso de Key Trust en objetos de equipo incluye pasos adicionales a la obtención de un Ticket Granting Ticket (TGT) y el hash NTLM. Las opciones incluyen:<sup>[[1]](#references)</sup>

1. Crear un **RC4 silver ticket** para actuar como usuarios privilegiados en el host previsto.
2. Utilizar el TGT con **S4U2Self** para suplantar a **usuarios privilegiados**, lo que requiere modificar el Service Ticket para añadir una clase de servicio al nombre del servicio.

Una ventaja importante del abuso de Key Trust es que se limita a la clave privada generada por el atacante, evitando la delegación a cuentas potencialmente vulnerables y sin requerir la creación de una cuenta de equipo, que podría ser difícil de eliminar.<sup>[[1]](#references)</sup>

## Herramientas

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker utiliza DSInternals para manipular `msDS-KeyCredentialLink` desde C#. Whisker y su equivalente en Python, **pyWhisker**, admiten añadir, listar, eliminar y borrar key credentials.<sup>[[2]](#references)[[4]](#references)</sup>

Las funciones de **Whisker** incluyen:

- **Add**: Genera un par de claves y añade una key credential.
- **List**: Muestra todas las entradas de key credentials.
- **Remove**: Elimina una key credential especificada.
- **Clear**: Borra todas las key credentials, lo que puede interrumpir el uso legítimo de WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker lleva el workflow a **sistemas tipo UNIX** con Impacket y PyDSInternals, incluyendo operaciones de list/add/remove e import/export de JSON.<sup>[[4]](#references)</sup>
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray enumera objetos del dominio sobre los que el operador tiene derechos como `GenericWrite`/`GenericAll`, intenta añadir credenciales de clave ampliamente e incluye modos de limpieza/recursivos. El spraying amplio es disruptivo y llamativo; utiliza objetivos explícitos y conserva cada DeviceID añadido para una eliminación precisa.<sup>[[3]](#references)</sup>

## References

- [1] [Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Tool for taking over AD accounts by manipulating msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Tool to spray Shadow Credentials across a domain](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Python version of the Shadow Credentials tool](https://github.com/ShutdownRepo/pywhisker)
{{#include ../../../banners/hacktricks-training.md}}
