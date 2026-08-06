# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Introducción <a href="#3f17" id="3f17"></a>

**Consulta la publicación original para obtener [toda la información sobre esta técnica](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

En **resumen**: si puedes escribir en la propiedad **msDS-KeyCredentialLink** de un usuario/equipo, puedes obtener el **hash NT del objeto**.<sup>[[1]](#references)</sup>

En la publicación se describe un método para configurar **credenciales de autenticación mediante claves pública-privada** con el fin de adquirir un **Service Ticket** único que incluye el hash NTLM del objetivo. Este proceso implica el NTLM_SUPPLEMENTAL_CREDENTIAL cifrado dentro del Privilege Attribute Certificate (PAC), que puede descifrarse.<sup>[[1]](#references)</sup>

### Requisitos

Para aplicar esta técnica, deben cumplirse ciertas condiciones:<sup>[[1]](#references)</sup>

- Se necesita al menos un Domain Controller con Windows Server 2016.
- El Domain Controller debe tener instalado un certificado digital de autenticación de servidor.
- Active Directory debe estar en el Windows Server 2016 Functional Level.
- Se requiere una cuenta con permisos delegados para modificar el atributo msDS-KeyCredentialLink del objeto objetivo.

## Abuso

El abuso de Key Trust en objetos de equipo comprende pasos adicionales a la obtención de un Ticket Granting Ticket (TGT) y del hash NTLM. Las opciones incluyen:<sup>[[1]](#references)</sup>

1. Crear un **RC4 silver ticket** para actuar como usuarios privilegiados en el host objetivo.
2. Usar el TGT con **S4U2Self** para suplantar a **usuarios privilegiados**, lo que requiere modificar el Service Ticket para añadir una clase de servicio al nombre del servicio.

Una ventaja importante del abuso de Key Trust es que se limita a la clave privada generada por el atacante, evitando la delegación a cuentas potencialmente vulnerables y sin requerir la creación de una cuenta de equipo, cuya eliminación podría ser complicada.<sup>[[1]](#references)</sup>

## Herramientas

### [**Whisker**](https://github.com/eladshamir/Whisker)

Está basado en DSInternals y proporciona una interfaz en C# para este ataque. Whisker y su equivalente en Python, **pyWhisker**, permiten manipular el atributo `msDS-KeyCredentialLink` para obtener el control de cuentas de Active Directory. Estas herramientas admiten varias operaciones, como añadir, enumerar, eliminar y borrar credenciales de clave del objeto objetivo.

Las funciones de **Whisker** incluyen:

- **Add**: Genera un par de claves y añade una credencial de clave.
- **List**: Muestra todas las entradas de credenciales de clave.
- **Remove**: Elimina una credencial de clave especificada.
- **Clear**: Borra todas las credenciales de clave, lo que puede interrumpir el uso legítimo de WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Extiende la funcionalidad de Whisker a **sistemas basados en UNIX**, aprovechando Impacket y PyDSInternals para ofrecer capacidades de explotación integrales, incluida la enumeración, adición y eliminación de KeyCredentials, así como su importación y exportación en formato JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray tiene como objetivo **explotar los permisos GenericWrite/GenericAll que grupos de usuarios amplios pueden tener sobre objetos del dominio** para aplicar ShadowCredentials de forma generalizada. Esto implica iniciar sesión en el dominio, verificar el nivel funcional del dominio, enumerar los objetos del dominio e intentar añadir KeyCredentials para obtener TGT y revelar el hash NT. Las opciones de limpieza y las tácticas de explotación recursiva aumentan su utilidad.

## Referencias

- [1] [Shadow Credentials: abusando del mapeo de cuentas Key Trust para tomar el control de cuentas](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Herramienta para tomar el control de cuentas de AD manipulando msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Herramienta para aplicar Shadow Credentials en un dominio](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Versión en Python de la herramienta Shadow Credentials](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
