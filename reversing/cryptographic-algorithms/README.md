# Algoritmos Criptográficos/Compresión

## Algoritmos Criptográficos/Compresión

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red de HackTricks en AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Identificación de Algoritmos

Si te encuentras con un código **que utiliza desplazamientos a la derecha e izquierda, xors y varias operaciones aritméticas**, es altamente probable que sea la implementación de un **algoritmo criptográfico**. Aquí se mostrarán algunas formas de **identificar el algoritmo utilizado sin necesidad de revertir cada paso**.

### Funciones de API

**CryptDeriveKey**

Si se utiliza esta función, puedes encontrar qué **algoritmo se está utilizando** verificando el valor del segundo parámetro:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Consulta aquí la tabla de algoritmos posibles y sus valores asignados: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Comprime y descomprime un búfer de datos dado.

**CryptAcquireContext**

Desde [la documentación](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): La función **CryptAcquireContext** se utiliza para adquirir un identificador para un contenedor de clave particular dentro de un proveedor de servicios criptográficos (CSP) específico. **Este identificador devuelto se utiliza en llamadas a funciones de CryptoAPI** que utilizan el CSP seleccionado.

**CryptCreateHash**

Inicia el proceso de hash de un flujo de datos. Si se utiliza esta función, puedes encontrar qué **algoritmo se está utilizando** verificando el valor del segundo parámetro:

![](<../../.gitbook/assets/image (376).png>)

\
Consulta aquí la tabla de algoritmos posibles y sus valores asignados: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Constantes de Código

A veces es muy fácil identificar un algoritmo gracias al hecho de que necesita usar un valor especial y único.

![](<../../.gitbook/assets/image (370).png>)

Si buscas la primera constante en Google, esto es lo que obtienes:

![](<../../.gitbook/assets/image (371).png>)

Por lo tanto, puedes asumir que la función decompilada es un **calculador sha256**.\
Puedes buscar cualquiera de las otras constantes y obtendrás (probablemente) el mismo resultado.

### Información de Datos

Si el código no tiene ninguna constante significativa, puede estar **cargando información de la sección .data**.\
Puedes acceder a esos datos, **agrupar el primer dword** y buscarlo en Google como hemos hecho en la sección anterior:

![](<../../.gitbook/assets/image (372).png>)

En este caso, si buscas **0xA56363C6** puedes encontrar que está relacionado con las **tablas del algoritmo AES**.

## RC4 **(Cifrado Simétrico)**

### Características

Está compuesto por 3 partes principales:

* **Etapa de Inicialización/**: Crea una **tabla de valores de 0x00 a 0xFF** (256 bytes en total, 0x100). Esta tabla se llama comúnmente **Caja de Sustitución** (o SBox).
* **Etapa de Mezcla**: Recorrerá la tabla creada anteriormente (bucle de 0x100 iteraciones, nuevamente) modificando cada valor con bytes **semialeatorios**. Para crear estos bytes semialeatorios, se utiliza la **clave RC4**. Las claves de RC4 pueden tener **entre 1 y 256 bytes de longitud**, sin embargo, generalmente se recomienda que sea superior a 5 bytes. Comúnmente, las claves de RC4 tienen una longitud de 16 bytes.
* **Etapa XOR**: Finalmente, el texto plano o cifrado se **XORea con los valores creados anteriormente**. La función para cifrar y descifrar es la misma. Para esto, se realizará un **bucle a través de los 256 bytes creados** tantas veces como sea necesario. Esto suele reconocerse en un código decompilado con un **%256 (módulo 256)**.

{% hint style="info" %}
**Para identificar un RC4 en un código de desensamblado/decompilado, puedes buscar 2 bucles de tamaño 0x100 (con el uso de una clave) y luego un XOR de los datos de entrada con los 256 valores creados anteriormente en los 2 bucles, probablemente usando un %256 (módulo 256)**
{% endhint %}

### **Etapa de Inicialización/Caja de Sustitución:** (Observa el número 256 utilizado como contador y cómo se escribe un 0 en cada lugar de los 256 caracteres)

![](<../../.gitbook/assets/image (377).png>)

### **Etapa de Mezcla:**

![](<../../.gitbook/assets/image (378).png>)

### **Etapa XOR:**

![](<../../.gitbook/assets/image (379).png>)

## **AES (Cifrado Simétrico)**

### **Características**

* Uso de **cajas de sustitución y tablas de búsqueda**
* Es posible **distinguir AES gracias al uso de valores específicos de tablas de búsqueda** (constantes). _Ten en cuenta que la **constante** puede estar **almacenada** en el binario **o creada**_ _**dinámicamente**._
* La **clave de cifrado** debe ser **divisible** por **16** (generalmente 32B) y generalmente se utiliza un **IV** de 16B.

### Constantes de SBox

![](<../../.gitbook/assets/image (380).png>)

## Serpent **(Cifrado Simétrico)**

### Características

* Es raro encontrar malware que lo utilice, pero hay ejemplos (Ursnif)
* Es fácil determinar si un algoritmo es Serpent o no basándose en su longitud (función extremadamente larga)

### Identificación

En la siguiente imagen, observa cómo se utiliza la constante **0x9E3779B9** (nota que esta constante también se utiliza en otros algoritmos criptográficos como **TEA** -Tiny Encryption Algorithm).\
También observa el **tamaño del bucle** (**132**) y el **número de operaciones XOR** en las instrucciones de **desensamblado** y en el **ejemplo de código**:

![](<../../.gitbook/assets/image (381).png>)

Como se mencionó anteriormente, este código puede visualizarse dentro de cualquier decompilador como una **función muy larga** ya que **no hay saltos** dentro de ella. El código decompilado puede verse así:

![](<../../.gitbook/assets/image (382).png>)

Por lo tanto, es posible identificar este algoritmo verificando el **número mágico** y los **XORs iniciales**, viendo una **función muy larga** y **comparando** algunas **instrucciones** de la función larga **con una implementación** (como el desplazamiento a la izquierda por 7 y la rotación a la izquierda por 22).

## RSA **(Cifrado Asimétrico)**

### Características

* Más complejo que los algoritmos simétricos
* ¡No hay constantes! (las implementaciones personalizadas son difíciles de determinar)
* KANAL (un analizador criptográfico) no muestra pistas sobre RSA ya que se basa en constantes.

### Identificación mediante comparaciones

![](<../../.gitbook/assets/image (383).png>)

* En la línea 11 (izquierda) hay un `+7) >> 3` que es igual a la línea 35 (derecha): `+7) / 8`
* La línea 12 (izquierda) está verificando si `modulus_len < 0x040` y en la línea 36 (derecha) está verificando si `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Características

* 3 funciones: Inicializar, Actualizar, Finalizar
* Funciones de inicialización similares

### Identificación

**Inicializar**

Puedes identificar ambos verificando las constantes. Ten en cuenta que sha\_init tiene 1 constante que MD5 no tiene:

![](<../../.gitbook/assets/image (385).png>)

**Transformación de MD5**

Observa el uso de más constantes

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (hash)

* Más pequeño y más eficiente ya que su función es encontrar cambios accidentales en los datos
* Utiliza tablas de búsqueda (por lo que puedes identificar constantes)

### Identificación

Verifica las **constantes de la tabla de búsqueda**:

![](<../../.gitbook/assets/image (387).png>)

Un algoritmo de hash CRC se ve así:

![](<../../.gitbook/assets/image (386).png>)

## APLib (Compresión)

### Características

* Constantes no reconocibles
* Puedes intentar escribir el algoritmo en Python y buscar cosas similares en línea

### Identificación

El gráfico es bastante grande:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Verifica **3 comparaciones para reconocerlo**:

![](<../../.gitbook/assets/image (384).png>)

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red de HackTricks en AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
