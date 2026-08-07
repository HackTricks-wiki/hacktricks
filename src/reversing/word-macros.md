# Word Macros

{{#include ../banners/hacktricks-training.md}}

### Junk Code

Macro'nun reversing işlemini zorlaştırmak için **hiç kullanılmayan junk code** bulmak çok yaygındır.\
Örneğin, aşağıdaki görselde hiçbir zaman true olmayacak bir `If` ifadesinin bazı gereksiz ve işlevsiz kodları çalıştırmak için kullanıldığını görebilirsiniz.

![Word Macros - Junk Code: Örneğin, aşağıdaki görselde hiçbir zaman true olmayacak bir If ifadesinin bazı gereksiz ve işlevsiz kodları çalıştırmak için kullanıldığını görebilirsiniz](<../images/image (369).png>)

### Macro Forms

**GetObject** fonksiyonunu kullanarak macro formlarındaki verileri elde etmek mümkündür. Bu, analizi zorlaştırmak için kullanılabilir. Aşağıda, **verileri text box'ların içinde gizlemek** için kullanılan bir macro formunun fotoğrafı yer almaktadır (bir text box, başka text box'ları gizliyor olabilir):

![Junk Code - Macro Forms: GetObject fonksiyonunu kullanarak macro formlarındaki verileri elde etmek mümkündür. Bu, analizi zorlaştırmak için kullanılabilir. Aşağıda, ...](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
