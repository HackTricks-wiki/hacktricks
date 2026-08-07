# TLS e Certificados

{{#include ../../banners/hacktricks-training.md}}


Esta área trata de **análise, formatos, conversões e erros comuns de X.509**.

## X.509: análise, formatos e erros comuns

### Análise rápida
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Campos úteis para inspecionar:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (é uma CA?)
- Janela de validade (NotBefore/NotAfter)
- Algoritmo de assinatura (MD5? SHA1?)

### Formatos e conversão

- PEM (Base64 com cabeçalhos BEGIN/END)
- DER (binário)
- PKCS#7 (`.p7b`) (cadeia de certificados, sem chave privada)
- PKCS#12 (`.pfx/.p12`) (certificado + chave privada + cadeia)

Conversões:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Vetores ofensivos comuns

- Confiar em raízes fornecidas pelo usuário / ausência de validação da cadeia
- Algoritmos de assinatura fracos (legados)
- Restrições de nome / bugs de análise de SAN (específicos da implementação)
- Problemas de confused deputy com vinculação incorreta da autenticação por certificado de cliente

### Logs de CT

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
