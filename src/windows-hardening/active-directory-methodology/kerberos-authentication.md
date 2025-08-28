# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

Kerberos is time-sensitive. A typical default clock skew tolerance is 5 minutes. If your attacking host clock drifts beyond this window, pre-auth and service requests will fail with KRB_AP_ERR_SKEW or similar errors. Always sync your time with the DC before Kerberos operations:

```bash
sudo ntpdate <dc.fqdn>
```

For a deep dive on protocol flow and abuse:

**Check the amazing post from:** [https://www.tarlogic.com/en/blog/how-kerberos-works/](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## References

- [How Kerberos Works – Tarlogic](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [HTB Sendai – 0xdf (operational notes on clock skew)](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}