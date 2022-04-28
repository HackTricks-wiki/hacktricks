# GCP - Abuse GCP Permissions

## Introduction to GCP Privilege Escalation <a href="#introduction-to-gcp-privilege-escalation" id="introduction-to-gcp-privilege-escalation"></a>

GCP, as any other cloud, have some **principals**: users, groups and service accounts, and some **resources** like compute engine, cloud functions…\
Then, via roles, **permissions are granted to those principals over the resources**. This is the way to specify the permissions a principal has over a resource in GCP.\
There are certain permissions that will allow a user to **get even more permissions** on the resource or third party resources, and that’s what is called **privilege escalation** (also, the exploitation the vulnerabilities to get more permissions).

Therefore, I would like to separate GCP privilege escalation techniques in **2 groups**:

* **Privesc to a principal**: This will allow you to **impersonate another principal**, and therefore act like it with all his permissions. e.g.: Abuse _getAccessToken_ to impersonate a service account.
* **Privesc on the resource**: This will allow you to **get more permissions over the specific resource**. e.g.: you can abuse _setIamPolicy_ permission over cloudfunctions to allow you to trigger the function.
  * Note that some **resources permissions will also allow you to attach an arbitrary service account** to the resource. This means that you will be able to launch a resource with a SA, get into the resource, and **steal the SA token**. Therefore, this will allow to escalate to a principal via a resource escalation. This has happened in several resources previously, but now it’s less frequent (but can still happen).

Obviously, the most interesting privilege escalation techniques are the ones of the **second group** because it will allow you to **get more privileges outside of the resources you already have** some privileges over. However, note that **escalating in resources** may give you also access to **sensitive information** or even to **other principals** (maybe via reading a secret that contains a token of a SA).

{% hint style="warning" %}
It's important to note also that in **GCP Service Accounts are both principals and permissions**, so escalating privileges in a SA will allow you to impersonate it also.
{% endhint %}

{% hint style="info" %}
The permissions between parenthesis indicate the permissions needed to exploit the vulnerability with `gcloud`. Those might not be needed if exploiting it through the API.
{% endhint %}

## Privilege Escalation to Principals

Check all the **known permissions** that will allow you to **escalate privileges over other principals** in:

{% content-ref url="gcp-privesc-to-other-principals.md" %}
[gcp-privesc-to-other-principals.md](gcp-privesc-to-other-principals.md)
{% endcontent-ref %}

## Privilege Escalation to Resources

Check all the **known permissions** that will allow you to **escalate privileges over other resources** in:

{% content-ref url="gcp-privesc-to-resources.md" %}
[gcp-privesc-to-resources.md](gcp-privesc-to-resources.md)
{% endcontent-ref %}

##
