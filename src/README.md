# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logos & motion design by_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Run HackTricks Locally

```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export HT_LANG="master" # Leave master for English
# "af" for Afrikaans
# "de" for German
# "el" for Greek
# "es" for Spanish
# "fr" for French
# "hi" for HindiP
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```

Your local copy of HackTricks will be **available at [http://localhost:3337](http://localhost:3337)** after <5 minutes (it needs to build the book, be patient).

Alternatively, if you have Docker Compose you can just run the following from the repo root:

```bash
docker compose up
```

This uses the bundled `docker-compose.yml` to serve the branch currently checked out on the host at [http://localhost:3337](http://localhost:3337) with live reload. To change languages when using Compose, check out the desired language branch before starting the service.

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber provides penetration testing, security audits, exploit and research work, tools, and security-awareness services. Its site describes a team of penetration testers, programmers, and security researchers with more than a decade of experience.<sup>[[1]](#references)</sup>

You can check their **blog** at [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** also support cybersecurity open source projects like HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti is a crowdsourced security provider offering bug bounty and penetration-testing services through a global researcher community. Its platform combines continuous bug bounty coverage with on-demand PTaaS and managed vulnerability disclosure programs.<sup>[[2]](#references)</sup>

**Bug bounty tip**: Join Intigriti through [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) and explore its bug bounty programs.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security offers self-paced, hands-on AI security training for security engineers, AppSec professionals, and developers. Its AI Security Certification covers LLM and agent fundamentals, RAG and vector databases, threat modeling, prompt-injection and MCP attacks, and defensive architecture.<sup>[[3]](#references)</sup>

👉 More details on the AI Security course:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** provides APIs for Google and other search engines, returning structured SERP data with features such as location-aware results, Maps, Shopping, and Knowledge Graph results.<sup>[[4]](#references)</sup>

For more information, check out their [**blog**](https://serpapi.com/blog/), try an example in their [**playground**](https://serpapi.com/playground), or [**create a free account**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** offers self-paced mobile and AI-security courses. Its catalog covers mobile application auditing and reversing with tools such as Ghidra, Frida, and LLDB, along with AI/LLM attack and defense labs.<sup>[[5]](#references)[[6]](#references)</sup>

Browse the [8kSec Academy course catalog](https://academy.8ksec.io/).

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** markets an offensive-AI platform that maps code and infrastructure, then uses static and dynamic agents to find and validate exploitable weaknesses with proof-of-concept evidence and remediation guidance.<sup>[[7]](#references)</sup>

**Code security tip**: Explore Naxus for code- and infrastructure-focused vulnerability discovery.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec provides penetration testing, security subscriptions, staffing, and vulnerability-assessment services. Its site says it operates internationally and covers offensive security, defensive security, and governance, risk, and compliance work.<sup>[[8]](#references)</sup>

For more information, visit their [**website**](https://websec.net/en/) or [**blog**](https://websec.net/blog/).

In addition to the above WebSec is also a **committed supporter of HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) provides expert-led cybersecurity training with custom-built content and labs grounded in real infrastructures. Its programs are tailored to organizational needs and span assessment through implementation.<sup>[[9]](#references)</sup> For custom training inquiries, reach out [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**What sets their training apart:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions focuses on cybersecurity consulting for **Education** and **FinTech**, including cloud assessments, internal and external penetration tests, vulnerability assessments, and compliance support.<sup>[[10]](#references)</sup>

Stay informed and up to date with the latest in cybersecurity by visiting our [**blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio is a desktop Kubernetes IDE with CloudMaps visualization, multi-cluster navigation, RBAC, Helm, logs, YAML, and terminal views. The vendor says it connects through kubeconfig without installing agents and supports macOS, Windows, Linux, and air-gapped clusters.<sup>[[11]](#references)</sup>

---

## License & Disclaimer

See the HackTricks Values & FAQ entry in References below.

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Practical AI Security: Attacks, Defenses, and Applications](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti HackTricks referral](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec sponsorship video](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets courses](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Values & FAQ](welcome/hacktricks-values-and-faq.md)

{{#include banners/hacktricks-training.md}}
