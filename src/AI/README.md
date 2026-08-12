# AI in Cybersecurity

{{#include ../banners/hacktricks-training.md}}

## Main Machine Learning Algorithms

The best starting point to learn about AI is to understand how the main machine learning algorithms work. This will help you to understand how AI works, how to use it and how to attack it:


{{#ref}}
./AI-Supervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Unsupervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Reinforcement-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Deep-Learning.md
{{#endref}}

### LLMs Architecture

In the following page you will find the basics of each component to build a basic LLM using transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI Security

### AI Risk Frameworks

Two useful starting frameworks for assessing AI-system risk are the OWASP Machine Learning Security Top 10 and Google's Secure AI Framework (SAIF). They are complementary rather than an exhaustive list of AI risk frameworks.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompts Security

LLMs have made the use of AI explode in the last years, but they are not perfect and can be tricked by adversarial prompts. This is a very important topic to understand how to use AI safely and how to attack it:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

It's very common to developers and companies to run models downloaded from the Internet, however just loading a model might be enough to execute arbitrary code on the system. This is a very important topic to understand how to use AI safely and how to attack it:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-Assisted KYC Bypass

Generative video can be combined with virtual-camera injection and camera API manipulation to bypass weak KYC, age-verification, and biometric liveness workflows:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) is an open protocol for connecting AI applications to tools and data sources. Because MCP servers can expose data and actions, assessments must include authorization, consent, tool-input validation, and trust-boundary review.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bots

LLM-powered agents can automate long-running black-box web pentesting workflows when they are supported by observability, orchestration, authenticated session handling, and adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)

{{#include ../banners/hacktricks-training.md}}
