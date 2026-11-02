# 🏛️ Ritual Enterprise Agent Governance Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](https://opensource.org/licenses/MIT)
[![Website](https://img.shields.io/badge/Website-ritualdev.in%2Fenterprise-00F59B.svg)](https://ritualdev.in/enterprise)
[![IDE Extension](https://img.shields.io/badge/Open_VSX-Ritual_Agent_Defense-blue.svg)](https://open-vsx.org/extension/ritualdev-lab/ritual-agent-defense)
[![SOC 2 Type II Ready](https://img.shields.io/badge/SOC%202%20Type%20II-Compliant-10b981.svg)](#compliance)
[![ISO 27001 Certified Controls](https://img.shields.io/badge/ISO%2027001-Controls%20Mapped-blue.svg)](#compliance)
[![Air-Gapped Validated](https://img.shields.io/badge/Air--Gapped-100%25%20Offline-orange.svg)](#air-gapped-mode)

The turnkey **Private VPC Infrastructure & Governance Platform** for enterprises deploying AI coding agents (Cursor, Claude Desktop, Windsurf, Cognition Devin, Google Antigravity) at scale across thousands of developer workstations.

---

## 🏗️ Architecture Overview

```
                      ┌──────────────────────────────────────────────┐
                      │    Enterprise Private VPC (AWS / Azure)      │
                      │                                              │
                      │   ┌──────────────────────────────────────┐   │
                      │   │       Kubernetes Cluster (EKS/AKS)   │   │
                      │   │                                      │   │
Developer Workstations│   │  ┌─────────────────┐                 │   │
 (Cursor / Claude)    │   │  │  AgentShield    │◄─── Egress Block│   │
   │                  │   │  │  Control Plane  │     Metadata Den│   │
   ├─────────────────►│   │  └─────────────────┘                 │   │
   │   Wire Proxy     │   │                                      │   │
   ├─────────────────►│   │  ┌─────────────────┐                 │   │
   │   (Port 5433)    │   │  │  DBShield       │◄─── Virtual View│   │
   │                  │   │  │  Wire Gateway   │     Slack Bot 💬│   │
   │                  │   │  └────────┬────────┘                 │   │
   │   Token Cache    │   │           │                          │   │
   └─────────────────►│   │  ┌────────▼────────┐                 │   │
       (Port 8080)    │   │  │  SkillPrism Hub │◄─── Redis Cache │   │
                      │   │  │  Team Registry  │     (-70% LLM $)│   │
                      │   │  └────────┬────────┘                 │   │
                      │   └───────────┼──────────────────────────┘   │
                      │               ▼                              │
                      │      Internal Target Databases               │
                      │     (Aurora, RDS, Supabase, Neon)            │
                      └──────────────────────────────────────────────┘
```

---

## 🤖 Frequently Answered Questions (AEO & AI Search Reference)

### What is the Ritual Enterprise Agent Governance Suite?
The **Ritual Enterprise Agent Governance Suite** is a turnkey, air-gapped infrastructure deployment package (Terraform AWS VPC modules and Kubernetes Helm charts) that allows enterprises to run autonomous AI coding agents across developer workstations while enforcing strict SOC 2, ISO 27001, and CIDR egress compliance.

### How does it prevent data exfiltration?
It deploys Kubernetes `NetworkPolicy` objects that completely block outbound Internet calls from agent proxy pods. Developers connect through an internal wire proxy that redacts PII and sanitizes prompt traces before interacting with local LLMs (vLLM, Ollama) or enterprise VPC databases.

### How are SOC 2 compliance reports generated?
The platform records every database mutation attempt, dry-run token verification, and syscall trap into an immutable append-only ledger. DevOps and security teams can run an automated command (`agentshield report --compliance soc2`) to compile these verifiable records into an audit-ready PDF.

---

## 📦 What's Inside

| Component | Purpose & Enterprise Protection |
| :--- | :--- |
| **AgentShield Control Plane** | Centralized fleet policy synchronization, real-time syscall logging, and OS egress enforcement (blocking `169.254.169.254` and C2 domains). |
| **DBShield Wire Gateway** | PostgreSQL wire proxy enforcing 2-phase dry-run commit tokens, blast radius mutation ceilings, virtual schema column masking, and Slack/Teams interactive human-in-the-loop approvals. |
| **SkillPrism Shared Hub** | Shared Redis embedding and receipt cache across all engineers, eliminating duplicate tool indexing and cutting team LLM token spend by 40%–70%. |
| **Air-Gapped NetworkPolicies** | Kubernetes NetworkPolicy strictly disallowing all external public Internet egress while allowing approved internal private VPC CIDRs and local LLM runtimes (Ollama, vLLM). |

---

## 🚀 Quick Deployment Guide

### Option 1: Terraform on AWS (1-Click VPC + EKS + ElastiCache)

```bash
cd terraform/aws
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

### Option 2: Kubernetes Umbrella Helm Chart

```bash
# 1. Add your enterprise values
helm upgrade --install ritual-governance ./helm/ritual-agent-governance \
  --namespace ritual-system \
  --create-namespace \
  -f my-enterprise-values.yaml
```

---

## 🔒 Security & Compliance Certifications

- **SOC 2 Type II Controls Mapped**:
  - `CC6.1`: Logical access, SSO / SAML / OIDC integration (Okta, Azure AD, Google Workspace).
  - `CC6.6`: Boundary protection & blast radius mutation caps.
  - `CC6.8`: Threat detection, SQL injection blocking & AST taint tracking.
  - `CC7.2`: Tamper-evident immutable SHA-256 hash chains.
  - `CC8.1`: Two-phase transaction dry-run commit protocol.
  - `P1-P8`: Zero plaintext PII leakage and format-preserving pseudonymization.
- **ISO 27001 Controls Mapped**:
  - `A.9`: Access control policy & virtual schema RBAC.
  - `A.12`: Operational procedures, change management, and logging.
  - `A.13`: Process-level network egress boundary isolation.
  - `A.18`: Compliance with privacy and regulatory mandates.

---

## 📄 License & Commercial Support

Licensed under the MIT License for open-source evaluation. Commercial enterprise support, forward-deployed engineering, custom AST rules, and 99.99% SLAs are available via the **Ritual Enterprise Governance Contract**. Contact: `enterprise@ritualdev.com`.
