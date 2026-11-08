# Enterprise Agent Governance Suite

> Private VPC Terraform Modules, Kubernetes Helm Umbrella Chart & Air-Gapped Compliance Suite for AI Coding Agents.

## Structure
- `terraform/aws/`: Zero-trust AWS VPC, KMS encryption, subnets, and IMDSv2 hardened configurations.
- `helm/ritual-agent-governance/`: Umbrella chart packaging AgentShield, DBShield, and SkillPrism with airgap network policies.
- `fleet/`: Developer workstation fleet orchestration and compliance verification.

## Testing & Validation
- Validate Terraform: `terraform fmt -check && terraform validate`
- Validate Helm: `helm lint ./helm/ritual-agent-governance`
