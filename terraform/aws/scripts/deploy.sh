#!/usr/bin/env bash
# =============================================================================
# Sentinel Cyber AI — AWS Terraform Deploy Script
# One-click deploy and post-deployment verification
#
# Prerequisites:
#   1. AWS credentials configured (aws configure)
#   2. Terraform 1.6+ installed
#   3. terraform.tfvars configured with your values
#
# Usage:
#   ./scripts/deploy.sh                      # Full deploy
#   ./scripts/deploy.sh --plan               # Review plan only
#   ./scripts/deploy.sh --destroy            # Tear down everything
#   ./scripts/deploy.sh --ssh                # SSH into the new server
#   ./scripts/deploy.sh --status             # Check deployment status
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SSH_KEY_FILE="$SCRIPT_DIR/sentinel-key.pem"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

check_prerequisites() {
    echo -e "${BLUE}🔍 Checking prerequisites...${NC}"

    if ! command -v terraform &> /dev/null; then
        echo -e "${RED}❌ Terraform not installed.${NC}"
        echo "   Install: https://developer.hashicorp.com/terraform/install"
        exit 1
    fi
    echo -e "${GREEN}  ✅ Terraform: $(terraform --version | head -1)${NC}"

    if ! command -v aws &> /dev/null; then
        echo -e "${RED}❌ AWS CLI not installed.${NC}"
        echo "   Install: https://aws.amazon.com/cli/"
        exit 1
    fi
    echo -e "${GREEN}  ✅ AWS CLI: $(aws --version 2>&1)${NC}"

    if ! aws sts get-caller-identity &> /dev/null; then
        echo -e "${RED}❌ AWS credentials not configured.${NC}"
        echo "   Run: aws configure"
        exit 1
    fi
    echo -e "${GREEN}  ✅ AWS credentials configured${NC}"

    if [ ! -f "$TERRAFORM_DIR/terraform.tfvars" ]; then
        echo -e "${YELLOW}⚠️  terraform.tfvars not found. Creating from example...${NC}"
        cp "$TERRAFORM_DIR/terraform.tfvars.example" "$TERRAFORM_DIR/terraform.tfvars"
        echo -e "${YELLOW}   Edit terraform.tfvars with your values, then re-run.${NC}"
        exit 0
    fi
    echo -e "${GREEN}  ✅ terraform.tfvars found${NC}"
}

init_terraform() {
    echo -e "${BLUE}📦 Initializing Terraform...${NC}"
    cd "$TERRAFORM_DIR"
    terraform init
    echo -e "${GREEN}  ✅ Terraform initialized${NC}"
}

plan() {
    cd "$TERRAFORM_DIR"
    echo -e "${BLUE}📋 Planning infrastructure...${NC}"
    terraform plan -out=tfplan
    echo -e "${GREEN}  ✅ Plan saved to tfplan${NC}"
}

apply() {
    cd "$TERRAFORM_DIR"
    if [ ! -f "tfplan" ]; then
        echo -e "${YELLOW}⚠️  No saved plan found. Running plan + apply...${NC}"
        terraform apply -auto-approve
    else
        terraform apply tfplan
    fi

    # Save SSH key
    echo -e "${BLUE}🔑 Saving SSH key...${NC}"
    terraform output -raw key_private_key_pem 2>/dev/null > "$SSH_KEY_FILE" || true
    if [ -f "$SSH_KEY_FILE" ] && [ -s "$SSH_KEY_FILE" ]; then
        chmod 400 "$SSH_KEY_FILE"
        echo -e "${GREEN}  ✅ SSH key saved to $SSH_KEY_FILE${NC}"
    fi

    show_outputs
}

show_outputs() {
    cd "$TERRAFORM_DIR"
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Sentinel Cyber AI — Deployment Complete         ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
    echo ""
    terraform output
    echo ""
    echo -e "${YELLOW}SSH Command:${NC} $(terraform output -raw ssh_command 2>/dev/null || echo 'N/A')"
    echo -e "${YELLOW}API URL:${NC}     $(terraform output -raw api_url 2>/dev/null || echo 'N/A')"
    echo ""
    echo -e "${YELLOW}Next:${NC}"
    echo "  1. Wait for bootstrap to complete (~5 min)"
    echo "  2. SSH in: $(terraform output -raw ssh_command 2>/dev/null || echo 'ssh -i sentinel-key.pem ubuntu@<IP>')"
    echo "  3. Check status: sudo journalctl -u sentinel -f"
    echo "  4. Verify API: $(terraform output -raw api_health_url 2>/dev/null || echo 'curl http://<IP>/health')"
}

destroy() {
    cd "$TERRAFORM_DIR"
    echo -e "${RED}⚠️  DESTROYING ALL INFRASTRUCTURE${NC}"
    echo -n "Type 'yes' to confirm: "
    read -r confirm
    if [ "$confirm" != "yes" ]; then
        echo "Cancelled."
        exit 0
    fi
    terraform destroy -auto-approve
    rm -f "$SSH_KEY_FILE"
    echo -e "${GREEN}  ✅ Infrastructure destroyed${NC}"
}

ssh_connect() {
    cd "$TERRAFORM_DIR"
    local ip
    ip=$(terraform output -raw ec2_public_ip 2>/dev/null || true)
    if [ -z "$ip" ]; then
        echo -e "${RED}❌ No EC2 IP found. Deploy first.${NC}"
        exit 1
    fi

    if [ -f "$SSH_KEY_FILE" ]; then
        ssh -i "$SSH_KEY_FILE" -o StrictHostKeyChecking=no "ubuntu@$ip"
    else
        ssh -o StrictHostKeyChecking=no "ubuntu@$ip"
    fi
}

status() {
    cd "$TERRAFORM_DIR"
    echo -e "${BLUE}📊 Deployment Status:${NC}"
    terraform show -json 2>/dev/null | python3 -c "
import json, sys
state = json.load(sys.stdin)
values = state.get('values', {}).get('outputs', {})
for name, output in values.items():
    val = output.get('value', '')
    if isinstance(val, str) and len(str(val)) > 80:
        val = str(val)[:80] + '...'
    print(f'  {name}: {val}')
" 2>/dev/null || echo "  No state found. Run deploy first."

    local ip
    ip=$(terraform output -raw ec2_public_ip 2>/dev/null || true)
    if [ -n "$ip" ]; then
        echo ""
        echo -e "${BLUE}🔍 Service Checks:${NC}"
        echo -n "  API Health: "
        curl -sf "http://$ip/health" > /dev/null 2>&1 && echo -e "${GREEN}✅${NC}" || echo -e "${YELLOW}⏳ Waiting...${NC}"
        echo -n "  Dashboard: "
        curl -sf "http://$ip:8500" > /dev/null 2>&1 && echo -e "${GREEN}✅${NC}" || echo -e "${YELLOW}⏳ Waiting...${NC}"
    fi
}

main() {
    local cmd=${1:-deploy}

    case "$cmd" in
        deploy)
            check_prerequisites
            init_terraform
            plan
            echo ""
            echo -e "${YELLOW}Review the plan above, then type 'apply' to proceed (or anything else to cancel):${NC}"
            read -r response
            if [ "$response" = "apply" ]; then
                apply
            else
                echo "Deployment cancelled."
            fi
            ;;
        --plan)
            check_prerequisites
            init_terraform
            plan
            ;;
        --apply)
            check_prerequisites
            init_terraform
            apply
            ;;
        --destroy)
            destroy
            ;;
        --ssh)
            ssh_connect
            ;;
        --status)
            status
            ;;
        --help|-h)
            echo "Sentinel Cyber AI — Terraform AWS Deploy"
            echo ""
            echo "Usage:"
            echo "  ./scripts/deploy.sh              Interactive deploy"
            echo "  ./scripts/deploy.sh --plan        Review plan only"
            echo "  ./scripts/deploy.sh --apply       Auto-approve deploy"
            echo "  ./scripts/deploy.sh --destroy     Tear down everything"
            echo "  ./scripts/deploy.sh --ssh         SSH into server"
            echo "  ./scripts/deploy.sh --status      Check deployment"
            echo ""
            echo "Prerequisites:"
            echo "  1. aws configure          # Set up AWS credentials"
            echo "  2. cp terraform.tfvars.example terraform.tfvars"
            echo "  3. Edit terraform.tfvars  # Set your values"
            echo ""
            echo "Quick Start:"
            echo "  ./scripts/deploy.sh        # 🚀 Deploy to production!"
            ;;
        *)
            echo "Unknown command: $cmd"
            echo "Usage: $0 [deploy|--plan|--apply|--destroy|--ssh|--status|--help]"
            ;;
    esac
}

main "$@"
