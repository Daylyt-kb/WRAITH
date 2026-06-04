#!/bin/bash
# ╔═══════════════════════════════════════════════════════════╗
# ║  WRAITH — One-Command Installer                          ║
# ║  Sets up everything needed to run WRAITH locally.        ║
# ╚═══════════════════════════════════════════════════════════╝

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${RED}"
cat << 'BANNER'
  ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗ 
 ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗
 ██║     ██║██████╔╝███████║█████╗  ██████╔╝
 ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗
 ╚██████╗██║██║     ██║  ██║███████╗██║  ██║
  ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
BANNER
echo -e "${NC}"
echo -e "${BOLD}WRAITH Installer — Zero Budget Edition${NC}"
echo -e "${CYAN}Works on Kali Linux, Ubuntu, Debian, macOS${NC}\n"

# ── 1. Check Python ──
echo -e "${YELLOW}[1/5] Checking Python...${NC}"
if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 --version 2>&1)
    echo -e "  ${GREEN}✓${NC} $PY_VERSION"
else
    echo -e "  ${RED}✗ Python 3 not found. Install it first.${NC}"
    exit 1
fi

# ── 2. Install Python dependencies ──
echo -e "${YELLOW}[2/5] Installing Python dependencies...${NC}"
if command -v pip3 &>/dev/null; then
    pip3 install -q rich anthropic requests 2>/dev/null || {
        pip3 install --user -q rich anthropic requests 2>/dev/null || true
    }
    echo -e "  ${GREEN}✓${NC} Python packages installed (rich, anthropic, requests)"
else
    echo -e "  ${YELLOW}⚠${NC} pip3 not found — install manually: pip install rich anthropic"
fi

# ── 3. Check Kali tools ──
echo -e "${YELLOW}[3/5] Checking Kali security tools...${NC}"
TOOLS=("nmap" "whois" "curl" "dig" "nikto" "amass" "whatweb" "theHarvester" "nuclei" "gobuster" "ffuf")
MISSING=()

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${YELLOW}○${NC} $tool (not installed)"
        MISSING+=("$tool")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}Missing tools. Install them with:${NC}"

    # Check if on Kali/Debian
    if command -v apt-get &>/dev/null; then
        APT_TOOLS=()
        for t in "${MISSING[@]}"; do
            case $t in
                nmap|whois|curl|nikto|gobuster|ffuf|amass|whatweb) APT_TOOLS+=("$t") ;;
            esac
        done
        if [ ${#APT_TOOLS[@]} -gt 0 ]; then
            echo -e "  ${CYAN}sudo apt-get install ${APT_TOOLS[*]}${NC}"
        fi
        if [[ " ${MISSING[@]} " =~ " theHarvester " ]]; then
            echo -e "  ${CYAN}sudo apt-get install theharvester${NC}"
        fi
        if [[ " ${MISSING[@]} " =~ " nuclei " ]]; then
            echo -e "  ${CYAN}# nuclei (requires Go):${NC}"
            echo -e "  ${CYAN}go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest${NC}"
        fi
    fi
    echo ""
    echo -e "${YELLOW}WRAITH will still work with available tools. Missing tools are skipped gracefully.${NC}"
fi

# ── 4. Create output directories ──
echo -e "${YELLOW}[4/5] Creating output directories...${NC}"
mkdir -p wraith_output/{reports,scripts,knowledge,consent}
echo -e "  ${GREEN}✓${NC} ./wraith_output/ created"

# ── 5. Make cipher.py executable ──
echo -e "${YELLOW}[5/5] Setting up WRAITH...${NC}"
chmod +x cipher.py
echo -e "  ${GREEN}✓${NC} cipher.py is executable"

# ── API Key setup ──
echo ""
echo -e "${BOLD}Optional: Set your Anthropic API key for AI-powered analysis${NC}"
echo -e "Get a free key at: ${CYAN}https://console.anthropic.com${NC}"
echo -e "The free tier includes enough credits to run many scans."
echo ""
echo -e "Add to your shell config (~/.bashrc or ~/.zshrc):"
echo -e "  ${CYAN}export ANTHROPIC_API_KEY='your-key-here'${NC}"
echo ""
echo -e "WRAITH works WITHOUT an API key — it just uses AI for richer report analysis."
echo ""

# ── Done ──
echo -e "${GREEN}${BOLD}═══════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  WRAITH is ready.${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════${NC}"
echo ""
echo -e "Quick start:"
echo -e "  ${CYAN}python3 cipher.py --check-tools${NC}          # See what tools you have"
echo -e "  ${CYAN}python3 cipher.py --interactive${NC}           # Open the commander shell"
echo -e "  ${CYAN}python3 cipher.py -t yoursite.com -m recon --authorized${NC}"
echo ""
echo -e "${YELLOW}Remember: Only test systems you own or have permission to test.${NC}"
echo -e "${YELLOW}WRAITH is legal-by-design. Unauthorized use is illegal.${NC}"
echo ""
