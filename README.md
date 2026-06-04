# WRAITH — AI Security Swarm

> The world's first civilian AI security swarm. Free, open source, legal by design.

## Install

```bash
git clone https://github.com/Daylyt-kb/WRAITH.git
cd WRAITH
cp .env.example .env
bash install.sh
python3 cipher.py --interactive
```

## Usage

```bash
python3 cipher.py -t example.com -m recon --authorized
python3 cipher.py -t example.com -m full --authorized
python3 cipher.py --check-tools
```

## Requirements
- Python 3.9+
- Linux/macOS/WSL (Kali Linux recommended for built-in security tools)
- Optional: OPENROUTER_API_KEY for AI-powered analysis

## Legal
Only test systems you own or have written authorization for.
