# Contract Checker - DeFi Security Analysis Bot

## Overview

A professional-grade Ethereum contract security analysis tool that batch processes contracts from a JSON watchlist.

### Key Features

✅ **Dynamic Contract Loading** - Add/remove addresses from `contracts.json` without editing code
✅ **Batch Processing** - Analyze multiple contracts in one run
✅ **Risk Scoring** - Weighted 5-factor risk assessment (0-100)
✅ **Verification Status** - Check if source code is verified on Etherscan
✅ **Complexity Analysis** - Evaluate contract bytecode complexity
✅ **Deployment History** - Track contract age and maturity
✅ **Vulnerability Detection** - Pattern-based vulnerability identification
✅ **Activity Tracking** - Monitor transaction history
✅ **Automated Reports** - Generate individual & batch JSON reports
✅ **Risk Visualization** - Categorized summary (CRITICAL/HIGH/MEDIUM/LOW)

---

## Quick Start

### 1. Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Get Etherscan API key
# Go to: https://etherscan.io/apis
# Create account, generate free key

# Add to .env file
ETHERSCAN_API_KEY=your_api_key_here
```

### 2. Add Contracts

Edit `contracts.json` and add your contract addresses:

```json
{
  "contracts": [
    {
      "address": "0xYOUR_CONTRACT_ADDRESS",
      "name": "ContractName",
      "chain": "ethereum",
      "category": "protocol-type",
      "description": "Brief description",
      "notes": "Additional notes"
    }
  ]
}
```

### 3. Run Analysis

```bash
python main.py
```

---

## Workflow

```
contracts.json
    ↓
[Load Contracts]
    ↓
[Batch Processing]
    ├─ Verification Check (Etherscan)
    ├─ Complexity Analysis (Bytecode)
    ├─ Deployment History (Age)
    ├─ Vulnerability Detection (Pattern)
    └─ Activity Tracking (Transactions)
    ↓
[Risk Scoring] → 0-100 Points
    ↓
[Generate Reports]
    ├─ Individual JSON files (per contract)
    └─ Batch summary JSON (all contracts)
    ↓
[Display Risk Summary]
    └─ Categorized by risk level
```

---

## Risk Scoring Breakdown

| Factor | Weight | Low Risk | High Risk |
|--------|--------|----------|----------|
| **Verification** | 25% | Verified=10pts | Not verified=80pts |
| **Complexity** | 15% | Simple=15pts | Complex=70pts |
| **Deployment Age** | 20% | >2 years=20pts | <3mo=85pts |
| **Vulnerabilities** | 25% | None=15pts | Many=85pts |
| **Activity** | 15% | High=15pts | None=90pts |

**Total Risk Score: 0-100**
- 🟢 LOW (0-39): Generally safe
- 🟡 MEDIUM (40-69): Caution recommended
- 🟠 HIGH (70-89): Exercise extreme caution
- 🔴 CRITICAL (90-100): Do NOT interact

---

## File Structure

```
contract_checker/
├── main.py              # Main entry point (batch processor)
├── risk_assessor.py     # Risk assessment module
├── contracts.json       # ⭐ Your contract watchlist
├── requirements.txt     # Python dependencies
├── .env                 # Environment variables (YOUR API KEY)
├── .gitignore           # Git ignore rules
├── README.md            # This file
└── reports/             # Auto-generated reports
    ├── assessment_USDC_0xA0b8_20260812_191800.json
    ├── assessment_UNI_0x1f98_20260812_191800.json
    └── batch_assessment_20260812_191800.json
```

---

## Managing contracts.json

### Add a Contract

```json
{
  "address": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
  "name": "DAI",
  "chain": "ethereum",
  "category": "stablecoin",
  "description": "MakerDAO's decentralized stablecoin",
  "notes": "Collateral-backed, widely trusted"
}
```

### Remove a Contract

Delete the contract object from the `contracts` array.

### Update a Contract

Modify any field (address, name, category, etc.).

### Batch Update

Replace entire `contracts.json` with new list.

---

## Output Example

### Console Output

```
======================================================================
🔐 ETHEREUM CONTRACT SECURITY CHECKER v2.1
======================================================================
Batch Processing Mode - Reading from contracts.json

✅ Loaded 4 contracts from contracts.json
   Version: 1.0.0
   Last Updated: 2026-08-12

======================================================================
🚀 BATCH CONTRACT SECURITY ASSESSMENT
======================================================================
Processing 4 contracts...

[1/4] 📋 Analyzing: USDC (stablecoin)
   Address: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
   Verified: ✅ Yes
   Compiler: v0.6.12+commit.27d51765
   🔄 Running risk assessment...
   Risk Score: 25/100
   Risk Level: LOW
   ✅ Assessment complete

[2/4] 📋 Analyzing: Uniswap (dex-token)
   ...

======================================================================
📊 BATCH PROCESSING SUMMARY
======================================================================
Total Contracts: 4
Successful Assessments: 4
Failed Assessments: 0
Success Rate: 100.0%

======================================================================
📤 EXPORTING REPORTS
======================================================================
💾 Exporting individual reports...
   ✅ reports/assessment_USDC_0xA0b8_20260812_191800.json
   ✅ reports/assessment_Uniswap_0x1f98_20260812_191800.json
   ✅ reports/assessment_WETH_0xC02a_20260812_191800.json
   ✅ reports/assessment_DAI_0x6B17_20260812_191800.json

✅ Batch report exported to: reports/batch_assessment_20260812_191800.json

======================================================================
⚠️  RISK SUMMARY
======================================================================

🟢 LOW (4 contracts):
   • USDC: 25/100
   • Uniswap: 32/100
   • WETH: 28/100
   • DAI: 35/100

ℹ️  Average Risk Score: 30/100

✅ Analysis complete!
```

### Report Files

**Individual Reports:** `reports/assessment_USDC_0xA0b8_20260812_191800.json`
```json
{
  "contract_metadata": {
    "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "name": "USDC",
    "category": "stablecoin",
    "description": "USD Coin - Circle's stablecoin"
  },
  "basic_info": {
    "verified": true,
    "compiler": "v0.6.12+commit.27d51765",
    "optimized": true
  },
  "risk_assessment": {
    "risk_score": 25,
    "risk_level": "LOW",
    "factors": {
      "verification": { ... },
      "complexity": { ... },
      "deployment": { ... },
      "vulnerabilities": { ... },
      "activity": { ... }
    },
    "recommendations": [ ... ]
  },
  "timestamp": "2026-08-12T19:18:04.123456"
}
```

**Batch Report:** `reports/batch_assessment_20260812_191800.json`
```json
{
  "metadata": {
    "generated_at": "2026-08-12T19:18:04.123456",
    "total_contracts": 4,
    "successful_assessments": 4,
    "average_risk_score": 30.0
  },
  "assessments": [ ... all individual assessments ... ]
}
```

---

## Use Cases

### 1. Portfolio Monitoring

Add all your DeFi protocol investments to `contracts.json` and run daily to track risk changes.

### 2. Due Diligence

Before investing, add contract address to `contracts.json` and run analysis.

### 3. Audit Preparation

Build watchlist of protocols to audit, generate reports for stakeholders.

### 4. Risk Tracking

Run periodically to detect if risk score increases over time.

### 5. Team Collaboration

Share `contracts.json` with team, each member runs analysis on same contracts.

---

## Troubleshooting

### ❌ "No contracts loaded"

**Problem:** `contracts.json` not found or empty

**Solution:**
```bash
# Create contracts.json in same directory as main.py
# Copy the template from documentation
```

### ❌ "ETHERSCAN_API_KEY not found"

**Problem:** API key not in `.env` file

**Solution:**
```bash
# Add to .env file:
ETHERSCAN_API_KEY=your_actual_api_key_here

# Get free key from: https://etherscan.io/apis
```

### ❌ "Contract not found or inaccessible"

**Problem:** Invalid address or network issue

**Solution:**
- Verify address on etherscan.io manually
- Check internet connection
- Try again (Etherscan API might be rate limiting)

### ⚠️ "Rate limit warning"

**Problem:** Too many requests to Etherscan API

**Solution:**
- Free tier is 5000 requests/second
- Script has built-in 0.5s delays between requests
- Upgrade to paid Etherscan API key for higher limits

---

## Best Practices

✅ **Do:**
- Keep `contracts.json` organized with metadata
- Run analysis before making investment decisions
- Review recommendations carefully
- Track risk changes over time
- Share findings with team
- Version control `contracts.json` changes

❌ **Don't:**
- Trust risk score as sole investment metric
- Ignore HIGH/CRITICAL risk warnings
- Use outdated risk assessments
- Hardcode addresses (use `contracts.json` instead)
- Share `.env` file (contains API key!)

---

## Advanced Features

### Batch Import

Create `contracts.json` with 100+ contracts and process all at once.

### Scheduled Runs

Use cron (Linux/Mac) or Task Scheduler (Windows) to run daily:
```bash
0 9 * * * cd /path/to/contract_checker && python main.py
```

### Report Analysis

Post-process batch reports with Python:
```python
import json
with open('reports/batch_assessment_*.json') as f:
    data = json.load(f)
    high_risk = [a for a in data['assessments'] 
                 if a['risk_assessment']['risk_level'] == 'HIGH']
```

---

## Version History

- **v2.1** - Batch processing with contracts.json
- **v2.0** - DeFi risk assessment integration
- **v1.0** - Basic contract verification

---

## License

MIT License - Free for academic and commercial use

---

## Support

For issues:
1. Check Troubleshooting section
2. Verify `.env` configuration
3. Test with example addresses (USDC, UNI)
4. Check Etherscan API status

---

**Happy analyzing! 🔐**
