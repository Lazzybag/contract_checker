#!/usr/bin/env python3
"""
Contract Checker - DeFi Security Analysis Bot
Integrated contract verification and risk assessment

Author: Lazzybag
Version: 2.0.0
"""

import os
import sys
import json
from datetime import datetime
from typing import Dict, Optional
import requests
from dotenv import load_dotenv

# Import custom modules
from risk_assessor import DeFiRiskAssessment

load_dotenv()

ETHERSCAN_API_KEY = os.getenv('ETHERSCAN_API_KEY')


class ContractChecker:
    """
    Complete Ethereum contract analysis tool
    
    Features:
    ✓ Source code verification check
    ✓ Contract metadata extraction
    ✓ Risk assessment scoring
    ✓ Detailed security analysis
    ✓ JSON/CSV export
    """
    
    def __init__(self, api_key: str):
        """
        Initialize contract checker
        
        Args:
            api_key: Etherscan API key
        """
        self.api_key = api_key
        self.etherscan_url = "https://api.etherscan.io/api"
        self.risk_assessor = DeFiRiskAssessment(api_key)
    
    def is_verified(self, address: str) -> bool:
        """Check if contract is verified"""
        try:
            params = {
                'module': 'contract',
                'action': 'getsourcecode',
                'address': address,
                'apikey': self.api_key
            }
            
            response = requests.get(self.etherscan_url, params=params)
            data = response.json()
            
            if data['status'] == '1' and data['result']:
                return data['result'][0]['SourceCode'] != ''
            return False
        except Exception as e:
            print(f"❌ Error checking verification: {str(e)}")
            return False
    
    def get_source_code(self, address: str) -> Optional[str]:
        """Get verified source code"""
        try:
            params = {
                'module': 'contract',
                'action': 'getsourcecode',
                'address': address,
                'apikey': self.api_key
            }
            
            response = requests.get(self.etherscan_url, params=params)
            data = response.json()
            
            if data['status'] == '1' and data['result']:
                return data['result'][0]['SourceCode']
            return None
        except Exception as e:
            print(f"❌ Error fetching source code: {str(e)}")
            return None
    
    def analyze_contract(self, address: str) -> Optional[Dict]:
        """Full contract analysis"""
        try:
            params = {
                'module': 'contract',
                'action': 'getsourcecode',
                'address': address,
                'apikey': self.api_key
            }
            
            response = requests.get(self.etherscan_url, params=params)
            data = response.json()
            
            if data['status'] == '1' and data['result']:
                contract = data['result'][0]
                return {
                    'address': address,
                    'verified': contract['SourceCode'] != '',
                    'name': contract.get('ContractName'),
                    'compiler': contract.get('CompilerVersion'),
                    'optimized': contract.get('OptimizationUsed') == '1',
                    'source_code': contract.get('SourceCode'),
                    'abi': contract.get('ABI'),
                }
            return None
        except Exception as e:
            print(f"❌ Error analyzing contract: {str(e)}")
            return None
    
    def full_security_assessment(self, address: str) -> Dict:
        """
        Complete security assessment including:
        - Basic contract info
        - Risk scoring
        - Recommendations
        """
        print(f"\n{'='*70}")
        print(f"🔍 ETHEREUM CONTRACT SECURITY ASSESSMENT")
        print(f"{'='*70}")
        
        # Basic contract analysis
        print(f"\n📋 Basic Contract Information:")
        basic_analysis = self.analyze_contract(address)
        
        if not basic_analysis:
            print(f"❌ Contract not found or inaccessible")
            return {}
        
        print(f"  Name: {basic_analysis['name']}")
        print(f"  Address: {address}")
        print(f"  Verified: {'✅ Yes' if basic_analysis['verified'] else '❌ No'}")
        print(f"  Compiler: {basic_analysis['compiler']}")
        print(f"  Optimized: {'✅ Yes' if basic_analysis['optimized'] else '❌ No'}")
        
        # Risk assessment
        print(f"\n⚠️  Risk Assessment:")
        risk_result = self.risk_assessor.rate_protocol(address)
        
        print(f"  Risk Score: {risk_result['risk_score']}/100")
        print(f"  Risk Level: {risk_result['risk_level']}")
        
        # Recommendations
        print(f"\n💡 Recommendations:")
        for i, rec in enumerate(risk_result['recommendations'], 1):
            print(f"  {i}. {rec}")
        
        # Combine results
        full_result = {
            'basic_info': basic_analysis,
            'risk_assessment': risk_result,
            'timestamp': datetime.now().isoformat()
        }
        
        print(f"\n{'='*70}\n")
        
        return full_result
    
    def export_assessment(self, assessment: Dict, filename: str = None):
        """
        Export assessment to JSON file
        """
        if not filename:
            address = assessment['basic_info']['address']
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"assessment_{address[:8]}_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(assessment, f, indent=2, ensure_ascii=False)
            print(f"✅ Assessment exported to {filename}")
        except Exception as e:
            print(f"❌ Export failed: {str(e)}")


def main():
    """
    Main entry point
    """
    try:
        if not ETHERSCAN_API_KEY:
            print("❌ Error: ETHERSCAN_API_KEY not found in .env file")
            print("   Get a free key from: https://etherscan.io/apis")
            sys.exit(1)
        
        checker = ContractChecker(ETHERSCAN_API_KEY)
        
        # Example: Analyze USDC (widely trusted stablecoin)
        contract_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        
        print("\n" + "="*70)
        print("ETHEREUM CONTRACT SECURITY CHECKER")
        print("="*70)
        print(f"Analyzing: {contract_address}")
        
        # Run full assessment
        assessment = checker.full_security_assessment(contract_address)
        
        if assessment:
            # Export results
            checker.export_assessment(assessment)
        
        print("\n✅ Analysis complete!\n")
    
    except KeyboardInterrupt:
        print("\n\n⏹️  Analysis interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
