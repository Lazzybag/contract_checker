#!/usr/bin/env python3
"""
Contract Checker - DeFi Security Analysis Bot v2.1
Batch processing with dynamic contract loading from contracts.json

Author: Lazzybag
Version: 2.1.0
"""

import os
import sys
import json
import time
from datetime import datetime
from typing import Dict, List, Optional
import requests
from dotenv import load_dotenv

# Import custom modules
from risk_assessor import DeFiRiskAssessment

load_dotenv()

ETHERSCAN_API_KEY = os.getenv('ETHERSCAN_API_KEY')
CONTRACTS_FILE = "contracts.json"
REPORTS_DIR = "reports"


class ContractChecker:
    """
    Complete Ethereum contract analysis tool with batch processing
    
    Features:
    ✓ Source code verification check
    ✓ Contract metadata extraction
    ✓ Risk assessment scoring
    ✓ Detailed security analysis
    ✓ Batch processing from JSON file
    ✓ Timestamped report export
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
        self.contracts: List[Dict] = []
        self.assessments: List[Dict] = []
        
        # Create reports directory if it doesn't exist
        if not os.path.exists(REPORTS_DIR):
            os.makedirs(REPORTS_DIR)
            print(f"📁 Created reports directory: {REPORTS_DIR}")
    
    def load_contracts(self, filename: str = CONTRACTS_FILE) -> bool:
        """
        Load contracts from JSON file
        
        Args:
            filename: Path to contracts.json file
        
        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            if not os.path.exists(filename):
                print(f"❌ File not found: {filename}")
                return False
            
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.contracts = data.get('contracts', [])
            metadata = data.get('metadata', {})
            
            print(f"✅ Loaded {len(self.contracts)} contracts from {filename}")
            if metadata:
                print(f"   Version: {metadata.get('version', 'N/A')}")
                print(f"   Last Updated: {metadata.get('last_updated', 'N/A')}")
            
            return True
        
        except json.JSONDecodeError as e:
            print(f"❌ JSON parsing error in {filename}: {str(e)}")
            return False
        except Exception as e:
            print(f"❌ Error loading contracts: {str(e)}")
            return False
    
    def is_verified(self, address: str) -> bool:
        """Check if contract is verified"""
        try:
            params = {
                'module': 'contract',
                'action': 'getsourcecode',
                'address': address,
                'apikey': self.api_key
            }
            
            response = requests.get(self.etherscan_url, params=params, timeout=10)
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
            
            response = requests.get(self.etherscan_url, params=params, timeout=10)
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
            
            response = requests.get(self.etherscan_url, params=params, timeout=10)
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
    
    def assess_single_contract(self, contract_info: Dict) -> Optional[Dict]:
        """
        Assess a single contract
        
        Args:
            contract_info: Dictionary with contract metadata from contracts.json
        
        Returns:
            Complete assessment including basic info and risk scoring
        """
        address = contract_info.get('address')
        name = contract_info.get('name', 'Unknown')
        category = contract_info.get('category', 'unknown')
        description = contract_info.get('description', '')
        
        print(f"\n📋 Analyzing: {name} ({category})")
        print(f"   Address: {address}")
        
        # Basic contract analysis
        basic_analysis = self.analyze_contract(address)
        
        if not basic_analysis:
            print(f"   ❌ Contract not found or inaccessible")
            return None
        
        print(f"   Verified: {('✅ Yes' if basic_analysis['verified'] else '❌ No')}")
        print(f"   Compiler: {basic_analysis['compiler']}")
        
        # Risk assessment
        print(f"   🔄 Running risk assessment...")
        risk_result = self.risk_assessor.rate_protocol(address)
        
        print(f"   Risk Score: {risk_result['risk_score']}/100")
        print(f"   Risk Level: {risk_result['risk_level']}")
        
        # Combine results
        assessment = {
            'contract_metadata': contract_info,
            'basic_info': basic_analysis,
            'risk_assessment': risk_result,
            'timestamp': datetime.now().isoformat()
        }
        
        return assessment
    
    def process_all_contracts(self) -> List[Dict]:
        """
        Process all contracts from contracts.json
        
        Returns:
            List of all assessments
        """
        if not self.contracts:
            print("❌ No contracts loaded. Run load_contracts() first.")
            return []
        
        print(f"\n{'='*70}")
        print(f"🚀 BATCH CONTRACT SECURITY ASSESSMENT")
        print(f"{'='*70}")
        print(f"Processing {len(self.contracts)} contracts...\n")
        
        self.assessments = []
        successful = 0
        failed = 0
        
        for i, contract in enumerate(self.contracts, 1):
            print(f"[{i}/{len(self.contracts)}] ", end="")
            
            assessment = self.assess_single_contract(contract)
            
            if assessment:
                self.assessments.append(assessment)
                successful += 1
                print(f"   ✅ Assessment complete")
            else:
                failed += 1
                print(f"   ❌ Assessment failed")
            
            # Rate limiting - be respectful to Etherscan API
            if i < len(self.contracts):
                time.sleep(0.5)
        
        # Summary
        print(f"\n{'='*70}")
        print(f"📊 BATCH PROCESSING SUMMARY")
        print(f"{'='*70}")
        print(f"Total Contracts: {len(self.contracts)}")
        print(f"Successful Assessments: {successful}")
        print(f"Failed Assessments: {failed}")
        print(f"Success Rate: {(successful/len(self.contracts)*100):.1f}%")
        
        return self.assessments
    
    def export_individual_reports(self) -> List[str]:
        """
        Export each assessment as individual JSON file
        
        Returns:
            List of exported file paths
        """
        exported_files = []
        
        print(f"\n💾 Exporting individual reports...")
        
        for assessment in self.assessments:
            try:
                contract_name = assessment['contract_metadata'].get('name', 'unknown')
                address = assessment['basic_info']['address'][:8]
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{REPORTS_DIR}/assessment_{contract_name}_{address}_{timestamp}.json"
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(assessment, f, indent=2, ensure_ascii=False)
                
                print(f"   ✅ {filename}")
                exported_files.append(filename)
            
            except Exception as e:
                print(f"   ❌ Export failed: {str(e)}")
        
        return exported_files
    
    def export_batch_report(self, filename: str = None) -> Optional[str]:
        """
        Export all assessments as single batch report
        
        Args:
            filename: Custom filename (optional)
        
        Returns:
            Path to exported file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{REPORTS_DIR}/batch_assessment_{timestamp}.json"
        
        try:
            batch_data = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'total_contracts': len(self.assessments),
                    'successful_assessments': len([a for a in self.assessments if a]),
                    'average_risk_score': self._calculate_average_risk_score()
                },
                'assessments': self.assessments
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(batch_data, f, indent=2, ensure_ascii=False)
            
            print(f"\n✅ Batch report exported to: {filename}")
            return filename
        
        except Exception as e:
            print(f"❌ Batch export failed: {str(e)}")
            return None
    
    def _calculate_average_risk_score(self) -> float:
        """
        Calculate average risk score across all assessments
        """
        if not self.assessments:
            return 0.0
        
        total_score = sum(
            a['risk_assessment']['risk_score'] 
            for a in self.assessments if a
        )
        
        return round(total_score / len([a for a in self.assessments if a]), 2)
    
    def display_risk_summary(self):
        """
        Display risk summary across all contracts
        """
        if not self.assessments:
            print("No assessments to display")
            return
        
        print(f"\n{'='*70}")
        print(f"⚠️  RISK SUMMARY")
        print(f"{'='*70}")
        
        # Group by risk level
        risk_groups = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }
        
        for assessment in self.assessments:
            if assessment:
                risk_level = assessment['risk_assessment']['risk_level']
                contract_name = assessment['contract_metadata'].get('name', 'Unknown')
                risk_score = assessment['risk_assessment']['risk_score']
                risk_groups[risk_level].append((contract_name, risk_score))
        
        # Display each group
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            contracts = risk_groups[level]
            if contracts:
                emoji = '🔴' if level == 'CRITICAL' else '🟠' if level == 'HIGH' else '🟡' if level == 'MEDIUM' else '🟢'
                print(f"\n{emoji} {level} ({len(contracts)} contracts):")
                for name, score in contracts:
                    print(f"   • {name}: {score}/100")
        
        print(f"\nℹ️  Average Risk Score: {self._calculate_average_risk_score()}/100")
        print(f"{'='*70}\n")


def main():
    """
    Main entry point - Load and process all contracts from contracts.json
    """
    try:
        if not ETHERSCAN_API_KEY:
            print("❌ Error: ETHERSCAN_API_KEY not found in .env file")
            print("   Get a free key from: https://etherscan.io/apis")
            sys.exit(1)
        
        print("\n" + "="*70)
        print("🔐 ETHEREUM CONTRACT SECURITY CHECKER v2.1")
        print("="*70)
        print("Batch Processing Mode - Reading from contracts.json")
        
        # Initialize checker
        checker = ContractChecker(ETHERSCAN_API_KEY)
        
        # Load contracts from JSON
        if not checker.load_contracts():
            print("\n❌ Failed to load contracts. Exiting.")
            sys.exit(1)
        
        # Process all contracts
        assessments = checker.process_all_contracts()
        
        if not assessments:
            print("\n❌ No successful assessments. Exiting.")
            sys.exit(1)
        
        # Export reports
        print(f"\n{'='*70}")
        print(f"📤 EXPORTING REPORTS")
        print(f"{'='*70}")
        
        checker.export_individual_reports()
        checker.export_batch_report()
        
        # Display summary
        checker.display_risk_summary()
        
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
