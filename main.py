# contract_checker/main.py

import os
import requests
from dotenv import load_dotenv

load_dotenv()

ETHERSCAN_API_KEY = os.getenv('ETHERSCAN_API_KEY')

class ContractChecker:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.etherscan_url = "https://api.etherscan.io/api"
    
    def is_verified(self, address: str) -> bool:
        """Check if contract is verified"""
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
    
    def get_source_code(self, address: str) -> str:
        """Get verified source code"""
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
    
    def analyze_contract(self, address: str) -> dict:
        """Full contract analysis"""
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


# Example usage
if __name__ == "__main__":
    checker = ContractChecker(ETHERSCAN_API_KEY)
    
    # Your contract address
    contract_address = "0x1234567890123456789012345678901234567890"
    
    analysis = checker.analyze_contract(contract_address)
    
    if analysis:
        print(f"✅ Contract: {analysis['name']}")
        print(f"📍 Address: {analysis['address']}")
        print(f"✓ Verified: {analysis['verified']}")
        print(f"🔧 Compiler: {analysis['compiler']}")
    else:
        print("❌ Contract not found")
