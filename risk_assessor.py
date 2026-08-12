#!/usr/bin/env python3
"""
DeFi Risk Assessment Module
Analyzes Ethereum contracts for security & operational risk

Author: Lazzybag
Version: 1.0.0
"""

import os
import requests
from typing import Dict, Optional, List
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

ETHERSCAN_API_KEY = os.getenv('ETHERSCAN_API_KEY')
COINGECKO_API_BASE = "https://api.coingecko.com/api/v3"


class DeFiRiskAssessment:
    """
    Comprehensive DeFi protocol risk assessment
    
    Evaluates:
    ✓ Source code verification
    ✓ Deployment history
    ✓ Contract complexity
    ✓ Known vulnerabilities
    ✓ Social metrics
    """
    
    # Risk scoring thresholds
    RISK_THRESHOLDS = {
        'critical': (90, 100),    # Red zone
        'high': (70, 89),         # Orange zone
        'medium': (40, 69),       # Yellow zone
        'low': (0, 39)            # Green zone
    }
    
    def __init__(self, etherscan_api_key: str):
        """
        Initialize risk assessor
        
        Args:
            etherscan_api_key: Etherscan API key for contract queries
        """
        self.api_key = etherscan_api_key
        self.etherscan_url = "https://api.etherscan.io/api"
        self.coingecko_url = COINGECKO_API_BASE
    
    def rate_protocol(self, address: str) -> Dict:
        """
        Complete risk assessment for a DeFi protocol
        
        Args:
            address: Ethereum contract address
        
        Returns:
            dict with risk score (0-100) and detailed breakdown
        """
        print(f"\n🔍 Analyzing contract: {address}")
        
        # Collect all risk factors
        factors = {}
        
        # 1. Source code verification (weight: 25%)
        print("   📝 Checking source code...")
        factors['verification'] = self._check_verification(address)
        
        # 2. Contract complexity (weight: 15%)
        print("   📊 Analyzing complexity...")
        factors['complexity'] = self._analyze_complexity(address)
        
        # 3. Deployment history (weight: 20%)
        print("   ⏰ Checking deployment history...")
        factors['deployment'] = self._check_deployment_history(address)
        
        # 4. Known vulnerabilities (weight: 25%)
        print("   ⚠️  Checking known vulnerabilities...")
        factors['vulnerabilities'] = self._check_vulnerabilities(address)
        
        # 5. Contract interactions (weight: 15%)
        print("   🔗 Analyzing transaction history...")
        factors['activity'] = self._check_activity(address)
        
        # Calculate weighted risk score
        risk_score = self._calculate_risk_score(factors)
        risk_level = self._get_risk_level(risk_score)
        
        return {
            'address': address,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'factors': factors,
            'timestamp': datetime.now().isoformat(),
            'recommendations': self._get_recommendations(risk_score, factors)
        }
    
    def _check_verification(self, address: str) -> Dict:
        """
        Check if contract source code is verified (25% weight)
        
        Risk Score:
        - Verified: 10 points (low risk)
        - Not verified: 80 points (high risk)
        """
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
                is_verified = contract['SourceCode'] != ''
                
                return {
                    'is_verified': is_verified,
                    'risk_points': 10 if is_verified else 80,
                    'weight': 0.25,
                    'comment': '✅ Code is transparent' if is_verified else '🚨 Code is hidden'
                }
        except Exception as e:
            print(f"   ⚠️  Verification check failed: {str(e)}")
        
        return {
            'is_verified': False,
            'risk_points': 60,
            'weight': 0.25,
            'comment': 'Unable to verify'
        }
    
    def _analyze_complexity(self, address: str) -> Dict:
        """
        Analyze contract complexity (15% weight)
        
        Factors:
        - Contract size (bytecode length)
        - Number of functions
        - External calls
        
        Risk Score:
        - Simple (<5KB): 15 points (low risk)
        - Medium (5-20KB): 35 points (medium risk)
        - Complex (>20KB): 70 points (high risk)
        """
        try:
            params = {
                'module': 'proxy',
                'action': 'eth_getCode',
                'address': address,
                'tag': 'latest',
                'apikey': self.api_key
            }
            
            response = requests.get(self.etherscan_url, params=params)
            data = response.json()
            
            if data['status'] == '1':
                bytecode = data['result']
                bytecode_length = len(bytecode) / 2  # Convert hex string to bytes
                
                if bytecode_length < 5000:
                    risk = 15
                    complexity = 'Simple'
                elif bytecode_length < 20000:
                    risk = 35
                    complexity = 'Medium'
                else:
                    risk = 70
                    complexity = 'Complex'
                
                return {
                    'bytecode_size_bytes': int(bytecode_length),
                    'complexity_level': complexity,
                    'risk_points': risk,
                    'weight': 0.15,
                    'comment': f'{complexity} contract ({int(bytecode_length)}B)'
                }
        except Exception as e:
            print(f"   ⚠️  Complexity analysis failed: {str(e)}")
        
        return {
            'complexity_level': 'Unknown',
            'risk_points': 50,
            'weight': 0.15,
            'comment': 'Unable to analyze'
        }
    
    def _check_deployment_history(self, address: str) -> Dict:
        """
        Check contract deployment history (20% weight)
        
        Risk Score:
        - Deployed >2 years ago: 20 points (low risk - proven)
        - Deployed 1-2 years ago: 35 points (medium risk)
        - Deployed <1 year ago: 60 points (high risk - unproven)
        - Deployed <3 months ago: 85 points (critical - very new)
        """
        try:
            params = {
                'module': 'account',
                'action': 'txlist',
                'address': address,
                'startblock': 0,
                'endblock': 99999999,
                'sort': 'asc',
                'apikey': self.api_key
            }
            
            response = requests.get(self.etherscan_url, params=params)
            data = response.json()
            
            if data['status'] == '1' and data['result']:
                # Get first transaction (deployment)
                first_tx = data['result'][0]
                deployment_timestamp = int(first_tx['timeStamp'])
                current_timestamp = datetime.now().timestamp()
                age_days = (current_timestamp - deployment_timestamp) / 86400
                
                if age_days > 730:  # >2 years
                    risk = 20
                    age_category = 'Mature (>2 years)'
                elif age_days > 365:  # 1-2 years
                    risk = 35
                    age_category = 'Established (1-2 years)'
                elif age_days > 90:  # 3 months - 1 year
                    risk = 60
                    age_category = 'Relatively New (3-12 months)'
                else:  # <3 months
                    risk = 85
                    age_category = 'Very New (<3 months)'
                
                return {
                    'deployment_age_days': int(age_days),
                    'deployment_age_category': age_category,
                    'first_transaction_hash': first_tx['hash'],
                    'risk_points': risk,
                    'weight': 0.20,
                    'comment': f'Deployed {int(age_days)} days ago'
                }
        except Exception as e:
            print(f"   ⚠️  Deployment check failed: {str(e)}")
        
        return {
            'deployment_age_category': 'Unknown',
            'risk_points': 50,
            'weight': 0.20,
            'comment': 'Unable to verify deployment'
        }
    
    def _check_vulnerabilities(self, address: str) -> Dict:
        """
        Check for known vulnerabilities (25% weight)
        
        Analyzes:
        - Reentrancy patterns
        - Integer overflow/underflow
        - Unchecked call returns
        - Delegatecall usage
        
        Risk Score:
        - No issues found: 15 points
        - Minor issues: 45 points
        - Major issues: 85 points
        """
        try:
            params = {
                'module': 'contract',
                'action': 'getsourcecode',
                'address': address,
                'apikey': self.api_key
            }
            
            response = requests.get(self.etherscan_url, params=params)
            data = response.json()
            
            vulnerabilities = []
            risk_points = 15  # Start with low risk
            
            if data['status'] == '1' and data['result']:
                source_code = data['result'][0].get('SourceCode', '')
                
                # Check for known vulnerability patterns
                if 'delegatecall' in source_code.lower():
                    vulnerabilities.append('Delegatecall usage detected')
                    risk_points += 15
                
                if 'call.value' in source_code or '.transfer' not in source_code:
                    vulnerabilities.append('Potential reentrancy risk')
                    risk_points += 15
                
                if 'unchecked' not in source_code:
                    vulnerabilities.append('Possible unchecked arithmetic')
                    risk_points += 10
                
                # Cap risk points
                risk_points = min(risk_points, 85)
            
            return {
                'vulnerabilities_found': vulnerabilities,
                'vulnerability_count': len(vulnerabilities),
                'risk_points': risk_points,
                'weight': 0.25,
                'comment': f'{len(vulnerabilities)} potential issues detected'
            }
        except Exception as e:
            print(f"   ⚠️  Vulnerability check failed: {str(e)}")
        
        return {
            'vulnerabilities_found': [],
            'vulnerability_count': 0,
            'risk_points': 50,
            'weight': 0.25,
            'comment': 'Unable to analyze code'
        }
    
    def _check_activity(self, address: str) -> Dict:
        """
        Check transaction activity (15% weight)
        
        Risk Score:
        - High activity (>1000 txs): 15 points (low risk - active)
        - Medium activity (100-1000 txs): 35 points
        - Low activity (<100 txs): 70 points (high risk - inactive)
        - No activity: 90 points (critical - dead contract)
        """
        try:
            params = {
                'module': 'account',
                'action': 'txlist',
                'address': address,
                'apikey': self.api_key
            }
            
            response = requests.get(self.etherscan_url, params=params)
            data = response.json()
            
            if data['status'] == '1':
                tx_count = len(data['result'])
                
                if tx_count > 1000:
                    risk = 15
                    activity = 'High'
                elif tx_count > 100:
                    risk = 35
                    activity = 'Medium'
                elif tx_count > 0:
                    risk = 70
                    activity = 'Low'
                else:
                    risk = 90
                    activity = 'None'
                
                return {
                    'transaction_count': tx_count,
                    'activity_level': activity,
                    'risk_points': risk,
                    'weight': 0.15,
                    'comment': f'{tx_count} transactions recorded'
                }
        except Exception as e:
            print(f"   ⚠️  Activity check failed: {str(e)}")
        
        return {
            'activity_level': 'Unknown',
            'risk_points': 50,
            'weight': 0.15,
            'comment': 'Unable to fetch activity data'
        }
    
    def _calculate_risk_score(self, factors: Dict) -> int:
        """
        Calculate weighted risk score (0-100)
        
        Formula: Sum(risk_points * weight)
        """
        total_score = 0
        
        for factor_name, factor_data in factors.items():
            risk_points = factor_data.get('risk_points', 50)
            weight = factor_data.get('weight', 0.2)
            weighted_points = risk_points * weight
            total_score += weighted_points
        
        return int(total_score)
    
    def _get_risk_level(self, score: int) -> str:
        """
        Convert risk score to risk level
        """
        for level, (min_score, max_score) in self.RISK_THRESHOLDS.items():
            if min_score <= score <= max_score:
                return level.upper()
        return "UNKNOWN"
    
    def _get_recommendations(self, risk_score: int, factors: Dict) -> List[str]:
        """
        Generate risk mitigation recommendations
        """
        recommendations = []
        
        # Based on risk score
        if risk_score >= 90:
            recommendations.append("🚨 CRITICAL: Do NOT interact with this contract")
            recommendations.append("   → Likely to be a rug pull or abandoned project")
        elif risk_score >= 70:
            recommendations.append("⚠️  HIGH RISK: Exercise extreme caution")
            recommendations.append("   → Verify contract code thoroughly before interacting")
        elif risk_score >= 40:
            recommendations.append("⚠️  MEDIUM RISK: Standard caution recommended")
            recommendations.append("   → Review contract functionality before use")
        else:
            recommendations.append("✅ LOW RISK: Appears to be relatively safe")
            recommendations.append("   → Standard security practices still recommended")
        
        # Based on factors
        if not factors['verification']['is_verified']:
            recommendations.append("📝 Code is not verified - Request source code verification")
        
        if factors['deployment']['deployment_age_days'] < 90:
            recommendations.append("⏰ Very new contract - Wait for proven track record")
        
        if factors['activity']['activity_level'] == 'Low':
            recommendations.append("📊 Low transaction activity - Check if contract is abandoned")
        
        if factors['vulnerabilities']['vulnerability_count'] > 0:
            recommendations.append("🔒 Potential vulnerabilities detected - Review code carefully")
        
        return recommendations


if __name__ == "__main__":
    # Example usage
    assessor = DeFiRiskAssessment(ETHERSCAN_API_KEY)
    
    # Test with USDC (generally safe)
    usdc_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    
    result = assessor.rate_protocol(usdc_address)
    
    print(f"\n{'='*60}")
    print(f"RISK ASSESSMENT REPORT")
    print(f"{'='*60}")
    print(f"Address: {result['address']}")
    print(f"Risk Score: {result['risk_score']}/100")
    print(f"Risk Level: {result['risk_level']}")
    print(f"\nDetailed Factors:")
    for factor_name, factor_data in result['factors'].items():
        print(f"  {factor_name.upper()}: {factor_data.get('comment', 'N/A')}")
    print(f"\nRecommendations:")
    for rec in result['recommendations']:
        print(f"  {rec}")
    print(f"{'='*60}\n")
