#!/usr/bin/env python3
"""
Scanner Refinement Tool
Uses HackerOne disclosed reports to improve ModScan detection patterns
"""

import pandas as pd
import re
from collections import defaultdict, Counter
import sqlite3
from urllib.parse import urlparse

class ScannerRefinement:
    def __init__(self, hackerone_csv="hackerone-reports/data.csv", db_path="lean_recon.db"):
        self.hackerone_csv = hackerone_csv
        self.db_path = db_path
        self.load_reports()
    
    def load_reports(self):
        """Load HackerOne reports data"""
        try:
            self.df = pd.read_csv(self.hackerone_csv)
            print(f"Loaded {len(self.df)} HackerOne reports")
        except Exception as e:
            print(f"Error loading reports: {e}")
            self.df = pd.DataFrame()
    
    def analyze_xss_patterns(self):
        """Analyze XSS vulnerability patterns from HackerOne reports"""
        
        xss_reports = self.df[self.df['vuln_type'].str.contains('XSS', case=False, na=False)]
        print(f"\n🔍 Analyzing {len(xss_reports)} XSS reports")
        
        patterns = {
            'reflected_indicators': [],
            'stored_indicators': [],
            'parameter_names': [],
            'attack_vectors': [],
            'vulnerable_endpoints': []
        }
        
        for _, report in xss_reports.iterrows():
            title = str(report['title']).lower()
            vuln_type = str(report['vuln_type']).lower()
            
            # Extract parameter names mentioned in titles
            param_matches = re.findall(r'via\s+(\w+)\s+parameter', title)
            param_matches += re.findall(r'in\s+(\w+)\s+parameter', title)
            param_matches += re.findall(r'parameter\s+(\w+)', title)
            param_matches += re.findall(r'field\s+(\w+)', title)
            patterns['parameter_names'].extend(param_matches)
            
            # Extract endpoints/paths mentioned
            endpoint_matches = re.findall(r'/[\w/\-\.]+', title)
            patterns['vulnerable_endpoints'].extend(endpoint_matches)
            
            # Classify XSS type indicators
            if 'reflected' in vuln_type or 'rxss' in title:
                patterns['reflected_indicators'].append(title)
            elif 'stored' in vuln_type:
                patterns['stored_indicators'].append(title)
            
            # Extract attack vectors
            if 'customerId' in title:
                patterns['attack_vectors'].append('customerId parameter')
            if 'notes' in title:
                patterns['attack_vectors'].append('notes field')
            if 'name' in title:
                patterns['attack_vectors'].append('name field')
        
        # Get top patterns
        top_params = Counter(patterns['parameter_names']).most_common(10)
        top_endpoints = Counter(patterns['vulnerable_endpoints']).most_common(10)
        
        print(f"\n📊 XSS Pattern Analysis:")
        print(f"Top vulnerable parameters: {top_params}")
        print(f"Top vulnerable endpoints: {top_endpoints}")
        
        return patterns
    
    def analyze_sqli_patterns(self):
        """Analyze SQL injection patterns"""
        
        sqli_reports = self.df[self.df['vuln_type'].str.contains('SQL', case=False, na=False)]
        print(f"\n🔍 Analyzing {len(sqli_reports)} SQL injection reports")
        
        patterns = {
            'injection_points': [],
            'techniques': [],
            'vulnerable_params': [],
            'endpoints': []
        }
        
        for _, report in sqli_reports.iterrows():
            title = str(report['title']).lower()
            
            # Extract injection techniques
            if 'blind' in title:
                patterns['techniques'].append('blind')
            if 'boolean' in title:
                patterns['techniques'].append('boolean_based')
            if 'time' in title:
                patterns['techniques'].append('time_based')
            if 'union' in title:
                patterns['techniques'].append('union_based')
                
            # Extract vulnerable parameters/points
            param_matches = re.findall(r'via\s+(\w+)', title)
            param_matches += re.findall(r'in\s+(\w+)', title)
            patterns['vulnerable_params'].extend(param_matches)
            
            # Extract injection points
            if 'user agent' in title:
                patterns['injection_points'].append('user_agent')
            if 'header' in title:
                patterns['injection_points'].append('headers')
            if 'cookie' in title:
                patterns['injection_points'].append('cookies')
        
        top_techniques = Counter(patterns['techniques']).most_common(5)
        top_params = Counter(patterns['vulnerable_params']).most_common(10)
        top_injection_points = Counter(patterns['injection_points']).most_common(5)
        
        print(f"\n📊 SQL Injection Pattern Analysis:")
        print(f"Top techniques: {top_techniques}")
        print(f"Top vulnerable parameters: {top_params}")
        print(f"Top injection points: {top_injection_points}")
        
        return patterns
    
    def analyze_ssrf_patterns(self):
        """Analyze SSRF patterns"""
        
        ssrf_reports = self.df[self.df['vuln_type'].str.contains('SSRF', case=False, na=False)]
        print(f"\n🔍 Analyzing {len(ssrf_reports)} SSRF reports")
        
        patterns = {
            'vulnerable_params': [],
            'endpoints': [],
            'techniques': []
        }
        
        for _, report in ssrf_reports.iterrows():
            title = str(report['title']).lower()
            
            # Extract parameter patterns
            param_matches = re.findall(r'via\s+(\w+)', title)
            param_matches += re.findall(r'in\s+(\w+)', title)
            param_matches += re.findall(r'parameter\s+(\w+)', title)
            patterns['vulnerable_params'].extend(param_matches)
            
            # Common SSRF indicators
            if 'url' in title:
                patterns['vulnerable_params'].append('url')
            if 'callback' in title:
                patterns['vulnerable_params'].append('callback')
            if 'redirect' in title:
                patterns['vulnerable_params'].append('redirect')
            if 'webhook' in title:
                patterns['vulnerable_params'].append('webhook')
        
        top_params = Counter(patterns['vulnerable_params']).most_common(10)
        
        print(f"\n📊 SSRF Pattern Analysis:")
        print(f"Top vulnerable parameters: {top_params}")
        
        return patterns
    
    def compare_with_scanner_findings(self):
        """Compare HackerOne patterns with ModScan findings"""
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get ModScan vulnerability types
            cursor.execute("SELECT type, COUNT(*) FROM vulnerabilities GROUP BY type")
            scanner_findings = dict(cursor.fetchall())
            
            conn.close()
            
            print(f"\n🔄 ModScan vs HackerOne Comparison:")
            print(f"ModScan found: {scanner_findings}")
            
            # Get HackerOne vulnerability types
            h1_vuln_types = self.df['vuln_type'].value_counts().head(10)
            print(f"\nTop HackerOne vulnerability types:")
            for vuln_type, count in h1_vuln_types.items():
                print(f"  {vuln_type}: {count}")
                
            return scanner_findings, h1_vuln_types.to_dict()
            
        except Exception as e:
            print(f"Error comparing findings: {e}")
            return {}, {}
    
    def generate_refinement_recommendations(self):
        """Generate specific recommendations for scanner improvement"""
        
        print(f"\n🎯 SCANNER REFINEMENT RECOMMENDATIONS:")
        
        # Analyze patterns
        xss_patterns = self.analyze_xss_patterns()
        sqli_patterns = self.analyze_sqli_patterns() 
        ssrf_patterns = self.analyze_ssrf_patterns()
        
        # Compare with current findings
        scanner_findings, h1_findings = self.compare_with_scanner_findings()
        
        recommendations = []
        
        # XSS Recommendations
        top_xss_params = Counter(xss_patterns['parameter_names']).most_common(5)
        recommendations.append(f"🔥 XSS: Focus on these parameters: {[p[0] for p in top_xss_params]}")
        
        # SQL Injection Recommendations  
        top_sqli_techniques = Counter(sqli_patterns['techniques']).most_common(3)
        recommendations.append(f"💉 SQLi: Implement these techniques: {[t[0] for t in top_sqli_techniques]}")
        
        # SSRF Recommendations
        top_ssrf_params = Counter(ssrf_patterns['vulnerable_params']).most_common(5)
        recommendations.append(f"🌐 SSRF: Target these parameters: {[p[0] for p in top_ssrf_params]}")
        
        # Coverage gaps
        if scanner_findings.get('XSS', 0) < 50:
            recommendations.append("⚠️ XSS detection seems low - consider more aggressive payloads")
        
        if 'boolean_based' in [t[0] for t in Counter(sqli_patterns['techniques']).most_common(3)]:
            recommendations.append("⚠️ Add boolean-based blind SQL injection detection")
        
        print("\n" + "\n".join(recommendations))
        return recommendations

def main():
    """Run scanner refinement analysis"""
    
    refiner = ScannerRefinement()
    
    if len(refiner.df) > 0:
        recommendations = refiner.generate_refinement_recommendations()
        
        print(f"\n✅ Analysis complete - {len(recommendations)} recommendations generated")
    else:
        print("❌ No HackerOne data found")

if __name__ == "__main__":
    main()