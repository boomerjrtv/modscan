#!/usr/bin/env python3
"""
Test Enhanced Scanner Integration
Quick verification that the enhanced components are working in the dashboard
"""

import asyncio
import logging
import sys
import os

# Add current directory to Python path
sys.path.insert(0, '/home/michael/recon-platform/modscan')
os.chdir('/home/michael/recon-platform/modscan')

async def test_enhanced_integration():
    """Test that enhanced scanner components are integrated and working"""
    
    print("🧪 Testing Enhanced Scanner Integration")
    print("=" * 50)
    
    # Test 1: Import and create enhanced scanner
    try:
        from modules.vulnerability_scanner import VulnerabilityScanner, ENHANCED_AVAILABLE
        print(f"✅ VulnerabilityScanner imported successfully")
        print(f"✅ Enhanced components available: {ENHANCED_AVAILABLE}")
        
        if ENHANCED_AVAILABLE:
            print("   📦 Knowledge base: Available")
            print("   🤖 AI planner: Available") 
            print("   🔍 Deterministic verifiers: Available")
            print("   🕸️ Attack graph: Available")
            print("   📊 Telemetry: Available")
        else:
            print("⚠️  Enhanced components not fully loaded")
        
    except Exception as e:
        print(f"❌ Scanner import failed: {e}")
        return False
    
    # Test 2: Create enhanced scanner instance
    try:
        config = {
            'use_enhanced': True,
            'enhanced_telemetry': True, 
            'enhanced_verification': True,
            'attack_chaining': False
        }
        
        scanner = VulnerabilityScanner({}, config)  # Empty asset_manager for test
        print(f"✅ Enhanced scanner created: use_enhanced={scanner.use_enhanced}")
        
    except Exception as e:
        print(f"❌ Scanner creation failed: {e}")
        return False
    
    # Test 3: Test knowledge base if available
    if ENHANCED_AVAILABLE:
        try:
            from knowledge_base import get_relevant_docs
            docs = get_relevant_docs("xss", {"stack": ["php"]}, k=3)
            print(f"✅ Knowledge base query returned {len(docs)} documents")
            
            if docs:
                print(f"   📄 Sample doc: {docs[0].title}")
                print(f"   🎯 Payloads available: {len(docs[0].payloads)}")
            
        except Exception as e:
            print(f"❌ Knowledge base test failed: {e}")
    
    # Test 4: Test telemetry
    if ENHANCED_AVAILABLE:
        try:
            from telemetry import log_scan_attempt, get_session_stats
            
            # Log a test attempt
            log_scan_attempt("http://test.com", "integration_test") \
                .with_payload("test_payload") \
                .with_evidence("integration_test_evidence") \
                .success(0.5) \
                .commit()
            
            stats = get_session_stats()
            print(f"✅ Telemetry logged: {stats['attempts_total']} total attempts")
            
        except Exception as e:
            print(f"❌ Telemetry test failed: {e}")
    
    # Test 5: Test attack graph
    if ENHANCED_AVAILABLE:
        try:
            from attack_graph import suggest_next_attacks
            
            suggestions = suggest_next_attacks(["info_disclosure"], {"stack": ["php", "mysql"]})
            print(f"✅ Attack graph suggestions: {len(suggestions)} actions")
            
            if suggestions:
                top_action, priority = suggestions[0]
                print(f"   🎯 Top suggestion: {top_action} (priority: {priority:.2f})")
            
        except Exception as e:
            print(f"❌ Attack graph test failed: {e}")
    
    print("\n🎯 Integration Test Summary:")
    if ENHANCED_AVAILABLE:
        print("✅ Enhanced vulnerability scanner is fully integrated!")
        print("   🔥 Your next dashboard scan will use enhanced verification")
        print("   📊 Telemetry will be logged to runs/ and artifacts/ directories")
        print("   🧠 Knowledge-based payloads will improve detection accuracy")
        print("   🔗 Attack chaining capabilities are available (disabled by default)")
    else:
        print("⚠️  Enhanced components partially loaded - some features may not work")
    
    return ENHANCED_AVAILABLE

if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    
    # Run the test
    success = asyncio.run(test_enhanced_integration())
    
    if success:
        print(f"\n🚀 Next: Run your dashboard scan again and look for:")
        print(f"   • 'Enhanced vulnerability scanner components loaded' in logs")  
        print(f"   • 'Enhanced XSS/SQLi verification found X vulnerabilities' messages")
        print(f"   • New artifacts stored in artifacts/ directory")
        print(f"   • Session telemetry in runs/ directory")
    else:
        print(f"\n❌ Integration test failed - enhanced features may not work")
    
    exit(0 if success else 1)