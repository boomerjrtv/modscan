#!/usr/bin/env python3
"""
Enhanced Vulnerability Scanner Integration Example
Demonstrates how to use all new components together
"""

import asyncio
import logging
from pathlib import Path

# Enhanced scanner components
from enhanced_scanner import enhanced_vulnerability_scan, create_enhanced_scanner
from telemetry import export_session_report, get_session_stats
from knowledge_base import get_relevant_docs
from attack_graph import find_exploit_chains, suggest_next_attacks

async def run_comprehensive_scan_example():
    """Example of running a comprehensive vulnerability scan"""
    
    print("🔍 Enhanced Vulnerability Scanner Demo")
    print("=" * 60)
    
    # Configuration
    config = {
        'gemini_api_key': 'your_gemini_api_key_here',  # Replace with real API key
        'callback_url': 'https://webhook.site/your-unique-id'  # For SSRF testing
    }
    
    # Target configuration
    target_url = "http://192.168.1.42/dvwa/vulnerabilities/sqli/"
    tech_stack = ["php", "mysql", "apache"]
    
    print(f"🎯 Target: {target_url}")
    print(f"🔧 Tech Stack: {', '.join(tech_stack)}")
    print()
    
    try:
        # Run enhanced scan with chaining
        print("🚀 Starting enhanced vulnerability scan...")
        result = await enhanced_vulnerability_scan(
            target_url=target_url,
            tech_stack=tech_stack,
            vulnerability_classes=["sqli.error_based", "xss.reflected", "ssrf"],
            config=config,
            enable_chaining=True  # Multi-round scanning
        )
        
        # Display results
        print(f"✅ Scan completed in {result.scan_duration:.2f} seconds")
        print(f"📊 Total HTTP requests: {result.total_requests}")
        print()
        
        # Vulnerabilities found
        if result.vulnerabilities:
            print(f"🚨 Found {len(result.vulnerabilities)} vulnerabilities:")
            print("-" * 40)
            
            for i, vuln in enumerate(result.vulnerabilities, 1):
                print(f"{i}. [{vuln.severity}] {vuln.vuln_type}")
                print(f"   Confidence: {vuln.confidence:.1%}")
                print(f"   Parameter: {vuln.affected_parameter}")
                print(f"   Payload: {vuln.payload}")
                print(f"   Evidence: {vuln.evidence[:100]}...")
                print()
        else:
            print("✅ No vulnerabilities found with high confidence")
        
        # Attack chains
        if result.attack_chains:
            print(f"🔗 Discovered {len(result.attack_chains)} attack chains:")
            print("-" * 40)
            
            for i, chain in enumerate(result.attack_chains, 1):
                print(f"{i}. {' → '.join(chain.capabilities)}")
                print(f"   Success probability: {chain.success_probability:.1%}")
                print(f"   Estimated time: {chain.estimated_time:.1f} minutes")
                print(f"   Stealth score: {chain.stealth_score:.1%}")
                print(f"   Description: {chain.description}")
                print()
        
        # Next recommended actions
        if result.next_recommended_actions:
            print("💡 Recommended next actions:")
            print("-" * 40)
            
            for action, priority in result.next_recommended_actions[:5]:
                print(f"   {action} (priority: {priority:.2f})")
            print()
        
        # Evidence artifacts
        if result.evidence_artifacts:
            print(f"📁 Stored {len(result.evidence_artifacts)} evidence artifacts")
            print("   Artifacts contain HTTP responses, headers, and proof-of-concept data")
            print()
        
        # Confidence scores by vulnerability type
        if result.confidence_scores:
            print("📈 Confidence scores by vulnerability type:")
            for vuln_type, confidence in result.confidence_scores.items():
                print(f"   {vuln_type}: {confidence:.1%}")
            print()
        
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        logging.error(f"Scan error: {e}", exc_info=True)

async def demonstrate_knowledge_base():
    """Demonstrate knowledge base queries"""
    
    print("\n📚 Knowledge Base Demo")
    print("=" * 60)
    
    # Query for XSS knowledge
    fingerprint = {
        "stack": ["javascript", "react", "nodejs"],
        "params": ["search", "comment", "message"]
    }
    
    print("🔍 Querying knowledge base for XSS vulnerabilities...")
    docs = get_relevant_docs("xss reflected", fingerprint, k=5)
    
    if docs:
        print(f"Found {len(docs)} relevant knowledge documents:")
        for doc in docs:
            print(f"  📄 {doc.title} (score: {doc.relevance_score:.2f})")
            print(f"     Category: {doc.category}")
            print(f"     Payloads: {len(doc.payloads)} available")
            print(f"     Content: {doc.content[:80]}...")
            print()
    else:
        print("No relevant documents found")

def demonstrate_attack_graph():
    """Demonstrate attack graph and chaining"""
    
    print("\n🕸️ Attack Graph Demo")
    print("=" * 60)
    
    # Simulate having discovered some capabilities
    current_capabilities = ["info_disclosure", "sqli_error_based"]
    target_capabilities = ["auth_bypass", "idor_vertical"]
    
    print(f"Current capabilities: {', '.join(current_capabilities)}")
    print(f"Target capabilities: {', '.join(target_capabilities)}")
    print()
    
    # Find attack chains
    chains = find_exploit_chains(current_capabilities, target_capabilities)
    
    if chains:
        print(f"🔗 Found {len(chains)} attack chains:")
        for i, chain in enumerate(chains, 1):
            print(f"  {i}. {' → '.join(chain.capabilities)}")
            print(f"     Success: {chain.success_probability:.1%}, Time: {chain.estimated_time:.1f}min")
            print(f"     Stealth: {chain.stealth_score:.1%}")
            print()
    
    # Get next action suggestions
    context = {
        "tech_stack": ["php", "mysql"],
        "parameters": ["id", "username", "password"]
    }
    
    suggestions = suggest_next_attacks(current_capabilities, context)
    
    if suggestions:
        print("💡 Next recommended actions:")
        for action, priority in suggestions[:5]:
            print(f"  {action} (priority: {priority:.2f})")

def show_session_statistics():
    """Display current session statistics"""
    
    print("\n📊 Session Statistics")
    print("=" * 60)
    
    stats = get_session_stats()
    
    print(f"Session ID: {stats['session_id']}")
    print(f"Duration: {stats['session_duration_seconds']:.1f} seconds")
    print(f"Total attempts: {stats['attempts_total']}")
    print(f"Successful attempts: {stats['attempts_success']}")
    print(f"Success rate: {stats['success_rate']:.1%}")
    print(f"Vulnerabilities found: {stats['vulnerabilities_found']}")
    print(f"Average response time: {stats['average_response_time']:.1f}ms")
    print(f"Attempts per minute: {stats['attempts_per_minute']:.1f}")
    print(f"Artifacts stored: {stats['artifacts_stored']}")
    print(f"Log file size: {stats['log_file_size_mb']:.2f} MB")

async def smoke_test():
    """Quick smoke test of all components"""
    
    print("\n🧪 Component Smoke Test")
    print("=" * 60)
    
    tests_passed = 0
    total_tests = 5
    
    # Test 1: Knowledge base
    try:
        docs = get_relevant_docs("test", {}, k=1)
        print("✅ Knowledge base: OK")
        tests_passed += 1
    except Exception as e:
        print(f"❌ Knowledge base: {e}")
    
    # Test 2: Attack graph
    try:
        chains = find_exploit_chains(["info_disclosure"], ["auth_bypass"])
        print("✅ Attack graph: OK")
        tests_passed += 1
    except Exception as e:
        print(f"❌ Attack graph: {e}")
    
    # Test 3: Telemetry
    try:
        from telemetry import log_scan_attempt
        log_scan_attempt("http://test.com", "smoke_test").success(0.5).commit()
        print("✅ Telemetry: OK")
        tests_passed += 1
    except Exception as e:
        print(f"❌ Telemetry: {e}")
    
    # Test 4: Deterministic verifiers
    try:
        from deterministic_verifiers import DeterministicVerifiers
        verifiers = DeterministicVerifiers()
        context = verifiers._analyze_xss_context("<div>test</div>", "test")
        print("✅ Deterministic verifiers: OK")
        tests_passed += 1
    except Exception as e:
        print(f"❌ Deterministic verifiers: {e}")
    
    # Test 5: AI Planner (basic validation only, no API call)
    try:
        from ai_planner import AIPlanner
        planner = AIPlanner({})
        fingerprint = planner.build_fingerprint("http://test.com", ["php"])
        print("✅ AI Planner: OK")
        tests_passed += 1
    except Exception as e:
        print(f"❌ AI Planner: {e}")
    
    print(f"\n🎯 Smoke test results: {tests_passed}/{total_tests} components working")
    
    return tests_passed == total_tests

async def main():
    """Main demonstration function"""
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("🚀 Enhanced Vulnerability Scanner Integration Demo")
    print("=" * 80)
    print()
    
    # Run smoke test first
    if not await smoke_test():
        print("❌ Smoke test failed - some components may not work properly")
        print("   Check dependencies and configuration")
        return
    
    print("\n" + "=" * 80)
    
    # Demonstrate individual components
    await demonstrate_knowledge_base()
    demonstrate_attack_graph()
    
    # Show current session stats
    show_session_statistics()
    
    print("\n" + "=" * 80)
    
    # Run comprehensive scan (requires valid target and API key)
    print("\n⚠️  To run the full scan demo:")
    print("1. Set a valid Gemini API key in the config")
    print("2. Ensure the target URL is accessible")
    print("3. Uncomment the line below")
    print()
    
    # Uncomment the next line to run the full scan
    # await run_comprehensive_scan_example()
    
    # Export session report
    print("📄 Exporting session report...")
    report_path = export_session_report()
    print(f"   Report saved to: {report_path}")
    
    print("\n✅ Demo completed successfully!")
    print("   Check the 'runs/', 'artifacts/', and 'telemetry/' directories for detailed logs")

if __name__ == "__main__":
    # Run the demonstration
    asyncio.run(main())