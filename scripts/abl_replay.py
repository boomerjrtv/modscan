#!/usr/bin/env python3
"""
ABL Skill Replay CLI

Simple command-line tool to replay generated ABL skills for debugging
and verification purposes.

Usage:
    python scripts/abl_replay.py tools/skills/example-skill.py
    python scripts/abl_replay.py tools/skills/ --all
"""

import argparse
import sys
import subprocess
from pathlib import Path

def replay_skill(skill_path: Path) -> bool:
    """Replay a single skill script"""
    if not skill_path.exists():
        print(f"❌ Skill file not found: {skill_path}")
        return False
        
    if not skill_path.suffix == '.py':
        print(f"❌ Not a Python script: {skill_path}")
        return False
        
    print(f"🎬 Replaying skill: {skill_path.name}")
    
    try:
        result = subprocess.run([
            sys.executable, str(skill_path)
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print(f"✅ Skill completed successfully")
            if result.stdout:
                print(f"📄 Output: {result.stdout.strip()}")
        else:
            print(f"❌ Skill failed with exit code {result.returncode}")
            if result.stderr:
                print(f"🚨 Error: {result.stderr.strip()}")
                
        return result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print("⏰ Skill execution timed out (30s)")
        return False
    except Exception as e:
        print(f"💥 Execution error: {e}")
        return False

def list_skills(skills_dir: Path):
    """List available skill files"""
    if not skills_dir.exists():
        print(f"❌ Skills directory not found: {skills_dir}")
        return []
        
    skills = list(skills_dir.glob("*.py"))
    if not skills:
        print(f"📭 No skills found in {skills_dir}")
        return []
        
    print(f"📚 Found {len(skills)} skill(s):")
    for i, skill in enumerate(skills, 1):
        print(f"  {i}. {skill.name}")
        
    return skills

def main():
    parser = argparse.ArgumentParser(
        description="Replay ABL-generated skills",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/abl_replay.py tools/skills/example-xss.py
  python scripts/abl_replay.py tools/skills/ --all  
  python scripts/abl_replay.py tools/skills/ --list
        """
    )
    
    parser.add_argument('path', help='Path to skill file or skills directory')
    parser.add_argument('--all', action='store_true', 
                       help='Replay all skills in directory')
    parser.add_argument('--list', action='store_true',
                       help='List available skills')
    
    args = parser.parse_args()
    
    skill_path = Path(args.path)
    
    if skill_path.is_file():
        # Single skill replay
        success = replay_skill(skill_path)
        sys.exit(0 if success else 1)
        
    elif skill_path.is_dir():
        skills = list_skills(skill_path)
        
        if args.list:
            sys.exit(0)
            
        if args.all:
            # Replay all skills
            successes = 0
            for skill in skills:
                if replay_skill(skill):
                    successes += 1
                print()  # Blank line between skills
                
            print(f"📊 Results: {successes}/{len(skills)} skills succeeded")
            sys.exit(0 if successes == len(skills) else 1)
        else:
            print("💡 Use --all to replay all skills or --list to list them")
            sys.exit(0)
    else:
        print(f"❌ Path not found: {skill_path}")
        sys.exit(1)

if __name__ == '__main__':
    main()