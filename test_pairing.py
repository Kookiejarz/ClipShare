#!/usr/bin/env python3
"""
Simple test script to demonstrate the pairing functionality
"""

import asyncio
import json
from utils.connection_utils import PairingManager

async def test_pairing_code_generation():
    """Test pairing code generation"""
    print("🧪 Testing pairing code generation...")
    
    # Generate several pairing codes
    for i in range(5):
        code = PairingManager.generate_pairing_code()
        print(f"  Generated code {i+1}: {code}")
        assert len(code) == 6, f"Code should be 6 digits, got {len(code)}"
        assert code.isdigit(), f"Code should be numeric, got {code}"
    
    print("✅ Pairing code generation test passed!")

def test_pairing_message_format():
    """Test pairing message format"""
    print("🧪 Testing pairing message format...")
    
    # Test pairing request message
    pairing_request = {
        'type': 'pairing_request',
        'identity': 'test-device-123',
        'device_name': 'Test Windows PC',
        'platform': 'windows',
        'pairing_code': '123456'
    }
    
    # Verify the message can be serialized
    json_str = json.dumps(pairing_request)
    parsed = json.loads(json_str)
    
    assert parsed['type'] == 'pairing_request'
    assert parsed['pairing_code'] == '123456'
    
    # Test pairing response message
    pairing_response = {
        'type': 'pairing_response',
        'status': 'accepted',
        'token': 'abc123def456',
        'server_id': 'mac-server'
    }
    
    json_str = json.dumps(pairing_response)
    parsed = json.loads(json_str)
    
    assert parsed['status'] == 'accepted'
    assert parsed['token'] == 'abc123def456'
    
    print("✅ Pairing message format test passed!")

async def main():
    """Run all tests"""
    print("🚀 Starting pairing system tests...\n")
    
    await test_pairing_code_generation()
    print()
    
    test_pairing_message_format()
    print()
    
    print("🎉 All pairing tests completed successfully!")
    print("\n📋 How to test the full pairing flow:")
    print("1. Start the Mac server: python3 mac_clip_check.py")
    print("2. Delete any existing Windows device token file")
    print("3. Start the Windows client: python windows_client.py")
    print("4. The Windows client will generate a pairing code")
    print("5. Confirm the pairing code on the Mac side")
    print("6. The devices should connect and sync clipboards")

if __name__ == "__main__":
    asyncio.run(main())