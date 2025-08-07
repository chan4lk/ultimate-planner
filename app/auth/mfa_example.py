"""
MFA Usage Examples for Ultimate Planner
========================================

This file contains example code showing how to use the MFA system.
"""

import asyncio
import pyotp
from datetime import datetime
from app.auth.mfa_service import MFAService
from app.auth.service import AuthService
from app.database import get_db

# Example 1: Setting up MFA for a user
async def example_mfa_setup():
    """Example of setting up MFA for a user."""
    db = next(get_db())
    mfa_service = MFAService(db)
    user_id = "example-user-id"
    
    # Setup MFA
    setup_response = await mfa_service.setup_mfa(user_id, app_name="Ultimate Planner")
    
    print("MFA Setup Response:")
    print(f"Secret Key: {setup_response.secret_key}")
    print(f"QR Code URL: {setup_response.qr_code_url}")
    print(f"Backup Codes: {setup_response.backup_codes}")
    
    # Generate QR code
    qr_code_data = mfa_service.generate_qr_code(user_id)
    print(f"QR Code size: {len(qr_code_data)} bytes")
    
    return setup_response

# Example 2: Verifying TOTP token
async def example_totp_verification():
    """Example of verifying a TOTP token."""
    db = next(get_db())
    mfa_service = MFAService(db)
    user_id = "example-user-id"
    
    # This would be the secret from setup
    secret = "JBSWY3DPEHPK3PXP"
    
    # Generate current TOTP token
    totp = pyotp.TOTP(secret)
    current_token = totp.now()
    
    print(f"Current TOTP token: {current_token}")
    
    # Verify token
    is_valid = await mfa_service.verify_totp_token(user_id, current_token)
    print(f"Token valid: {is_valid}")

# Example 3: Enhanced login flow
async def example_enhanced_login():
    """Example of the enhanced login flow with MFA."""
    db = next(get_db())
    auth_service = AuthService(db)
    
    from app.auth.schemas_mfa import LoginWithMFARequest
    
    # Step 1: Login without MFA token
    login_request = LoginWithMFARequest(
        email="user@example.com",
        password="user_password"
    )
    
    response = await auth_service.login_with_mfa(login_request)
    
    if hasattr(response, 'requires_mfa') and response.requires_mfa:
        print("MFA required!")
        print(f"Temporary token: {response.temporary_token}")
        
        # Step 2: Complete with MFA token
        from app.auth.schemas_mfa import CompleteMFALoginRequest
        
        complete_request = CompleteMFALoginRequest(
            temporary_token=response.temporary_token,
            mfa_token="123456"  # User enters this
        )
        
        final_response = await auth_service.complete_mfa_login(complete_request)
        print(f"Login successful: {final_response['access_token']}")
    else:
        print("No MFA required, login successful")
        print(f"Access token: {response['access_token']}")

# Example 4: Backup code usage
async def example_backup_code_usage():
    """Example of using backup codes."""
    db = next(get_db())
    mfa_service = MFAService(db)
    user_id = "example-user-id"
    
    # Setup MFA first to get backup codes
    setup = await mfa_service.setup_mfa(user_id)
    backup_codes = setup.backup_codes
    
    print(f"Generated backup codes: {backup_codes}")
    
    # Use first backup code
    first_code = backup_codes[0]
    is_valid = await mfa_service.verify_backup_code(user_id, first_code)
    print(f"Backup code '{first_code}' valid: {is_valid}")
    
    # Try to use same code again (should fail)
    is_valid_again = await mfa_service.verify_backup_code(user_id, first_code)
    print(f"Same backup code valid again: {is_valid_again}")  # False
    
    # Check remaining backup codes
    status = await mfa_service.get_mfa_status(user_id)
    print(f"Remaining backup codes: {status.backup_codes_remaining}")

# Example 5: MFA status and management
async def example_mfa_management():
    """Example of MFA status and management operations."""
    db = next(get_db())
    mfa_service = MFAService(db)
    user_id = "example-user-id"
    
    # Check initial status
    status = await mfa_service.get_mfa_status(user_id)
    print(f"MFA enabled: {status.is_enabled}")
    print(f"Setup completed: {status.setup_completed}")
    print(f"Backup codes remaining: {status.backup_codes_remaining}")
    
    if not status.setup_completed:
        # Setup MFA
        setup = await mfa_service.setup_mfa(user_id)
        
        # Enable MFA (requires valid TOTP token)
        # In real usage, user would provide token from their authenticator app
        secret = setup.secret_key
        totp = pyotp.TOTP(secret)
        token = totp.now()
        
        success = await mfa_service.enable_mfa(user_id, token)
        print(f"MFA enabled: {success}")
    
    # Regenerate backup codes
    new_codes = await mfa_service.regenerate_backup_codes(user_id)
    print(f"New backup codes: {new_codes.backup_codes}")

# Example 6: Security monitoring
async def example_security_monitoring():
    """Example of security monitoring and audit logs."""
    db = next(get_db())
    mfa_service = MFAService(db)
    user_id = "example-user-id"
    
    # Get recent MFA attempts
    attempts = await mfa_service.get_recent_attempts(user_id, limit=5)
    
    print("Recent MFA attempts:")
    for attempt in attempts:
        print(f"- {attempt.created_at}: {attempt.attempt_type} "
              f"({'success' if attempt.success else 'failed'}) "
              f"from {attempt.ip_address}")

# Example 7: API endpoint usage
def example_api_usage():
    """Example of using MFA API endpoints."""
    
    print("""
    API Usage Examples:
    
    1. Setup MFA:
    curl -X POST -H "Authorization: Bearer <token>" \\
         http://localhost:8000/auth/mfa/setup
    
    2. Get QR Code:
    curl -H "Authorization: Bearer <token>" \\
         http://localhost:8000/auth/mfa/qr-code \\
         --output qr_code.png
    
    3. Verify Token:
    curl -X POST -H "Authorization: Bearer <token>" \\
         -H "Content-Type: application/json" \\
         -d '{"token":"123456"}' \\
         http://localhost:8000/auth/mfa/verify
    
    4. Enable MFA:
    curl -X POST -H "Authorization: Bearer <token>" \\
         -H "Content-Type: application/json" \\
         -d '{"token":"123456"}' \\
         http://localhost:8000/auth/mfa/enable
    
    5. Enhanced Login:
    curl -X POST -H "Content-Type: application/json" \\
         -d '{"email":"user@example.com","password":"password","mfa_token":"123456"}' \\
         http://localhost:8000/auth/login-mfa
    
    6. Complete MFA Login:
    curl -X POST -H "Content-Type: application/json" \\
         -d '{"temporary_token":"temp_token","mfa_token":"123456"}' \\
         http://localhost:8000/auth/complete-mfa
    """)

# Example 8: Error handling
async def example_error_handling():
    """Example of proper error handling with MFA."""
    db = next(get_db())
    mfa_service = MFAService(db)
    user_id = "example-user-id"
    
    try:
        # Try to verify invalid token
        is_valid = await mfa_service.verify_totp_token(user_id, "000000")
        print(f"Invalid token result: {is_valid}")
    except Exception as e:
        print(f"Error verifying token: {e}")
    
    try:
        # Try to setup MFA for non-existent user
        await mfa_service.setup_mfa("non-existent-user")
    except Exception as e:
        print(f"Error setting up MFA: {e}")

# Run examples
if __name__ == "__main__":
    print("MFA System Examples")
    print("==================")
    
    # Run async examples
    loop = asyncio.get_event_loop()
    
    print("\n1. MFA Setup Example:")
    loop.run_until_complete(example_mfa_setup())
    
    print("\n2. TOTP Verification Example:")
    loop.run_until_complete(example_totp_verification())
    
    print("\n3. Enhanced Login Example:")
    loop.run_until_complete(example_enhanced_login())
    
    print("\n4. Backup Code Usage Example:")
    loop.run_until_complete(example_backup_code_usage())
    
    print("\n5. MFA Management Example:")
    loop.run_until_complete(example_mfa_management())
    
    print("\n6. Security Monitoring Example:")
    loop.run_until_complete(example_security_monitoring())
    
    print("\n7. API Usage Examples:")
    example_api_usage()
    
    print("\n8. Error Handling Example:")
    loop.run_until_complete(example_error_handling())
    
    print("\nAll examples completed!")