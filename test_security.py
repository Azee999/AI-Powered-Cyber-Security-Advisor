import requests
import json

BASE_URL = "http://localhost:5000"

# Test data for phishing email detection
phishing_tests = [
    {
        "content": """
        From: "Apple Support" <support@apple-security.com>
        Subject: Urgent: Your iCloud has been locked!
        
        Dear Customer,
        We detected unusual activity. Verify your account immediately:
        http://apple-verify-account.com?id=12345
        
        Failure to respond within 24 hours will result in account termination.
        """,
        "expected": True,
        "reason": "Urgent language + suspicious link"
    },
    {
        "content": """
        From: "PayPal" <service@paypal-confirm.net>
        Subject: Payment Alert
        
        Hello User,
        We need to confirm your recent payment of $499.99.
        Click here to verify: http://paypal-secure-login.com/confirm
        
        Thank you,
        PayPal Team
        """,
        "expected": True,
        "reason": "Mismatched sender domain"
    },
    {
        "content": """
        From: "GitHub Notifications" <noreply@github.com>
        Subject: Your weekly digest
        
        Here's your weekly activity summary:
        - 3 new commits
        - 2 closed issues
        
        View details: https://github.com
        """,
        "expected": False,
        "reason": "Legitimate GitHub email"
    }
]

# Test data for password breach checking
password_tests = [
    {
        "password": "password123", 
        "expected": True,
        "reason": "Common breached password"
    },
    {
        "password": "admin", 
        "expected": True,
        "reason": "Extremely common password"
    },
    {
        "password": "QwErTy!@#2023", 
        "expected": False,
        "reason": "Strong unique password"
    }
]

# Test data for URL scanning
url_tests = [
    {
        "url": "http://phishing-test.com/login",
        "expected": True,
        "reason": "Known phishing pattern"
    },
    {
        "url": "https://www.google.com",
        "expected": False,
        "reason": "Legitimate website"
    },
    {
        "url": "http://malware.testing.google.test/testing/malware/",
        "expected": True,
        "reason": "Test malware URL"
    }
]

def test_email_analysis():
    print("\n=== Testing Email Analysis ===")
    for test in phishing_tests:
        try:
            response = requests.post(
                f"{BASE_URL}/analyze-email",
                json={"content": test['content']},
                timeout=5
            )
            result = response.json()
            passed = result['is_phishing'] == test['expected']
            
            print(f"\nTest: {test['reason']}")
            print(f"Expected: {test['expected']} | Result: {result['is_phishing']}")
            print(f"Risk Score: {result.get('risk_score', 'N/A')}")
            print(f"Reasons: {', '.join(result.get('reasons', ['N/A']))}")
            print(f"Status: {'PASS' if passed else 'FAIL'}")
            
        except Exception as e:
            print(f"\nFailed to test email: {str(e)}")
            print(f"Content: {test['content'][:50]}...")
            print("Status: ERROR")

def test_password_check():
    print("\n=== Testing Password Check ===")
    for test in password_tests:
        try:
            response = requests.post(
                f"{BASE_URL}/check-password",
                json={"password": test['password']},
                timeout=5
            )
            result = response.json()
            passed = result['is_breached'] == test['expected']
            
            print(f"\nPassword: {test['password']}")
            print(f"Expected: {test['expected']} | Result: {result['is_breached']}")
            if result['is_breached']:
                print(f"Breach Count: {result.get('breach_count', 'Unknown')}")
            print(f"Reason: {result.get('reason', 'Not breached')}")
            print(f"Status: {'PASS' if passed else 'FAIL'}")
            
        except Exception as e:
            print(f"\nFailed to test password: {str(e)}")
            print(f"Password: {test['password']}")
            print("Status: ERROR")

def test_url_scanning():
    print("\n=== Testing URL Scanning ===")
    for test in url_tests:
        try:
            response = requests.post(
                f"{BASE_URL}/scan-url",
                json={"url": test['url']},
                timeout=5
            )
            result = response.json()
            passed = result['is_malicious'] == test['expected']
            
            print(f"\nURL: {test['url']}")
            print(f"Expected: {test['expected']} | Result: {result['is_malicious']}")
            print(f"Details: {result.get('details', 'N/A')[:100]}...")
            print(f"Status: {'PASS' if passed else 'FAIL'}")
            
        except Exception as e:
            print(f"\nFailed to test URL: {str(e)}")
            print(f"URL: {test['url']}")
            print("Status: ERROR")

def test_report_generation():
    print("\n=== Testing Report Generation ===")
    try:
        response = requests.get(f"{BASE_URL}/generate-report", timeout=10)
        if response.status_code == 200:
            with open("test_report.pdf", "wb") as f:
                f.write(response.content)
            print("Status: PASS (Report generated successfully)")
            print("Saved as: test_report.pdf")
        else:
            print(f"Status: FAIL (HTTP {response.status_code})")
            print(f"Response: {response.text[:200]}...")
    except Exception as e:
        print(f"Status: ERROR - {str(e)}")

if __name__ == "__main__":
    # First ensure the server is running
    print("=== AI Cybersecurity Advisor Tests ===")
    print("Note: Ensure the Flask server is running before testing!")
    
    test_email_analysis()
    test_password_check()
    test_url_scanning()
    test_report_generation()
    
    print("\n=== All tests completed ===")