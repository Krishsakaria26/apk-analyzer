import sys
import os
import json
import hashlib

from androguard.misc import AnalyzeAPK
from colorama import Fore, Style, init
from pyfiglet import Figlet

# Initialize colorama
init(autoreset=True)

# Banner
f = Figlet(font='slant')
print(Fore.GREEN + f.renderText('APK Analyzer'))

# Dangerous permissions list
dangerous_permissions = [
    "SEND_SMS",
    "READ_SMS",
    "RECEIVE_SMS",
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "READ_CALL_LOG",
    "RECORD_AUDIO",
    "CAMERA",
    "ACCESS_FINE_LOCATION",
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
    "SYSTEM_ALERT_WINDOW",
    "READ_PHONE_STATE",
    "REQUEST_INSTALL_PACKAGES",
    "BIND_ACCESSIBILITY_SERVICE",
    "PACKAGE_USAGE_STATS"
]


# Generate SHA256 Hash
def generate_sha256(file_path):

    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:

        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()


# Risk calculation
def calculate_risk(score):

    if score >= 60:
        return "HIGH", "DO NOT INSTALL", Fore.RED

    elif score >= 30:
        return "MEDIUM", "INSTALL WITH CAUTION", Fore.YELLOW

    else:
        return "LOW", "SAFE TO INSTALL", Fore.GREEN


# Main analyzer
def analyze_apk(apk_path):

    print(Fore.CYAN + "\n[+] Scanning APK...\n")

    try:
        a, d, dx = AnalyzeAPK(apk_path)

    except Exception as e:
        print(Fore.RED + f"[!] Error analyzing APK: {e}")
        return

    permissions = a.get_permissions()

    dangerous_found = []
    risk_score = 0

    # Permission analysis
    for permission in permissions:

        for danger in dangerous_permissions:

            if danger in permission:
                dangerous_found.append(permission)
                risk_score += 10

    # Risk level
    risk_level, recommendation, color = calculate_risk(risk_score)

    # Risk percentage
    risk_percentage = min(risk_score, 100)

    # APK size
    file_size = round(os.path.getsize(apk_path) / (1024 * 1024), 2)

    # SHA256 Hash
    apk_hash = generate_sha256(apk_path)

    # Output
    print(Fore.CYAN + "=" * 65)

    print(Fore.WHITE + f"App Name            : {a.get_app_name()}")
    print(Fore.WHITE + f"Package Name        : {a.get_package()}")
    print(Fore.WHITE + f"APK Size            : {file_size} MB")
    print(Fore.WHITE + f"Total Permissions   : {len(permissions)}")
    print(Fore.WHITE + f"SHA256 Hash         : {apk_hash}")

    print(color + f"[!] Risk Level       : {risk_level}")
    print(color + f"[!] Risk Score       : {risk_score}")
    print(color + f"[!] Risk Percentage  : {risk_percentage}%")
    print(color + f"[!] Recommendation   : {recommendation}")

    print(Fore.CYAN + "\nDangerous Permissions:")

    if dangerous_found:

        for perm in dangerous_found:
            print(Fore.RED + f"  [-] {perm}")

    else:
        print(Fore.GREEN + "  No dangerous permissions found.")

    # Security Tips
    print(Fore.CYAN + "\nSecurity Tips:")

    if risk_level == "HIGH":

        print(Fore.RED + "- Avoid installing this APK")
        print(Fore.RED + "- APK requests highly sensitive permissions")
        print(Fore.RED + "- Could compromise privacy/security")
        print(Fore.RED + "- Install only from trusted stores")

    elif risk_level == "MEDIUM":

        print(Fore.YELLOW + "- Install only if source is trusted")
        print(Fore.YELLOW + "- Review permissions carefully")
        print(Fore.YELLOW + "- Avoid granting unnecessary permissions")

    else:

        print(Fore.GREEN + "- APK appears relatively safe")
        print(Fore.GREEN + "- No major dangerous permissions detected")

    # TXT Report
    with open("scan_report.txt", "w", encoding="utf-8") as report:

        report.write("=========== APK ANALYSIS REPORT ===========\n\n")

        report.write(f"App Name           : {a.get_app_name()}\n")
        report.write(f"Package Name       : {a.get_package()}\n")
        report.write(f"APK Size           : {file_size} MB\n")
        report.write(f"Total Permissions  : {len(permissions)}\n")
        report.write(f"SHA256 Hash        : {apk_hash}\n\n")

        report.write(f"Risk Level         : {risk_level}\n")
        report.write(f"Risk Score         : {risk_score}\n")
        report.write(f"Risk Percentage    : {risk_percentage}%\n")
        report.write(f"Recommendation     : {recommendation}\n\n")

        report.write("Dangerous Permissions:\n")

        if dangerous_found:

            for perm in dangerous_found:
                report.write(f"- {perm}\n")

        else:
            report.write("No dangerous permissions found.\n")

    # JSON Report
    report_data = {
        "app_name": a.get_app_name(),
        "package_name": a.get_package(),
        "apk_size_mb": file_size,
        "total_permissions": len(permissions),
        "sha256": apk_hash,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_percentage": risk_percentage,
        "recommendation": recommendation,
        "dangerous_permissions": dangerous_found
    }

    with open("scan_report.json", "w") as json_file:
        json.dump(report_data, json_file, indent=4)

    print(Fore.GREEN + "\n[+] TXT report saved as scan_report.txt")
    print(Fore.GREEN + "[+] JSON report saved as scan_report.json")

    print(Fore.CYAN + "\n" + "=" * 65)


# Main execution
if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(Fore.RED + "Usage: python analyzer.py <apk_file>")
        sys.exit(1)

    apk_file = sys.argv[1]

    if not os.path.exists(apk_file):

        print(Fore.RED + "APK file not found.")
        sys.exit(1)

    analyze_apk(apk_file)