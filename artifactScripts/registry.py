import os
import subprocess
import pandas as pd

# Paths
RECMD_PATH = r"C:/Users/Harmehar/OneDrive/Desktop/Work-Prep/Cert-IN/Analysis/analysisTools/RECmd/RECmd.exe"  # Update with actual path
REGISTRY_DIR = "C:\\Users\\Harmehar\\OneDrive\\Desktop\\Work-Prep\\Cert-IN\\Analysis\\inputFiles"  # Directory containing SAM, SYSTEM, SOFTWARE, SECURITY hives
OUTPUT_DIR = "C:/Users/Harmehar/OneDrive/Desktop/Work-Prep/Cert-IN/Analysis/analysis_results"

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Registry hives to analyze
HIVES = ["SAM", "SYSTEM", "SOFTWARE", "SECURITY"]

def run_recmd():
    """
    Runs RECmd on a registry hive file.
    """
    # hive_path = os.path.join(REGISTRY_DIR, registry_hive)
    output_csv = os.path.join(OUTPUT_DIR, "analysis")

    

    command = [
        RECMD_PATH,
        "-d", REGISTRY_DIR,
        "--csv", OUTPUT_DIR,
        "-q"
        # "--sk", "\\"  # <---- Extracts all registry keys
    ]

    try:
        subprocess.run(command, check=True)
        print(f"[+] analysis completed. Report saved at: {output_csv}")
        return output_csv
    except subprocess.CalledProcessError as e:
        print(f"[!] Error analyzing : {e}")
        return None

def analyze_registry_data(csv_file):
    """
    Basic analysis on extracted registry data (e.g., user accounts, installed software).
    """
    if not os.path.exists(csv_file):
        print(f"[!] {csv_file} not found.")
        return

    df = pd.read_csv(csv_file)
    print(f"\n=== Analysis for {csv_file} ===")

    if "KeyPath" in df.columns and "Value" in df.columns:
        # Detect User Accounts from SAM hive
        if "SAM" in csv_file:
            users = df[df["KeyPath"].str.contains("SAM\\\\Domains\\\\Account\\\\Users", case=False, na=False)]
            print("\n[+] Extracted User Accounts:")
            print(users[["KeyPath", "Value"]].head(10))

        # Detect Installed Software from SOFTWARE hive
        if "SOFTWARE" in csv_file:
            installed_software = df[df["KeyPath"].str.contains("Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall", case=False, na=False)]
            print("\n[+] Installed Software Entries:")
            print(installed_software[["KeyPath", "Value"]].head(10))

        # Detect Recent System Boot Times from SYSTEM hive
        if "SYSTEM" in csv_file:
            boot_times = df[df["KeyPath"].str.contains("Select", case=False, na=False)]
            print("\n[+] System Boot Times:")
            print(boot_times[["KeyPath", "Value"]].head(10))

        # Detect Security Policies from SECURITY hive
        if "SECURITY" in csv_file:
            policies = df[df["KeyPath"].str.contains("Policy\\\\Pol", case=False, na=False)]
            print("\n[+] Security Policies:")
            print(policies[["KeyPath", "Value"]].head(10))

def main():
    print("[*] Starting registry analysis...")

    for hive in HIVES:
        csv_file = run_recmd()
        if csv_file:
            analyze_registry_data(csv_file)

    print("[+] Registry analysis completed. Reports saved in 'analysis_results/'.")

if __name__ == "__main__":
    main()
