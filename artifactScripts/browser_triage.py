import os
import subprocess
import sqlite3
import pandas as pd

# Define paths
TRIAGE_DIR = "C:\\Users\\Harmehar\\OneDrive\\Desktop\\Work-Prep\\Cert-IN\\Analysis\\inputFiles"
OUTPUT_DIR = "C:\\Users\\Harmehar\\OneDrive\\Desktop\\Work-Prep\\Cert-IN\\Analysis\\inputFiles\\analysis_results"
HINDSIGHT_PATH = r"C:/Users/Harmehar/OneDrive/Desktop/Work-Prep/Cert-IN/Analysis/analysisTools/hindsight.exe"  # Update with actual path
LECMD_PATH = r"C:/Users/Harmehar/OneDrive/Desktop/Work-Prep/Cert-IN/Analysis/analysisTools/LECmd.exe"  # Update with actual path

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Browser artifacts to search for
BROWSER_FILES = {
    "chrome": ["History", "Cookies", "WebCacheV01.dat"],
    "firefox": ["places.sqlite", "cookies.sqlite"],
    "edge": ["History", "Cookies"]
}

def find_browser_artifacts():
    """
    Search for browser artifact files in the triage data directory.
    Returns a dictionary with file paths.
    """
    found_files = {browser: {} for browser in BROWSER_FILES}

    for root, _, files in os.walk(TRIAGE_DIR):
        for browser, artifacts in BROWSER_FILES.items():
            for artifact in artifacts:
                if artifact in files:
                    found_files[browser][artifact] = os.path.join(root, artifact)

    return found_files

def analyze_chrome_history(history_db):
    """
    Analyze Chrome/Edge history SQLite database for insights.
    """
    if not os.path.exists(history_db):
        print(f"[!] {history_db} not found.")
        return None

    conn = sqlite3.connect(history_db)
    query = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 20"
    df = pd.read_sql_query(query, conn)
    conn.close()

    output_file = os.path.join(OUTPUT_DIR, "chrome_history.csv")
    df.to_csv(output_file, index=False)
    print(f"[+] Chrome history analysis saved to {output_file}")

def run_hindsight(chrome_path):
    """
    Runs Hindsight to extract forensic details from Chrome history.
    """
    output_html = os.path.join(OUTPUT_DIR, "hindsight_report.html")
    command = ["python", HINDSIGHT_PATH, "-i", chrome_path, "-o", output_html]
    
    try:
        subprocess.run(command, check=True)
        print(f"[+] Hindsight analysis saved to {output_html}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running Hindsight: {e}")

def analyze_lnk_files():
    """
    Runs LECmd to extract information from Windows shortcut files.
    """
    lnk_output = os.path.join(OUTPUT_DIR, "lnk_analysis.csv")
    command = [LECMD_PATH, "-d", TRIAGE_DIR, "--csv", lnk_output]
    
    try:
        subprocess.run(command, check=True)
        print(f"[+] LNK file analysis saved to {lnk_output}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running LECmd: {e}")

def main():
    print("[*] Searching for browser artifacts in triage data...")
    artifacts = find_browser_artifacts()

    for browser, files in artifacts.items():
        print(f"[+] Found {browser} artifacts:")
        for name, path in files.items():
            print(f"    - {name}: {path}")

            if "History" in name:
                analyze_chrome_history(path)

            if "WebCacheV01.dat" in name:
                run_hindsight(path)

    analyze_lnk_files()

if __name__ == "__main__":
    main()
