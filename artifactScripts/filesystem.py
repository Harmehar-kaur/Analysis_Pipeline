import os
import subprocess
import pandas as pd

# Path to MFTECmd executable (Update this path)
MFTECMD_PATH = r"C:\\Users\\Harmehar\\OneDrive\\Desktop\\Work-Prep\\Cert-IN\\Analysis\\analysisTools\\MFTECmd.exe"

# List of filesystem artifacts to analyze
FILESYSTEM_ARTIFACTS = ["$MFT", "$J", "$SECURE_$SDS", "$Boot", "$LogFile"]

def analyze_filesystem(directory, output_dir):
    """
    Analyzes multiple filesystem files using MFTECmd and generates CSV reports.

    :param directory: Path to the directory containing filesystem files.
    :param output_dir: Path to save all analysis results.
    """
    os.makedirs(output_dir, exist_ok=True)  # Ensure output directory exists
    artifact_outputs = []  # Store paths of successfully analyzed artifacts

    for artifact in FILESYSTEM_ARTIFACTS:
        artifact_path = os.path.join(directory, artifact)
        output_csv = os.path.join(output_dir, "FilesystemCsv")

        if os.path.exists(artifact_path):
            print(f"🔍 Analyzing {artifact} ...")
            success = run_mftecmd(artifact_path, output_csv)
            if success:
                artifact_outputs.append(output_csv)
        else:
            print(f"⚠️ {artifact} not found in the directory.")

    # Run anomaly detection after all analyses are completed

def run_mftecmd(input_file, output_csv):
    """
    Runs MFTECmd on the given file to extract forensic details.

    :param input_file: Path to the filesystem artifact (e.g., $MFT, $J).
    :param output_csv: Path to save the parsed output CSV.
    :return: True if successful, False otherwise.
    """
    command = [
        MFTECMD_PATH,
        "-f", input_file,
        "--csv", output_csv
    ]

    try:
        subprocess.run(command, check=True)
        print(f"✅ Analysis completed for {os.path.basename(input_file)}. Report saved at: {output_csv}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error analyzing {os.path.basename(input_file)}: {e}")
        return False
    except PermissionError:
        print(f"⚠️ Permission denied for {os.path.basename(input_file)}. Try running as administrator.")
        return False

if __name__ == "__main__":
    filesystem_dir = r"C:\\Users\\Harmehar\\OneDrive\\Desktop\\Work-Prep\\Cert-IN\\Analysis\\organizedFiles\\filesystem"
    output_dir = r"C:\\Users\\Harmehar\\OneDrive\\Desktop\\Work-Prep\\Cert-IN\\Analysis\\analysis_results"

    if os.path.exists(filesystem_dir):
        analyze_filesystem(filesystem_dir, output_dir)
    else:
        print("❌ Filesystem directory not found.")
