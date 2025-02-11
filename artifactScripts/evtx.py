import os
import subprocess
import pandas as pd

def analyze_evtx(evtx_directory, output_csv):
    """
    Analyzes EVTX files in the specified directory and generates a forensic timeline in CSV format.
    
    :param evtx_directory: Path to the directory containing .evtx files.
    :param output_csv: Path to save the output CSV file.
    """
    hayabusa_path = r"C:\\Users\\Harmehar\\OneDrive\\Desktop\\Work-Prep\\Cert-IN\\Analysis\\analysisTools\\hayabusa-3.0.1-win-x64.exe"
    
    command = [
        hayabusa_path,
        "csv-timeline",
        "--directory", evtx_directory,
        "--output", output_csv,
        "--clobber",
        "--sort-events"
    ]
    
    try:
        subprocess.run(command, check=True)
        print(f"EVTX analysis completed. Report saved at: {output_csv}")
        detect_anomalies(output_csv)
    except subprocess.CalledProcessError as e:
        print(f"Error analyzing EVTX files: {e}")

def detect_anomalies(csv_file):
    """
    Basic anomaly detection on the generated EVTX timeline CSV.
    """
    try:
        df = pd.read_csv(csv_file)
        
        # Detect high frequency Event IDs
        event_counts = df['EventID'].value_counts()
        high_freq_events = event_counts[event_counts > event_counts.mean() + 2 * event_counts.std()]
        
        # Detect uncommon event sources
        uncommon_sources = df['ProviderName'].value_counts()
        rare_sources = uncommon_sources[uncommon_sources < uncommon_sources.mean() - 1.5 * uncommon_sources.std()]
        
        # Detect unusual timestamps (e.g., events outside work hours 8AM-8PM)
        df['TimeCreated'] = pd.to_datetime(df['TimeCreated'])
        df['Hour'] = df['TimeCreated'].dt.hour
        unusual_times = df[(df['Hour'] < 8) | (df['Hour'] > 20)]
        
        print("Anomaly Detection Results:")
        if not high_freq_events.empty:
            print("High frequency Event IDs:")
            print(high_freq_events)
        if not rare_sources.empty:
            print("Rare event sources:")
            print(rare_sources)
        if not unusual_times.empty:
            print("Events occurring at unusual hours:")
            print(unusual_times[['TimeCreated', 'EventID', 'ProviderName']].head(10))
        
    except Exception as e:
        print(f"Error in anomaly detection: {e}")

if __name__ == "__main__":
    evtx_dir = r"C:\\Users\\Harmehar\\OneDrive\\Desktop\\Work-Prep\\Cert-IN\\Analysis\\organizedFiles\\evtx"
    output_file = r"C:\\Users\\Harmehar\\OneDrive\\Desktop\\Work-Prep\\Cert-IN\\Analysis\\analysis_results"
    
    if os.path.exists(evtx_dir) and os.listdir(evtx_dir):
        analyze_evtx(evtx_dir, output_file)
    else:
        print("No EVTX files found for analysis.")
