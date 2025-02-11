import os
import shutil
import subprocess

def categorize_files(input_directory, output_directory):
    """
    Categorizes forensic evidence files into subdirectories based on file type.
    """
    categories = {
        "evtx": [".evtx"],
        "filesystem": ["$MFT", "$J", "$SDS", ".vhd", ".vmdk"],
        "registry": [".reg", "SAM", "SECURITY", "SOFTWARE", "SYSTEM"],
        "memory": [".dmp", ".raw", ".vmem"],
        "logs": [".log", ".txt"],
        "sqlite": [".sqlite", ".db"],
        "lNK": [".lnk"],
        "browser": ["History", "Cookies", "WebCacheV01.dat"]
    }
    
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)
    
    faulty_files_path = os.path.join(output_directory, "faulty_files.txt")
    categorized_folders = set()
    
    with open(faulty_files_path, "w") as faulty_file:
        for path, folders, files in os.walk(input_directory):
            for filename in files:
                file_path = os.path.join(path, filename)
                # file_path = "\\\\?\\" + file_path  # Enable long path support
                
                # Determine category
                for category, extensions in categories.items():
                    if any(filename.endswith(ext) or filename in extensions for ext in extensions):
                        category_path = os.path.join(output_directory, category)
                        # category_path = "\\\\?\\" + category_path  # Enable long path support
                        
                        if not os.path.exists(category_path):
                            os.makedirs(category_path)
                        
                        if os.path.exists(file_path):
                            shutil.move(file_path, os.path.join(category_path, filename))
                            print(f"Moved: {filename} -> {category_path}")
                            categorized_folders.add(category)
                        else:
                            print(f"File not found: {file_path}")
                            faulty_file.write(f"{filename}\n")
                        break  # Move to next file after categorization
    
    return categorized_folders

def execute_category_scripts(output_directory, categorized_folders):
    """
    Executes the main.py script inside each category folder that contains files.
    """
    for category in categorized_folders:
        category_script = os.path.join(output_directory, category, "main.py")
        if os.path.exists(category_script):
            print(f"Executing script for category: {category}")
            subprocess.run(["python", category_script], check=True)

if __name__ == "__main__":
    input_dir = r"C:\\Users\\Harmehar\\OneDrive\\Desktop\\Work-Prep\\Cert-IN\\Analysis\\inputFiles"
    output_dir = r"C:\\Users\\Harmehar\\OneDrive\\Desktop\\Work-Prep\\Cert-IN\\Analysis\\organizedFiles"
    categorized_folders = categorize_files(input_dir, output_dir)
    execute_category_scripts(output_dir, categorized_folders)
