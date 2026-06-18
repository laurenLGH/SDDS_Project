#!/usr/bin/env python
import subprocess
import sys
import time
from pathlib import Path

def run_command(cmd, description):
    """Runs a command and display errors"""
    print(f"\n{'='*60}")
    print(f"{description}")
    print('='*60)
    
    try:
        result = subprocess.run(cmd, shell=True, check=True)
        print(f"[OK] {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] {description} failed with exit code {e.returncode}")
        if hasattr(e, 'stderr') and e.stderr:
            print(f"Error output: {e.stderr}")
        return False

def ensure_database():
    """Check if database exists, if not run the ingestion scripts"""
    db_path = Path("data/corpus.db")
    
    if not db_path.exists():
        print("\nDatabase not found. Running ingestion scripts...")
        
        ingestion_scripts = [
            ("src/ingestion/golden_image.py", "Ingesting golden image data"),
            ("src/ingestion/kev.py", "Ingesting KEV data"),
            ("src/ingestion/nvd.py", "Ingesting NVD data"),
            ("src/ingestion/blogs.py", "Ingesting blog data"),
            ("src/processing/make_silver.py", "Creating silver table"),
            ("src/processing/make_gold.py", "Creating gold table")
        ]
        
        for script, description in ingestion_scripts:
            if not run_command(f"{sys.executable} {script}", description):
                print(f"\n[FAILED] Database initialization failed at {script}")
                return False
    
    print("\n[SUCCESS] Database is ready!")
    return True

if __name__ == "__main__":
    # Ensure we're in the project directory
    project_root = Path(__file__).parent.resolve()
    
    print("\n" + "="*60)
    print("Starting SDDS Project Application")
    print("="*60)
    
    # Step 1: Ensure database exists
    if not ensure_database():
        print("\n[FAILED] Application startup failed. Please fix the database issues above.")
        sys.exit(1)
    
    # Step 2: Start backend server (port 5001)
    print("\n" + "="*60)
    print("Starting Backend Server on port 5001...")
    print("="*60)
    
    backend_process = subprocess.Popen(
        [sys.executable, "src/models/main.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=project_root  # Set working directory for the process
    )
    
    # Give backend time to start
    time.sleep(3)
    
    # Step 3: Start frontend server (port 5000)
    print("\n" + "="*60)
    print("Starting Frontend Server on port 5000...")
    print("="*60)
    
    # Use the correct Flask command with proper app discovery
    frontend_process = subprocess.Popen(
        [sys.executable, "-m", "flask", "--app", "src.main", "run", "--port", "5000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=project_root  # Set working directory for the process
    )
    
    # Monitor both processes
    try:
        print("\n" + "="*60)
        print("Application is running!")
        print("="*60)
        print("Frontend: http://localhost:5000")
        print("Backend:  http://localhost:5001")
        print("\nPress Ctrl+C to stop all services")
        
        # Wait for both processes
        backend_process.wait()
        frontend_process.wait()
        
    except KeyboardInterrupt:
        print("\n\nStopping services...")
        backend_process.terminate()
        frontend_process.terminate()
        print("All services stopped.")