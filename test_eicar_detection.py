import os
from detect_files import detect_files

# Windows-safe multiprocessing entry point
if __name__ == "__main__":
    # Optional: enable freeze_support for frozen executables (PyInstaller, cx_Freeze)
    from multiprocessing import freeze_support
    freeze_support()

    # Create a folder for testing
    test_folder = "eicar_test"
    os.makedirs(test_folder, exist_ok=True)

    # EICAR test string
    eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    # Save EICAR file
    test_file_path = os.path.join(test_folder, "eicar.com")
    with open(test_file_path, "wb") as f:
        f.write(eicar_bytes)

    # You can also add other files for testing
    # Example: TXT file
    txt_file_path = os.path.join(test_folder, "example.txt")
    with open(txt_file_path, "w") as f:
        f.write("This is a harmless text file for testing.\n")

    # Run detection
    results = detect_files(
        folder_path=test_folder,
        model_path="model.pkl",           # Make sure your trained model exists
        output_csv="eicar_scan_results.csv"
    )

    # Print results
    print("\n--- Scan Results ---")
    for r in results:
        print(f"{r['file']} → {r['prediction']} ({r['probability']:.2f}) - {r['status']}")
