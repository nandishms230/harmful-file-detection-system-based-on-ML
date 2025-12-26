# Harmful File Detection System

A machine learning-based system to detect harmful files (malware, viruses) in a given folder and quarantine them.

## Features

- **Feature Extraction**: Extracts file size, entropy, file extension, and PE header information (for executables).
- **ML Classification**: Uses RandomForest classifier trained on benign and malicious file datasets.
- **Quarantine**: Automatically moves detected harmful files to a quarantine folder.
- **Extensible**: Can be extended to support more file types and features.

## Setup

1. Clone or download the project.
2. Navigate to the project directory.
3. Create a virtual environment: `python -m venv venv`
4. Activate the environment: `venv\Scripts\activate` (Windows)
5. Install dependencies: `pip install -r requirements.txt`

## Usage

### Training the Model

1. Prepare datasets: Create folders with benign and malicious files.
2. Edit `train_model.py` to point to your dataset directories.
3. Run: `python train_model.py`

This will train the model and save it as `model.pkl`.

### Detecting Files

Run: `python detect_files.py <folder_path>`

Replace `<folder_path>` with the path to the folder you want to scan.

The script will scan all files in the folder (recursively), classify them, and quarantine harmful ones.

## Additional Feature Suggestions

- **Real-time Monitoring**: Use watchdog library to monitor folders for new files and scan automatically.
- **GUI Interface**: Build a Tkinter or web app for user-friendly interaction.
- **Logging**: Detailed logs of scans, detections, and actions.
- **Whitelist/Blacklist**: Exclude/include specific files or paths.
- **Integration**: Connect with Windows Defender or other AV software.
- **Reports**: Generate scan summary reports.
- **Multi-threading**: Speed up scanning of large folders.
- **Cloud Analysis**: Upload suspicious files for deeper inspection.
- **Email Alerts**: Notify users of detections.
- **Deep Learning**: Upgrade to TensorFlow for better accuracy on complex malware.

## Requirements

- Python 3.7+
- scikit-learn
- numpy
- pandas
- pefile

## Dataset

For training, use a dataset like EMBER (https://github.com/elastic/ember). Ensure you have separate folders for benign and malicious samples.

## Disclaimer

This is a basic implementation for educational purposes. It may not detect all types of malware and should not be relied upon as the sole security measure. Always use established antivirus software.
