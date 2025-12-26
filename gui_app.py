import customtkinter as ctk
import tkinter.filedialog as filedialog
import tkinter.messagebox as messagebox
import threading
import os
import subprocess
import pandas as pd
import joblib
import datetime
import shutil
from detect_files import detect_files
from train_model import train_model
from utils import extract_features

# ----- Helper function to detect EICAR -----
def is_eicar(file_path):
    eicar_str = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            return eicar_str in content
    except:
        return False

# Set appearance
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class HarmfulFileDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Harmful File Detector")
        self.root.geometry("900x600")
        self.root.resizable(True, True)

        # Variables
        self.folder_path = ctk.StringVar(value="")
        self.model_path = ctk.StringVar(value="model.pkl")
        self.appearance_var = ctk.StringVar(value="Dark")
        self.scan_results = []
        self.model_accuracy = "N/A"
        self.harmful_files = []
        self.quarantine_frame = None

        # Header
        self.header_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.header_frame.pack(pady=20, padx=20, fill="x")

        self.title_label = ctk.CTkLabel(self.header_frame, text="🛡️ Harmful File Detector",
                                        font=ctk.CTkFont(size=28, weight="bold"))
        self.title_label.pack()

        self.subtitle_label = ctk.CTkLabel(self.header_frame, text="AI-powered malicious file scanner",
                                           font=ctk.CTkFont(size=14))
        self.subtitle_label.pack(pady=(5, 0))

        # Theme toggle
        self.theme_switch = ctk.CTkSwitch(self.header_frame, text="🌗 Theme", variable=self.appearance_var,
                                          onvalue="Dark", offvalue="Light", command=self.toggle_theme)
        self.theme_switch.pack(anchor="ne", padx=10, pady=10)

        # Folder & Model Controls
        self.controls_frame = ctk.CTkFrame(self.root)
        self.controls_frame.pack(pady=10, padx=20, fill="x")

        self.folder_label = ctk.CTkLabel(self.controls_frame, text="Select Folder to Scan:")
        self.folder_label.pack(anchor="w", padx=10, pady=(10, 0))

        self.folder_entry = ctk.CTkEntry(self.controls_frame, textvariable=self.folder_path, width=500)
        self.folder_entry.pack(side="left", padx=(10, 5), pady=5)

        self.browse_button = ctk.CTkButton(self.controls_frame, text="Browse Folder", command=self.browse_folder)
        self.browse_button.pack(side="left", padx=(0, 10), pady=5)

        self.model_label = ctk.CTkLabel(self.controls_frame, text="Model Path:")
        self.model_label.pack(anchor="w", padx=10, pady=(10, 0))

        self.model_entry = ctk.CTkEntry(self.controls_frame, textvariable=self.model_path, width=500)
        self.model_entry.pack(side="left", padx=(10, 5), pady=5)

        self.model_note = ctk.CTkLabel(self.controls_frame, text="Using Pre-Trained Model",
                                       font=ctk.CTkFont(size=12, slant="italic"))
        self.model_note.pack(anchor="w", padx=10, pady=(5, 10))

        # Buttons
        self.buttons_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.buttons_frame.pack(pady=10, padx=20, fill="x")

        self.scan_button = ctk.CTkButton(self.buttons_frame, text="Start Scan", command=self.start_scan_thread,
                                         fg_color="#1f77b4", hover_color="#005a9e")
        self.scan_button.pack(side="left", padx=(0, 10), pady=5)

        self.retrain_button = ctk.CTkButton(self.buttons_frame, text="Retrain Model (Optional)",
                                            command=self.retrain_thread, fg_color="#ff7f0e", hover_color="#cc6600")
        self.retrain_button.pack(side="left", padx=(0, 10), pady=5)

        self.quarantine_button = ctk.CTkButton(self.buttons_frame, text="Open Quarantine Folder",
                                               command=self.open_quarantine, fg_color="#2ca02c", hover_color="#228b22")
        self.quarantine_button.pack(side="left", padx=(0, 10), pady=5)

        # Progress & Logs
        self.progress_frame = ctk.CTkFrame(self.root)
        self.progress_frame.pack(pady=10, padx=20, fill="x")

        self.progress_bar = ctk.CTkProgressBar(self.progress_frame, width=800)
        self.progress_bar.pack(pady=(10, 5), padx=10)
        self.progress_bar.set(0)

        self.logs_label = ctk.CTkLabel(self.progress_frame, text="Scan Logs:")
        self.logs_label.pack(anchor="w", padx=10, pady=(5, 0))

        self.logs_textbox = ctk.CTkTextbox(self.progress_frame, width=800, height=200, wrap="word")
        self.logs_textbox.pack(pady=(0, 10), padx=10)

        # Stats Card
        self.stats_frame = ctk.CTkFrame(self.root)
        self.stats_frame.pack(pady=10, padx=20, fill="x")

        self.stats_title = ctk.CTkLabel(self.stats_frame, text="Scan Summary", font=ctk.CTkFont(size=16, weight="bold"))
        self.stats_title.pack(pady=(10, 5))

        self.stats_inner_frame = ctk.CTkFrame(self.stats_frame, fg_color="transparent")
        self.stats_inner_frame.pack(pady=(0, 10), padx=10, fill="x")

        self.files_scanned_label = ctk.CTkLabel(self.stats_inner_frame, text="Files Scanned: 0",
                                                font=ctk.CTkFont(size=14))
        self.files_scanned_label.pack(side="left", padx=20, pady=5)

        self.harmful_detected_label = ctk.CTkLabel(self.stats_inner_frame, text="Harmful Detected: 0",
                                                   font=ctk.CTkFont(size=14))
        self.harmful_detected_label.pack(side="left", padx=20, pady=5)

        self.quarantined_label = ctk.CTkLabel(self.stats_inner_frame, text="Quarantined: 0",
                                              font=ctk.CTkFont(size=14))
        self.quarantined_label.pack(side="left", padx=20, pady=5)

        self.accuracy_label = ctk.CTkLabel(self.stats_inner_frame, text=f"Model Accuracy: {self.model_accuracy}",
                                           font=ctk.CTkFont(size=14))
        self.accuracy_label.pack(side="left", padx=20, pady=5)

        # Export Button
        self.export_button = ctk.CTkButton(self.stats_frame, text="Export Results to CSV", command=self.export_csv,
                                           fg_color="#9467bd", hover_color="#7b4f9d")
        self.export_button.pack(pady=(0, 10))

        # Footer
        self.footer_label = ctk.CTkLabel(self.root, text="Developed by B5 — 2025",
                                         font=ctk.CTkFont(size=12))
        self.footer_label.pack(pady=10)

    # ---------------- Theme Toggle ----------------
    def toggle_theme(self):
        mode = self.appearance_var.get()
        ctk.set_appearance_mode(mode)

    # ---------------- Folder Browse ----------------
    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_path.set(folder)

    # ---------------- Scan Thread ----------------
    def start_scan_thread(self):
        if not self.folder_path.get():
            messagebox.showerror("Error", "Please select a folder to scan.")
            return
        if not os.path.exists(self.model_path.get()):
            messagebox.showerror("Error", "Model file not found.")
            return
        self.scan_button.configure(state="disabled")
        self.logs_textbox.delete("0.0", "end")
        self.progress_bar.set(0)
        self.scan_results = []
        thread = threading.Thread(target=self.start_scan)
        thread.start()

    # ---------------- Scan Logic ----------------
    def start_scan(self):
        folder = self.folder_path.get()
        model = self.model_path.get()
        quarantine_path = os.path.join(folder, 'quarantine')

        if not os.path.exists(model):
            self.update_logs("Model not found. Please train the model first.\n")
            self.root.after(0, lambda: self.scan_button.configure(state="normal"))
            return

        artifact = joblib.load(model)
        if isinstance(artifact, dict) and 'model' in artifact and 'columns' in artifact:
            model_obj = artifact['model']
            trained_columns = artifact['columns']
        else:
            model_obj = artifact
            trained_columns = None

        os.makedirs(quarantine_path, exist_ok=True)

        results = []
        file_count = 0
        total_files = sum([len(files) for r, d, files in os.walk(folder) if not r.startswith(quarantine_path)])

        for root_dir, dirs, files in os.walk(folder):
            if os.path.abspath(root_dir).startswith(os.path.abspath(quarantine_path)):
                continue
            for file in files:
                file_path = os.path.join(root_dir, file)
                file_count += 1
                self.update_logs(f"Processing file {file_count}: {file_path}\n")
                self.update_progress(file_count / total_files)

                try:
                    # ----- EICAR Check -----
                    if is_eicar(file_path):
                        prediction = 1  # Harmful
                        probability = 1.0
                        dest = os.path.join(quarantine_path, os.path.basename(file_path))
                        try:
                            shutil.move(file_path, dest)
                            status = "Quarantined"
                        except Exception as e:
                            status = f"QuarantineFailed: {str(e)}"

                        result = {
                            'file': file_path,
                            'prediction': 'Harmful',
                            'probability': probability,
                            'status': status
                        }
                        results.append(result)
                        self.update_logs(f"{file_path} (EICAR Test): Harmful (Prob: {probability:.2f}) - {status}\n")
                        continue  # Skip ML prediction

                    # ----- ML Prediction -----
                    features = extract_features(file_path)
                    df = pd.DataFrame([features])

                    if 'file_extension' in df.columns:
                        df = pd.get_dummies(df, columns=['file_extension'])

                    df = df.fillna(0)

                    if trained_columns is not None:
                        df = df.reindex(columns=trained_columns, fill_value=0)
                    else:
                        expected = getattr(model_obj, "n_features_in_", None)
                        if expected and df.shape[1] < expected:
                            for i in range(expected - df.shape[1]):
                                df[f'extra_{i}'] = 0
                        if expected and df.shape[1] > expected:
                            df = df.iloc[:, :expected]

                    df = df.apply(pd.to_numeric, errors='coerce').fillna(0)

                    prediction = model_obj.predict(df)[0]

                    probability = 0.0
                    try:
                        proba = model_obj.predict_proba(df)[0]
                        classes = list(model_obj.classes_)
                        if 1 in classes:
                            idx = classes.index(1)
                            probability = float(proba[idx])
                        else:
                            probability = float(max(proba))
                    except Exception:
                        pass

                    if int(prediction) == 1:
                        dest = os.path.join(quarantine_path, os.path.basename(file_path))
                        try:
                            shutil.move(file_path, dest)
                            status = "Quarantined"
                        except Exception as e:
                            status = f"QuarantineFailed: {str(e)}"
                    else:
                        status = "Safe"

                    result = {
                        'file': file_path,
                        'prediction': 'Harmful' if int(prediction) == 1 else 'Safe',
                        'probability': probability,
                        'status': status
                    }
                    results.append(result)
                    file_type = "PE" if features.get('extension', '').lower() in ['.exe', '.dll'] else "Non-PE"
                    self.update_logs(f"{result['file']} ({file_type}): {result['prediction']} (Prob: {result['probability']:.2f}) - {result['status']}\n")

                except Exception as e:
                    self.update_logs(f"Error processing {file_path}: {str(e)}\n")
                    results.append({
                        'file': file_path,
                        'prediction': 'Error',
                        'probability': 0.0,
                        'status': f'Error: {str(e)}'
                    })

        self.scan_results = results
        self.harmful_files = [r for r in results if r['prediction'] == 'Harmful']
        self.update_stats()
        self.update_logs(f"Scan complete: {len(results)} files scanned, {len(self.harmful_files)} harmful quarantined.\n")
        if self.harmful_files:
            self.root.after(0, lambda: self.show_quarantine_options())
        else:
            self.root.after(0, lambda: messagebox.showinfo("Scan Complete", f"Scan complete: {len(results)} files scanned, no harmful files detected."))
        self.root.after(0, lambda: self.scan_button.configure(state="normal"))

    # ---------------- Retrain ----------------
    def retrain_thread(self):
        self.retrain_button.configure(state="disabled")
        thread = threading.Thread(target=self.retrain_model)
        thread.start()

    def retrain_model(self):
        try:
            ember_path = 'train_ember_2018_v2_features.parquet'
            if os.path.exists(ember_path):
                train_model(ember_path=ember_path)
            else:
                messagebox.showerror("Error", "EMBER dataset not found.")
                self.root.after(0, lambda: self.retrain_button.configure(state="normal"))
                return
            self.update_logs("Model retrained successfully.\n")
            messagebox.showinfo("Success", "Model retrained and saved as model.pkl.")
        except Exception as e:
            self.update_logs(f"Error retraining model: {str(e)}\n")
            messagebox.showerror("Error", f"Error retraining model: {str(e)}")
        self.root.after(0, lambda: self.retrain_button.configure(state="normal"))

    # ---------------- Quarantine ----------------
    def open_quarantine(self):
        folder = self.folder_path.get()
        if not folder:
            messagebox.showerror("Error", "Please select a folder first.")
            return
        quarantine_path = os.path.join(folder, 'quarantine')
        if os.path.exists(quarantine_path):
            try:
                if os.name == 'nt':  # Windows
                    os.startfile(quarantine_path)
                else:
                    subprocess.run(['xdg-open', quarantine_path])
            except Exception as e:
                messagebox.showerror("Error", f"Could not open quarantine folder: {str(e)}")
        else:
            messagebox.showwarning("Warning", "Quarantine folder does not exist yet.")

    # ---------------- Export ----------------
    def export_csv(self):
        if not self.scan_results:
            messagebox.showwarning("Warning", "No scan results to export.")
            return
        try:
            df = pd.DataFrame(self.scan_results)
            df.to_csv('scan_results.csv', index=False)
            messagebox.showinfo("Success", "Scan results saved to scan_results.csv")
        except Exception as e:
            messagebox.showerror("Error", f"Error exporting CSV: {str(e)}")

    # ---------------- Logs ----------------
    def update_logs(self, text):
        timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
        self.root.after(0, lambda: self.logs_textbox.insert("end", timestamp + text))
        self.root.after(0, lambda: self.logs_textbox.see("end"))

    def update_progress(self, value):
        self.root.after(0, lambda: self.progress_bar.set(value))

    # ---------------- Stats ----------------
    def update_stats(self):
        files_scanned = len(self.scan_results)
        harmful_detected = sum(1 for r in self.scan_results if r['prediction'] == 'Harmful')
        quarantined = sum(1 for r in self.scan_results if r['status'] == 'Quarantined')
        self.root.after(0, lambda: self.files_scanned_label.configure(text=f"Files Scanned: {files_scanned}"))
        self.root.after(0, lambda: self.harmful_detected_label.configure(text=f"Harmful Detected: {harmful_detected}"))
        self.root.after(0, lambda: self.quarantined_label.configure(text=f"Quarantined: {quarantined}"))
        self.model_accuracy = "N/A"
        self.root.after(0, lambda: self.accuracy_label.configure(text=f"Model Accuracy: {self.model_accuracy}"))

    # ---------------- Quarantine Options ----------------
    def show_quarantine_options(self):
        if self.quarantine_frame:
            self.quarantine_frame.destroy()
        self.quarantine_frame = ctk.CTkFrame(self.root)
        self.quarantine_frame.pack(pady=10, padx=20, fill="x")

        title = ctk.CTkLabel(self.quarantine_frame, text="Harmful Files Detected - Choose Action:",
                             font=ctk.CTkFont(size=16, weight="bold"))
        title.pack(pady=(10, 5))

        files_text = "\n".join([f"{os.path.basename(r['file'])} (Prob: {r['probability']:.2f})" for r in self.harmful_files])
        files_label = ctk.CTkLabel(self.quarantine_frame, text=files_text, font=ctk.CTkFont(size=12))
        files_label.pack(pady=(0, 10))

        button_frame = ctk.CTkFrame(self.quarantine_frame, fg_color="transparent")
        button_frame.pack(pady=(0, 10))

        delete_button = ctk.CTkButton(button_frame, text="Delete Harmful Files", command=self.delete_harmful_files,
                                      fg_color="#dc143c", hover_color="#b22222")
        delete_button.pack(side="left", padx=(0, 10))

        keep_button = ctk.CTkButton(button_frame, text="Keep in Quarantine", command=self.keep_in_quarantine,
                                    fg_color="#228b22", hover_color="#006400")
        keep_button.pack(side="left")

    def delete_harmful_files(self):
        folder = self.folder_path.get()
        quarantine_path = os.path.join(folder, 'quarantine')
        deleted_count = 0
        for r in self.harmful_files:
            file_in_quarantine = os.path.join(quarantine_path, os.path.basename(r['file']))
            if os.path.exists(file_in_quarantine):
                try:
                    os.remove(file_in_quarantine)
                    deleted_count += 1
                    self.update_logs(f"Deleted: {file_in_quarantine}\n")
                except Exception as e:
                    self.update_logs(f"Failed to delete {file_in_quarantine}: {str(e)}\n")
        messagebox.showinfo("Deletion Complete", f"Deleted {deleted_count} harmful files from quarantine.")
        self.quarantine_frame.destroy()
        self.quarantine_frame = None

    def keep_in_quarantine(self):
        messagebox.showinfo("Action Confirmed", "Harmful files will remain in quarantine.")
        self.quarantine_frame.destroy()
        self.quarantine_frame = None

# ---------------- Run App ----------------
if __name__ == "__main__":
    root = ctk.CTk()
    app = HarmfulFileDetectorApp(root)
    root.mainloop()
