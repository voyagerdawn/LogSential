import psutil
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QProgressBar, QMessageBox, QStackedWidget, QListWidget, QListWidgetItem, QCheckBox
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import sys
import time
import subprocess

# ---------------------------- SCAN THREAD ----------------------------
class ScanThread(QThread):
    update_progress = pyqtSignal(int)
    update_status = pyqtSignal(str)
    append_output = pyqtSignal(str)

    def __init__(self, trusted_processes=None):
        super().__init__()
        self.trusted_processes = trusted_processes or []

    def run(self):
        self.update_status.emit("Starting Scan...")
        suspicious = 0
        processes = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']))
        total = len(processes)

        for idx, proc in enumerate(processes):
            try:
                name = proc.info['name']
                if name in self.trusted_processes:
                    continue

                pid = proc.info['pid']
                cpu = proc.info['cpu_percent']
                mem = proc.info['memory_info'].rss / (1024 * 1024)  # in MB

                danger_score = 0
                if cpu > 50:
                    danger_score += 1
                if mem > 100:
                    danger_score += 1
                if name.lower() in ["keylogger.exe", "logger.exe"]:
                    danger_score += 2

                if danger_score >= 2:
                    self.append_output.emit(f"Suspicious process detected: {name} (PID: {pid})")
                    suspicious += 1

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            progress = int((idx + 1) / total * 100)
            self.update_progress.emit(progress)
            time.sleep(0.1)

        self.update_status.emit(f"Scan Completed. {suspicious} suspicious processes found.")

# ---------------------------- MAIN UI ----------------------------
class DefenseModule(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        self.process_list = QListWidget()
        for proc in psutil.process_iter(['name']):
            try:
                item = QListWidgetItem(proc.info['name'])
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(Qt.CheckState.Unchecked)
                self.process_list.addItem(item)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        self.network_alert_checkbox = QCheckBox("Alert on suspicious network activity")
        self.network_block_checkbox = QCheckBox("Block suspicious connections")

        self.apply_button = QPushButton("Apply Settings")
        self.apply_button.clicked.connect(self.apply_defense_settings)

        layout.addWidget(QLabel("Select Trusted Processes:"))
        layout.addWidget(self.process_list)
        layout.addWidget(self.network_alert_checkbox)
        layout.addWidget(self.network_block_checkbox)
        layout.addWidget(self.apply_button)

        self.setLayout(layout)

        self.trusted_processes = []
        self.network_alert_enabled = False
        self.network_block_enabled = False

    def apply_defense_settings(self):
        self.trusted_processes = []
        for i in range(self.process_list.count()):
            item = self.process_list.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                process_name = item.text().split(" (PID")[0]
                self.trusted_processes.append(process_name)

        self.network_alert_enabled = self.network_alert_checkbox.isChecked()
        self.network_block_enabled = self.network_block_checkbox.isChecked()

        QMessageBox.information(self, "Defense Settings", "Settings applied successfully.")

# ---------------------------- MAIN WINDOW ----------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Keylogger Detection - PyQt6")
        self.setGeometry(100, 100, 600, 400)

        self.stack = QStackedWidget()
        self.home_widget = QWidget()
        self.defense_widget = DefenseModule()

        self.stack.addWidget(self.home_widget)
        self.stack.addWidget(self.defense_widget)

        self.setCentralWidget(self.stack)

        # Home Page Layout
        layout = QVBoxLayout()
        self.start_button = QPushButton("Start Scan")
        self.start_button.clicked.connect(self.start_scan)
        self.defense_button = QPushButton("Defense Settings")
        self.defense_button.clicked.connect(lambda: self.stack.setCurrentWidget(self.defense_widget))

        self.status_label = QLabel("Idle")
        self.progress_bar = QProgressBar()
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)

        layout.addWidget(self.start_button)
        layout.addWidget(self.defense_button)
        layout.addWidget(self.status_label)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.output_text)

        self.home_widget.setLayout(layout)

    def start_scan(self):
        trusted = self.defense_widget.trusted_processes
        self.scan_thread = ScanThread(trusted_processes=trusted)
        self.scan_thread.update_progress.connect(self.progress_bar.setValue)
        self.scan_thread.update_status.connect(self.status_label.setText)
        self.scan_thread.append_output.connect(self.output_text.append)
        self.scan_thread.start()

# ---------------------------- APP LAUNCH ----------------------------
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
