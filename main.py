import subprocess
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import QThread, pyqtSignal, QRect, Qt, QPoint
from PyQt6.QtWidgets import QApplication, QMenu, QWidgetAction, QMainWindow, QWidget, QHBoxLayout, QPushButton, QTextEdit, QLabel, QProgressBar, QMessageBox, QStackedWidget, QListWidget, QListWidgetItem, QCheckBox, QFrame
from PyQt6.QtGui import QAction 
import psutil
import time
import re
from pynput import keyboard
from collections import deque
from PyQt6 import QtWidgets, QtGui
from PyQt6.QtWidgets import QMessageBox

class DeepScanFrame(QtWidgets.QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setGeometry(290, 290, 171, 48)
        font_id1 = QtGui.QFontDatabase.addApplicationFont("../Assets/Geologica_Cursive-Regular.ttf")
        font_family1 = QtGui.QFontDatabase.applicationFontFamilies(font_id1)[0]
        app_font = QtGui.QFont(font_family1, 14)

        self.kernelScan = QtWidgets.QPushButton("Run deep Scan", self)
        self.kernelScan.setGeometry(11, 11, 149, 26)
        self.kernelScan.setFont(app_font)

        self.setStyleSheet("background-color: #f5f5f5; border-radius: 10px;")
        self.kernelScan.setStyleSheet("background-color: #f5f5f5; color: #002b5c;")

        self.kernelScan.clicked.connect(self.run_deep_scan)

        # DTA settings
        self.tainted_keys = deque(maxlen=100)
        self.detection_window = 10  # seconds

        # Start keyboard listener
        self.listener = keyboard.Listener(on_press=self.on_key_press)
        self.listener.start()

    def on_key_press(self, key):
        try:
            self.tainted_keys.append((str(key.char), time.time()))
        except AttributeError:
            self.tainted_keys.append((str(key), time.time()))

    def run_deep_scan(self):
        suspicious_processes = []
        current_time = time.time()

        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
            try:
                files = proc.info['open_files']
                if not files:
                    continue

                for f in files:
                    if any(ext in f.path for ext in ['.txt', '.log']) or any(h in f.path.lower() for h in ['keystrokes', 'keylog']):
                        recent_keys = [t for k, t in self.tainted_keys if current_time - t < self.detection_window]
                        if recent_keys:
                            suspicious_processes.append((proc.pid, proc.name(), f.path))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if suspicious_processes:
            result_text = "\n".join(
                [f"{name} (PID: {pid}) writing to {path}" for pid, name, path in suspicious_processes]
            )
            QMessageBox.warning(self, "⚠️ Suspicious Activity Detected", result_text)
        else:
            QMessageBox.information(self, "✅ No Threats Found", "No keylogger behavior was detected.")

    def enterEvent(self, event):
        self.setStyleSheet("background-color: #002b5c;")
        self.kernelScan.setStyleSheet("color: white;")
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.setStyleSheet("background-color: #f5f5f5;")
        self.kernelScan.setStyleSheet("background-color: #f5f5f5; color: #002b5c;")
        super().leaveEvent(event)


import time
from pynput import keyboard
import threading

class TypingMonitor:
    def __init__(self):
        self.last_time = None
        self.intervals = []

    def on_press(self, key):
        current_time = time.time()
        if self.last_time:
            interval = current_time - self.last_time
            if 0 < interval < 2:  # valid typing delay
                self.intervals.append(interval)
        self.last_time = current_time

    def start(self):
        self.listener = keyboard.Listener(on_press=self.on_press)
        self.listener.start()

    def get_typing_speed(self):
        if not self.intervals:
            return None
        avg = sum(self.intervals) / len(self.intervals)
        self.intervals.clear()  # Optional: reset after each sample
        return avg

# DCA Learning
import json
import os

class ThreatManager:
    DB_PATH = "learned_keylogger_patterns.json"

    @staticmethod
    def load_threats():
        if os.path.exists(ThreatManager.DB_PATH):
            with open(ThreatManager.DB_PATH, "r") as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    return []
        return []

    @staticmethod
    def save_threats(threats):
        with open(ThreatManager.DB_PATH, "w") as f:
            json.dump(threats, f, indent=4)

    @staticmethod
    def add_threat(pattern):
        threats = ThreatManager.load_threats()
        if pattern not in threats:
            threats.append(pattern)
            ThreatManager.save_threats(threats)
            print("[ThreatManager] Learned a new keylogger pattern.")
        else:
            print("[ThreatManager] Pattern already known.")

    @staticmethod
    def is_known_threat(process_info):
        threats = ThreatManager.load_threats()
        name = process_info.get("name", "").lower()
        raw_cmdline = process_info.get("cmdline", [])
        if isinstance(raw_cmdline, list):
            cmdline = " ".join(raw_cmdline).lower()
        else:
            cmdline = str(raw_cmdline).lower()

        for threat in threats:
            if name == threat.get("name", "").lower():
                return True
            if any(k in cmdline for k in threat.get("cmdline", [])):
                return True
        return False

# DCA Algo
class DendriticCell:
    def __init__(self):
        self.pamp_signals = 0
        self.danger_signals = 0
        self.safe_signals = 0
        self.collected_antigens = []
        self.typing_speed_threshold_min = 1.42  # 17 WPM in keys per second
        self.typing_speed_threshold_max = 8.67  # 104 WPM in keys per second
        self.allowed_processes = ['notepad', 'chrome', 'firefox', 'word', 'cmd', 'powershell']  # List of processes to check for typing speed

    def decay_signals(self):
        self.pamp_signals = max(0, self.pamp_signals - 0.1)
        self.danger_signals = max(0, self.danger_signals - 0.1)
        self.safe_signals = max(0, self.safe_signals - 0.1)

    def collect_signals(self, process_info):
        self.decay_signals()  # Apply decay before updating
        name = process_info.get('name', 'Unknown')
        behavior_score = process_info.get('behavior_score', 0)
        raw_cmdline = process_info.get('cmdline', [])
        cmdline = ' '.join(raw_cmdline) if isinstance(raw_cmdline, list) else str(raw_cmdline)
        typing_speed = process_info.get('typing_speed', 0)  # Get typing speed from the process info

        # Check if process is in the allowed list of typing processes
        if any(proc in name.lower() for proc in self.allowed_processes):
            if typing_speed < self.typing_speed_threshold_min or typing_speed > self.typing_speed_threshold_max:
                print(f"[DCA] Abnormal typing speed detected: {typing_speed} keys per second")
                self.danger_signals += 1
                print(f"[DCA] Typing speed outside normal range. Danger signal triggered.")
        else:
            print(f"[DCA] Process {name} is not a typing process, skipping typing speed check.")

        if ThreatManager.is_known_threat(process_info):
            self.pamp_signals += 1
            print(f"[DCA] Matched known threat pattern: {name}")
        elif "keylogger" in name.lower():
            self.pamp_signals += 1
            print(f"[DCA] Keylogger name detected: {name}")
        elif behavior_score >= 3 or any(kw in cmdline.lower() for kw in ['hook', 'keyboard', 'keylog']):
            self.danger_signals += 1
            print(f"[DCA] Suspicious behavior detected in: {name} | Score: {behavior_score}")
        else:
            self.safe_signals += 1
            print(f"[DCA] Safe signal collected from: {name} | Score: {behavior_score}")

        self.collected_antigens.append(process_info)

    def is_mature(self):
        return self.danger_signals >= 1

    def classify(self):
        if self.is_mature():
            print("Classifying as: Suspicious Process (Mature DC)")
            last_antigen = self.collected_antigens[-1]
            pattern = {
                "name": last_antigen.get("name", ""),
                "cmdline": last_antigen.get("cmdline", []),
                "behavior_score": last_antigen.get("behavior_score", 0)
            }
            ThreatManager.add_threat(pattern)
            return "Suspicious Process (Mature DC)"
        else:
            print("Classifying as: Safe Process (Semi-Mature DC)")
            return "Safe Process (Semi-mature DC)"

# Thread for monitoring
class ProcessMonitor(QThread):
    process_signal = pyqtSignal(dict)

    def run(self):
        while True:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'cmdline']):
                try:
                    process_info = {
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cmdline': proc.info['cmdline'],
                        'connections': [],
                        'behavior_score': 0,
                        'behavior': 'normal'
                    }

                    typing_speed = self.typing_monitor.get_typing_speed() if hasattr(self, 'typing_monitor') else 0
                    process_info['typing_speed'] = typing_speed

                    # Score high CPU or memory usage
                    if proc.info['cpu_percent'] > 50:
                        process_info['behavior_score'] += 2
                    if proc.info['memory_percent'] > 50:
                        process_info['behavior_score'] += 2

                    # Check command line for suspicious keywords
                    cmdline_str = ' '.join(proc.info['cmdline']) if isinstance(proc.info['cmdline'], list) else ''
                    suspicious_keywords = ["keylog", "logger", "capture", "snoop", "monitor"]
             

                    # Check for excessive network connections (common in remote keyloggers)
                    if len(process_info['connections']) > 10:
                        process_info['behavior_score'] += 2

                    # Check for frequent CPU spikes (suspicious polling behavior)
                    if 30 < proc.info['cpu_percent'] < 80:
                        process_info['behavior_score'] += 1

                    # High I/O could also be a sign
                    try:
                        io_counters = proc.io_counters()
                        if io_counters.write_count > 1000:
                            process_info['behavior_score'] += 2
                    except Exception:
                        pass

                    # Collect network connections
                    try:
                        for conn in proc.connections(kind='inet'):
                            local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                            remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                            process_info['connections'].append({
                                'fd': conn.fd,
                                'family': conn.family,
                                'type': conn.type,
                                'local_address': local,
                                'remote_address': remote,
                                'status': conn.status
                            })
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                    # Determine behavior based on score threshold
                    if process_info['behavior_score'] >= 2:
                        process_info['behavior'] = 'Suspicious'
                    else:
                        process_info['behavior'] = 'Normal'


                    self.process_signal.emit(process_info)
                    time.sleep(1)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

# File Activity Monitoring                      
class FileActivityMonitor(QThread):
    file_activity_signal = pyqtSignal(str)  # Signal to send detected activity

    def detect_suspicious_file_activity(self):
        
        for proc in psutil.process_iter(['pid', 'name', 'io_counters']):
            try:
                io = proc.info['io_counters']
                if io and io.write_count > 1000:  
                    self.file_activity_signal.emit(f"Suspicious process writing a lot of data: {proc.info['name']} (PID: {proc.info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    def run(self):
        while True:
            self.detect_suspicious_file_activity()
            time.sleep(5)

#Main UI and fucntionalities
class Ui_MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.dca = DendriticCell()
        self.typing_monitor = TypingMonitor()
        self.typing_monitor.start()
        self.process_monitor = ProcessMonitor()
        self.process_monitor.process_signal.connect(self.run_dca_monitoring)
        
        self.setupUi(self)  # <- Make sure this is called BEFORE using self.suslist
        self.process_monitor.start()
        self.setup_suslist_context_menu()  
        
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.setFixedSize(850, 662)
        MainWindow.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.ArrowCursor))

        MainWindow.setWindowFlags(QtCore.Qt.WindowType.FramelessWindowHint)

        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        font_id = QtGui.QFontDatabase.addApplicationFont("../Assets/Geologica_Auto-SemiBold.ttf")  # Replace with your font filename
        font_family = QtGui.QFontDatabase.applicationFontFamilies(font_id)[0]

        header_font = QtGui.QFont(font_family, 21)

        self.titleFrame = QtWidgets.QFrame(parent=self.centralwidget)
        self.titleFrame.setGeometry(QtCore.QRect(-11, 0, 861, 51))
        self.titleFrame.setStyleSheet("QFrame {"
        "background-color:#F5F5F5;"
        "}")
        self.titleFrame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.titleFrame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.titleFrame.setObjectName("titleFrame")

        self.SENTIAL = QtWidgets.QLabel(parent=self.titleFrame)
        self.SENTIAL.setGeometry(QtCore.QRect(40, 0, 141, 41))
        self.SENTIAL.setFont(header_font)
        self.SENTIAL.setStyleSheet("color: #002B5C;")
        self.SENTIAL.setObjectName("SENTIAL")

        self.widget = QtWidgets.QWidget(parent=self.titleFrame)
        self.widget.setGeometry(QtCore.QRect(740, 10, 95, 26))
        self.widget.setObjectName("widget")
        self.windowFlagLayout = QtWidgets.QHBoxLayout(self.widget)
        self.windowFlagLayout.setContentsMargins(0, 0, 0, 0)
        self.windowFlagLayout.setSpacing(30)
        self.windowFlagLayout.setObjectName("windowFlagLayout")

        self.MINIMIZE = QtWidgets.QPushButton(parent=self.widget)
        self.MINIMIZE.setStyleSheet("""
                QPushButton{
                        border: none;
                }
                QPushButton:hover {
                        background-color:#002B5C;
                        icon: url(../Assets/minimize_hover.svg);
                }
        """)
        self.MINIMIZE.setText("")
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("../Assets/minimize.svg"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.MINIMIZE.setIcon(icon)
        self.MINIMIZE.setObjectName("MINIMIZE")
        self.windowFlagLayout.addWidget(self.MINIMIZE)

        self.CLOSE = QtWidgets.QPushButton(parent=self.widget)
        self.CLOSE.setStyleSheet("""
                QPushButton{
                        border: none;
                }
                QPushButton:hover {
                        background-color:#002B5C;
                        icon: url(../Assets/close_hover.svg);
                        border-radius: 20px;
                }
        """)
        self.CLOSE.setText("")
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap("../Assets/close.svg"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.CLOSE.setIcon(icon1)
        self.CLOSE.setObjectName("CLOSE")
        self.windowFlagLayout.addWidget(self.CLOSE)

        self.MINIMIZE.clicked.connect(MainWindow.showMinimized)
        self.CLOSE.clicked.connect(MainWindow.close)

        self.displayFrame = QtWidgets.QStackedWidget(parent=self.centralwidget)
        self.displayFrame.setGeometry(QtCore.QRect(40, 100, 771, 381))
        self.displayFrame.setStyleSheet("background-color: rgb(255, 255, 255);"
                                        "border-radius:10px;")
        self.displayFrame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.displayFrame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.displayFrame.setObjectName("displayFrame")

        self.page1 = QtWidgets.QWidget()
        self.page2 = QtWidgets.QWidget()
        
        self.displayFrame.addWidget(self.page1)
        self.displayFrame.addWidget(self.page2)

        self.deepScanFrame = DeepScanFrame(self.page1)
        self.deepScanFrame.setGeometry(290, 280, 171, 48)

        self.frame = QFrame(self.page2)
        self.frame.setObjectName("frame")
        self.frame.setGeometry(QRect(29, 40, 270, 311))
        self.frame.setFrameShape(QFrame.Shape.StyledPanel)
        self.frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.frame_2 = QFrame(self.page2)
        self.frame_2.setObjectName("frame_2")
        self.frame_2.setGeometry(QRect(330, 40, 400, 311))
        self.frame_2.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.frame_2.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.frame.setStyleSheet("QFrame { border: 2px solid #002B5C; }")
        self.frame_2.setStyleSheet("QFrame { border: 2px solid #002B5C; }") 

        self.suslist = QtWidgets.QListWidget(self.frame)
        self.suslist.setGeometry(QtCore.QRect(10,10,250,291))
        self.suslist.setStyleSheet("""
            QListWidget {
                background-color: #f5f5f5;
                border-radius: 10px; 
                color: #002b5c;                      
            }                                             
        """)
        self.suslist.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.suslist.customContextMenuRequested.connect(self.show_process_context_menu)

        self.netlist = QtWidgets.QTableWidget(self.frame_2)
        self.netlist.setGeometry(QtCore.QRect(10,10,380,291))
        self.netlist.setStyleSheet("""
            QListWidget {
                background-color: #f5f5f5;
                border-radius: 10px; 
                color: #002b5c;                      
            }                                                   
        """)
        self.netlist.setColumnCount(5)
        self.netlist.setHorizontalHeaderLabels(["Process Name", "Local Address", "Remote Address", "Status", "Block"])
        self.netlist.horizontalHeader().setStretchLastSection(True)
        self.netlist.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.Stretch)


        self.navFrame = QtWidgets.QFrame(parent=self.centralwidget)
        self.navFrame.setGeometry(QtCore.QRect(190, 530, 451, 81))
        self.navFrame.setStyleSheet("background-color: rgb(255, 255, 255);"
                                    "border-radius:20px;")
        self.navFrame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.navFrame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.navFrame.setObjectName("navFrame")

        self.monitorButton = QtWidgets.QPushButton(parent=self.navFrame)
        self.monitorButton.setGeometry(QtCore.QRect(20, -10, 121, 111))
        self.monitorButton.setStyleSheet("""
                QPushButton:hover{
                        background-color:#F5F5F5;
                }
        """)
        self.monitorButton.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        self.monitorButton.setText("")
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap("../Assets/monitor.svg"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.monitorButton.setIcon(icon2)
        self.monitorButton.setIconSize(QtCore.QSize(50, 50))
        self.monitorButton.setObjectName("monitorButton")
        self.monitorButton.clicked.connect(self.showPage1)
        
        self.defendButton = QtWidgets.QPushButton(parent=self.navFrame)
        self.defendButton.setGeometry(QtCore.QRect(270, -13, 93, 101))
        self.defendButton.setStyleSheet("""
                QPushButton:hover{
                        background-color:#F5F5F5;
                }
        """)
        self.defendButton.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        self.defendButton.setText("")
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap("../Assets/defend.svg"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.defendButton.setIcon(icon3)
        self.defendButton.setIconSize(QtCore.QSize(50, 50))
        self.defendButton.setObjectName("defendButton")
        self.defendButton.clicked.connect(self.showPage2)

        self.monitoringLog = QtWidgets.QTextEdit(parent=self.page1)
        self.monitoringLog.setGeometry(QtCore.QRect(173, 46, 391, 141))
        self.monitoringLog.setStyleSheet("""
                QTextEdit {
                    background-color: #F5F5F5;
                    border-radius: 10px;
                    color: #002B5C;
                }
        """)
        self.monitoringLog.setReadOnly(True)  
        self.monitoringLog.setObjectName("monitoringLog")

        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(parent=MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 850, 26))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)

        self.statusbar = QtWidgets.QStatusBar(parent=MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.SENTIAL.setText(_translate("MainWindow", "logSential"))
        # self.kernelScan.setText(_translate("MainWindow", "Run Deep Scan "))
    
    from PyQt6.QtWidgets import QPushButton

    def add_block_button(self, row, process_name, pid):
        btn = QPushButton("Block")
        btn.clicked.connect(lambda: self.block_process_network(pid, process_name))
        self.netlist.setCellWidget(row, 4, btn)  # Add button to 5th column

    def showPage1(self):
        self.displayFrame.setCurrentIndex(0)

    def showPage2(self):
        self.displayFrame.setCurrentIndex(1)

    def run_dca_monitoring(self, process_info):
    # Run DCA signal collection
        self.dca.collect_signals(process_info)

    # Only log and show suspicious or potential keylogger processes
        if process_info['behavior'] in ['Suspicious', 'Potential Keylogger']:
        # Log to Monitoring Panel
            log_message = f"{process_info['name']} (PID: {process_info['pid']}) - Behavior: {process_info['behavior']} | Score: {process_info['behavior_score']}"
            self.monitoringLog.append(log_message)

        # Add to Suspicious List
            item = QListWidgetItem(f"{process_info['name']} (PID: {process_info['pid']})")
            self.suslist.addItem(item)

        # Add network connections to netlist
            for conn in process_info['connections']:
                row_position = self.netlist.rowCount()
                self.netlist.insertRow(row_position)
                self.netlist.setItem(row_position, 0, QtWidgets.QTableWidgetItem(process_info['name']))
                self.netlist.setItem(row_position, 1, QtWidgets.QTableWidgetItem(conn.get('local_address', '')))
                self.netlist.setItem(row_position, 2, QtWidgets.QTableWidgetItem(conn.get('remote_address', '')))
                self.netlist.setItem(row_position, 3, QtWidgets.QTableWidgetItem(conn.get('status', '')))

                self.add_block_button(row_position, process_info['name'], process_info['pid'])

    def update_logs(self, message):
        """
        This method updates the monitoring log with new messages.
        """
        if message == "Scanning Processes...":
            if self.monitoringLog.toPlainText().endswith("Scanning Processes..."):
                return
        self.monitoringLog.append(message)

    # Add sus processes to defend frame
    def add_sus_process(self, process_info):
        item_text = process_info['name']
        # Avoid duplicates
        existing_items = [self.suslist.item(i).text() for i in range(self.suslist.count())]
        if item_text not in existing_items:
            self.suslist.addItem(item_text)
    
    def setup_suslist_context_menu(self):
        self.suslist.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.suslist.customContextMenuRequested.connect(self.show_process_context_menu)

    def show_process_context_menu(self, position: QPoint):
        item = self.suslist.itemAt(position)
        if item is None:
            return

        menu = QMenu(self)

        terminate_action = QAction("Terminate Process", self)
        quarantine_action = QAction("Quarantine Executable", self)

        terminate_action.triggered.connect(lambda: self.terminate_process(item.text()))
        quarantine_action.triggered.connect(lambda: self.quarantine_process(item.text()))

        
        menu.addAction(terminate_action)
        menu.addAction(quarantine_action)

        menu.exec(self.suslist.viewport().mapToGlobal(position))

    def block_process_network(self, pid, process_name):
        try:
            rule_name = f"Block_{process_name}_{pid}"
            command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block program="C:\\Windows\\System32\\tasklist.exe" enable=yes'
            # Replace with actual path to the executable of the process (use psutil if needed)

            subprocess.run(command, shell=True, check=True)
            QtWidgets.QMessageBox.information(self, "Firewall", f"Network blocked for: {process_name} (PID: {pid})")
        except subprocess.CalledProcessError as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to apply firewall rule: {e}")

    
    def terminate_process(self, item_text):
        match = re.match(r"(.+?) \(PID: (\d+)\)", item_text)
        if not match:
            QMessageBox.warning(self, "Error", "Invalid item format.")
            return

        process_name, pid = match.groups()
        pid = int(pid)

        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=3)
            QMessageBox.information(self, "Success", f"Terminated {process_name} (PID: {pid})")
        
            # Remove item from list
            for i in range(self.suslist.count()):
                if self.suslist.item(i).text() == item_text:
                    self.suslist.takeItem(i)
                    break

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to terminate: {e}")

    def quarantine_process(self, item_text):
        import shutil, os

        match = re.match(r"(.+?) \(PID: (\d+)\)", item_text)
        if not match:
            QMessageBox.warning(self, "Error", "Invalid item format.")
            return

        process_name, pid = match.groups()
        pid = int(pid)

        try:
            proc = psutil.Process(pid)
            exe_path = proc.exe()
            quarantine_dir = "C:\\logSential\\Quarantine"

            if not os.path.exists(quarantine_dir):
                os.makedirs(quarantine_dir)

            new_path = os.path.join(quarantine_dir, f"{process_name}_{pid}.quarantined")
        
            proc.terminate()
            proc.wait(timeout=3)

            shutil.move(exe_path, new_path)

            QMessageBox.information(self, "Quarantined", f"{process_name} quarantined successfully.")

            # Remove from list
            for i in range(self.suslist.count()):
                if self.suslist.item(i).text() == item_text:
                    self.suslist.takeItem(i)
                    break

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Quarantine failed: {e}")

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec())


    
