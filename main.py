from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import QThread, pyqtSignal
import psutil
import time

# Deep Scan Button UI
class DeepScanFrame(QtWidgets.QFrame):
        def __init__(self, parent=None):
                super().__init__(parent)
                self.setGeometry(290, 290, 171, 48)
                font_id1 = QtGui.QFontDatabase.addApplicationFont("../Assets/Geologica_Cursive-Regular.ttf")
                font_family1 = QtGui.QFontDatabase.applicationFontFamilies(font_id1)[0]
                app_font = QtGui.QFont(font_family1, 14)

                self.kernelScan = QtWidgets.QPushButton("Run deep Scan",self)
                self.kernelScan.setGeometry(11,11,149,26)
                self.kernelScan.setFont(app_font)

                self.setStyleSheet("background-color: #f5f5f5;border-radius: 10px;")
                self.kernelScan.setStyleSheet("background-color: #f5f5f5;""color: #002b5c;")

        def enterEvent(self, event):
                self.setStyleSheet("background-color: #002b5c;")
                self.kernelScan.setStyleSheet("color: white;")
                super().enterEvent(event)
        def leaveEvent(self, event):
                self.setStyleSheet("background-color: #f5f5f5;")  # Original frame color
                self.kernelScan.setStyleSheet("background-color: #f5f5f5; color: #002b5c;")  # Original button color
                super().leaveEvent(event)

# DCA Algo
class DendriticCell:
    def __init__(self):
        self.pamp_signals = 0
        self.danger_signals = 0
        self.safe_signals = 0
        self.collected_antigens = []

    def collect_signals(self, process_info):
        if "keylogger" in process_info['name'].lower():
            self.pamp_signals += 1
        elif "suspicious" in process_info['behavior']:
            self.danger_signals += 1
        else:
            self.safe_signals += 1
        self.collected_antigens.append(process_info)

    def is_mature(self):
        return self.pamp_signals > self.safe_signals and self.danger_signals > 1

    def classify(self):
        if self.is_mature():
            return "Suspicious Process (Mature DC)"
        else:
            return "safe Process (Semi-mature DC)"

# Thread for monitoring
class ProcessMonitor (QThread):
    process_signal = pyqtSignal(dict)

    def run(self):
        while True:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    process_info = {'name': proc.info['name'], 'behavior': 'normal'}
                    self.process_signal.emit(process_info)
                    time.sleep(1)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                      
#Main UI an fucntionalities
class Ui_MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.dca = DendriticCell()
        self.process_monitor = ProcessMonitor()
        self.process_monitor.process_signal.connect(self.run_dca_monitoring)
        self.process_monitor.start()

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

        # Adding two sample pages to the stacked widget
        self.page1 = QtWidgets.QWidget()
        self.page2 = QtWidgets.QWidget()
        #
        self.displayFrame.addWidget(self.page1)
        self.displayFrame.addWidget(self.page2)

        # Add a deep scan button to page1 for testing
        self.deepScanFrame = DeepScanFrame(self.page1)
        self.deepScanFrame.setGeometry(290, 280, 171, 48)

        # self.deepScanFrame = DeepScanFrame(self.displayFrame)
        # self.deepScanFrame.setGeometry(290, 280, 171, 48)

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
        self.monitoringLog.setReadOnly(True)  # Make it read-only
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

    def showPage1(self):
        self.displayFrame.setCurrentIndex(0)

    def showPage2(self):
        self.displayFrame.setCurrentIndex(1)

    def run_dca_monitoring(self, process_info):
        print(f"Received process_info: {process_info}")  # Debugging line
        if isinstance(process_info, dict):
            self.dca.collect_signals(process_info)
            result = self.dca.classify()
            log_output = f"Process {process_info['name']} classified as: {result}"
            self.update_logs(log_output)
        else:
            print(f"Unexpected type: {type(process_info)}")

    def update_logs(self, message):
        """
        This method updates the monitoring log with new messages.
        """
        self.monitoringLog.append(message)

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec())
