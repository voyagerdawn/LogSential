from PyQt6.QtWidgets import QApplication, QWidget, QFrame, QHBoxLayout
from PyQt6.QtGui import QColor
from PyQt6.QtCore import Qt

app = QApplication([])

# Main window
window = QWidget()
window.setWindowTitle("Nested Frames Example")
window.setGeometry(100, 100, 400, 200)

# Parent Frame
parent_frame = QFrame()
parent_frame.setFrameShape(QFrame.Shape.StyledPanel)
parent_layout = QHBoxLayout(parent_frame)

# First child frame
frame1 = QFrame()
frame1.setFrameShape(QFrame.Shape.StyledPanel)
frame1.setStyleSheet("background-color: lightblue;")

# Second child frame
frame2 = QFrame()
frame2.setFrameShape(QFrame.Shape.StyledPanel)
frame2.setStyleSheet("background-color: lightgreen;")

# Add child frames to parent frame layout
parent_layout.addWidget(frame1)
parent_layout.addWidget(frame2)

# Set parent_frame as the layout of the main window
main_layout = QHBoxLayout(window)
main_layout.addWidget(parent_frame)

window.show()
app.exec()
