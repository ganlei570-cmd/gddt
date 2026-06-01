from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QWidget)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont

from xbzhan_auth import xb_auth, load_cached_key

BG      = '#1C1E2A'
CARD    = '#252538'
PRIMARY = '#2563EB'
GREEN   = '#22C55E'
RED     = '#EF4444'
TXT     = '#FFFFFF'
SEC     = '#8B8FA8'


class _LoginWorker(QThread):
    done = Signal(bool, str)

    def __init__(self, key: str):
        super().__init__()
        self._key = key

    def run(self):
        ok, msg = xb_auth.login(self._key)
        self.done.emit(ok, msg)


class LoginWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('一键新机 — 授权登录')
        self.setFixedSize(390, 280)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.WindowCloseButtonHint)
        self._worker = None
        self._setup_ui()

    def _setup_ui(self):
        self.setStyleSheet(f"""
            QDialog  {{ background: {BG}; font-family: 'Microsoft YaHei'; color: {TXT}; }}
            QLabel   {{ color: {TXT}; background: transparent; }}
            QLineEdit {{
                background: {CARD}; color: {TXT}; border: 1px solid #3A3B50;
                border-radius: 8px; padding: 10px 14px; font-size: 13px;
            }}
            QLineEdit:focus {{ border: 1px solid {PRIMARY}; }}
            QPushButton#login {{
                background: {PRIMARY}; color: {TXT}; border-radius: 10px;
                min-height: 44px; font-size: 14px; border: none;
            }}
            QPushButton#login:hover    {{ background: #1d4ed8; }}
            QPushButton#login:disabled {{ background: #2A2B3A; color: {SEC}; }}
            QPushButton#unbind {{
                background: transparent; color: {SEC}; border: none; font-size: 11px;
            }}
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 28, 24, 20)
        root.setSpacing(14)

        # 标题
        title = QLabel('一键新机')
        f = QFont('Microsoft YaHei', 18); f.setBold(True)
        title.setFont(f)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(title)

        sub = QLabel('输入卡密以继续使用')
        sub.setStyleSheet(f'color: {SEC}; font-size: 12px;')
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(sub)

        # 输入框
        self._input = QLineEdit()
        self._input.setPlaceholderText('请输入卡密')
        self._input.setText(load_cached_key())
        self._input.returnPressed.connect(self._do_login)
        root.addWidget(self._input)

        # 错误提示
        self._lbl_err = QLabel('')
        self._lbl_err.setStyleSheet(f'color: {RED}; font-size: 12px;')
        self._lbl_err.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_err.setFixedHeight(18)
        root.addWidget(self._lbl_err)

        # 登录按钮
        self._btn = QPushButton('登 录')
        self._btn.setObjectName('login')
        self._btn.clicked.connect(self._do_login)
        root.addWidget(self._btn)

        # 底部解绑
        row = QHBoxLayout()
        row.addStretch()
        btn_unbind = QPushButton('解绑当前设备')
        btn_unbind.setObjectName('unbind')
        btn_unbind.clicked.connect(self._do_unbind)
        row.addWidget(btn_unbind)
        w = QWidget(); w.setLayout(row)
        root.addWidget(w)

    def _do_login(self):
        key = self._input.text().strip()
        if not key:
            self._lbl_err.setText('请输入卡密')
            return
        self._lbl_err.setText('')
        self._btn.setEnabled(False)
        self._btn.setText('验证中...')
        self._worker = _LoginWorker(key)
        self._worker.done.connect(self._on_done)
        self._worker.start()

    def _on_done(self, ok: bool, msg: str):
        self._btn.setEnabled(True)
        self._btn.setText('登 录')
        if ok:
            xb_auth.start_heartbeat()
            self.accept()
        else:
            self._lbl_err.setText(msg or '验证失败，请检查卡密')

    def _do_unbind(self):
        key = self._input.text().strip()
        if not key:
            self._lbl_err.setText('请先输入卡密')
            return
        self._btn.setEnabled(False)
        ok, msg = xb_auth.unbind_all(key)
        self._btn.setEnabled(True)
        if ok:
            self._lbl_err.setStyleSheet(f'color: {GREEN}; font-size: 12px;')
            self._lbl_err.setText('解绑成功，可在新设备登录')
        else:
            self._lbl_err.setStyleSheet(f'color: {RED}; font-size: 12px;')
            self._lbl_err.setText(msg)
