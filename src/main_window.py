from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFrame, QGridLayout, QMessageBox)
from PySide6.QtCore import Qt, QThread
from PySide6.QtGui import QPainter, QColor, QBrush, QFont

from device_worker import DeviceWorker

BG      = '#1C1E2A'
CARD    = '#252538'
PRIMARY = '#2563EB'
CTA     = '#F97316'
GREEN   = '#22C55E'
TXT     = '#FFFFFF'
SEC     = '#8B8FA8'
BTN_BG  = '#353649'
TOGGLE_ON  = '#22C55E'
TOGGLE_OFF = '#3A3B50'

_QSS = f"""
QMainWindow, QWidget#root {{ background: {BG}; color: {TXT}; font-family:'Microsoft YaHei'; }}
QLabel {{ color: {TXT}; background: transparent; }}
QPushButton#btn {{
    background: {BTN_BG}; color: {TXT}; border-radius: 10px;
    min-height: 44px; font-size: 13px; border: none;
}}
QPushButton#btn:hover    {{ background: #404358; }}
QPushButton#btn:disabled {{ color: {SEC}; background: #252535; }}
QPushButton#link         {{ background: transparent; border: none; font-size: 12px; }}
QPushButton#connect      {{
    background: {PRIMARY}; color: {TXT}; border-radius: 8px;
    min-height: 30px; min-width: 58px; font-size: 12px; border: none;
}}
"""


class ToggleSwitch(QWidget):
    def __init__(self, checked=False, enabled=True, parent=None):
        super().__init__(parent)
        self._on = checked
        self.setEnabled(enabled)
        self.setFixedSize(51, 31)

    def isChecked(self): return self._on

    def setChecked(self, v):
        self._on = v
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if not self.isEnabled():
            track = QColor('#2A2B3A')
        elif self._on:
            track = QColor(TOGGLE_ON)
        else:
            track = QColor(TOGGLE_OFF)
        p.setBrush(QBrush(track))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(0, 0, 51, 31, 15, 15)
        p.setBrush(QBrush(QColor('#FFFFFF')))
        thumb_x = 24 if self._on else 4
        p.drawEllipse(thumb_x, 4, 23, 23)

    def mousePressEvent(self, _):
        if self.isEnabled():
            self.setChecked(not self._on)


def lbl(text, size=13, color=TXT, bold=False):
    w = QLabel(text)
    f = QFont('Microsoft YaHei', size)
    f.setBold(bold)
    w.setFont(f)
    w.setStyleSheet(f'color:{color};')
    return w


def card(inner_layout, bg=CARD):
    f = QFrame()
    f.setStyleSheet(f'QFrame{{background:{bg};border-radius:12px;}}')
    f.setLayout(inner_layout)
    return f


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('一键新机')
        self.setFixedWidth(390)
        self.setStyleSheet(_QSS)
        self._worker: QThread | None = None

        root = QWidget(); root.setObjectName('root')
        self.setCentralWidget(root)
        lay = QVBoxLayout(root)
        lay.setContentsMargins(12, 14, 12, 14)
        lay.setSpacing(10)

        lay.addWidget(self._toolbar())
        lay.addWidget(self._toggles_card())
        lay.addWidget(self._device_card())
        lay.addWidget(self._app_card())
        lay.addWidget(self._btn_grid())
        lay.addStretch()
        lay.addWidget(self._footer())

    # ── sections ──────────────────────────────────────────────────────────

    def _toolbar(self):
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        ex = QPushButton('安全退出'); ex.setObjectName('link')
        ex.setStyleSheet(f'color:{SEC};background:transparent;border:none;font-size:12px;')
        ex.clicked.connect(self.close)
        row.addWidget(ex)
        row.addStretch()
        row.addWidget(lbl('一键新机', 16, TXT, True))
        row.addStretch()
        gear = QPushButton('⚙')
        gear.setObjectName('link')
        gear.setStyleSheet(f'color:{SEC};background:transparent;border:none;font-size:18px;')
        row.addWidget(gear)
        w = QWidget(); w.setLayout(row)
        return w

    def _toggles_card(self):
        lay = QVBoxLayout()
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(10)
        for name, checked, enabled in [('模拟定位', False, False),
                                        ('随机参数', True,  True),
                                        ('VPN',     False, False)]:
            row = QHBoxLayout()
            row.addWidget(lbl(name))
            row.addStretch()
            row.addWidget(ToggleSwitch(checked=checked, enabled=enabled))
            w = QWidget(); w.setLayout(row)
            lay.addWidget(w)
        row = QHBoxLayout()
        row.addWidget(lbl('新机参数'))
        row.addStretch()
        b = QPushButton('配置'); b.setObjectName('btn')
        b.setFixedSize(60, 28); b.setEnabled(False)
        row.addWidget(b)
        w = QWidget(); w.setLayout(row)
        lay.addWidget(w)
        return card(lay)

    def _device_card(self):
        lay = QHBoxLayout()
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(10)
        icon = lbl('📱', 28); icon.setFixedWidth(36)
        lay.addWidget(icon)
        v = QVBoxLayout(); v.setSpacing(2)
        self._lbl_model = lbl('未连接', 13, TXT, True)
        self._lbl_ver   = lbl('点击连接获取设备信息', 11, SEC)
        v.addWidget(self._lbl_model)
        v.addWidget(self._lbl_ver)
        lay.addLayout(v)
        lay.addStretch()
        self._btn_connect = QPushButton('连接')
        self._btn_connect.setObjectName('connect')
        self._btn_connect.clicked.connect(self._do_connect)
        lay.addWidget(self._btn_connect)
        return card(lay)

    def _app_card(self):
        lay = QVBoxLayout()
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(8)
        hdr = QHBoxLayout()
        hdr.addWidget(lbl('应用列表[1]', 11, SEC))
        hdr.addStretch()
        hdr.addWidget(lbl('高德地图', 11, SEC))
        w = QWidget(); w.setLayout(hdr)
        lay.addWidget(w)
        row = QHBoxLayout(); row.setSpacing(20)
        for name, checked in [('保存参数', True), ('全息备份', True)]:
            sub = QHBoxLayout(); sub.setSpacing(6)
            sub.addWidget(lbl(name, 12))
            t = ToggleSwitch(checked=checked)
            sub.addWidget(t)
            ww = QWidget(); ww.setLayout(sub)
            row.addWidget(ww)
        row.addStretch()
        w2 = QWidget(); w2.setLayout(row)
        lay.addWidget(w2)
        return card(lay)

    def _btn_grid(self):
        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(8)
        buttons = [
            ('一键新机',    True,  self._do_new_machine, 0, 0),
            ('清理Safari',  False, None,                  0, 1),
            ('备份记录',    True,  self._do_backup,       0, 2),
            ('清理剪贴板',  False, None,                  1, 0),
            ('清理Keychain',True,  self._do_clear_kc,    1, 1),
            ('还原机器',    True,  self._do_restore,      1, 2),
        ]
        for text, enabled, slot, r, c in buttons:
            b = QPushButton(text); b.setObjectName('btn')
            b.setEnabled(enabled)
            if slot:
                b.clicked.connect(slot)
            grid.addWidget(b, r, c)
        w = QWidget(); w.setLayout(grid)
        return w

    def _footer(self):
        row = QHBoxLayout()
        row.setContentsMargins(4, 0, 4, 0)
        row.addWidget(lbl('v1.0.0', 11, SEC))
        row.addStretch()
        pay = QPushButton('充值'); pay.setEnabled(False)
        pay.setStyleSheet(f'color:{CTA};background:transparent;border:none;font-size:12px;')
        row.addWidget(pay)
        row.addSpacing(8)
        disc = QPushButton('免责声明')
        disc.setStyleSheet(f'color:{PRIMARY};background:transparent;border:none;font-size:12px;')
        row.addWidget(disc)
        w = QWidget(); w.setLayout(row)
        return w

    # ── workers ───────────────────────────────────────────────────────────

    def _run(self, op, **kwargs):
        if self._worker and self._worker.isRunning():
            QMessageBox.information(self, '提示', '当前有任务正在执行，请稍候')
            return
        self._worker = DeviceWorker(op, **kwargs)
        self._worker.operation_done.connect(self._on_done)
        self._worker.device_info.connect(self._on_device_info)
        self._worker.log_message.connect(self._on_log)
        self._worker.start()
        self._btn_connect.setEnabled(False)

    def _on_done(self, ok, msg):
        self._btn_connect.setEnabled(True)
        if ok:
            QMessageBox.information(self, '完成', msg)
        else:
            QMessageBox.warning(self, '失败', msg)

    def _on_device_info(self, info):
        self._lbl_model.setText(info.get('model', '未知'))
        self._lbl_ver.setText(
            f"iOS {info.get('sysver','')}  "
            f"IDFV: {info.get('idfv','')[:8]}…")

    def _on_log(self, msg):
        print(f'[UI] {msg}')

    def _do_connect(self):      self._run('connect')
    def _do_new_machine(self):  self._run('new_machine')
    def _do_clear_kc(self):     self._run('clear_keychain')

    def _do_backup(self):
        from backup_window import BackupWindow
        w = BackupWindow(self)
        w.exec()

    def _do_restore(self):
        from backup_window import BackupWindow
        w = BackupWindow(self)
        if w.exec() and w.selected_path:
            self._run('restore', backup_path=w.selected_path)
