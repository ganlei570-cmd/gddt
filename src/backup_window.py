import shutil
from pathlib import Path
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QListWidget, QListWidgetItem, QAbstractItemView, QWidget, QMessageBox)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

BG    = '#1C1E2A'
CARD  = '#252538'
TXT   = '#FFFFFF'
SEC   = '#8B8FA8'
RED   = '#EF4444'
GREEN = '#22C55E'
BLUE  = '#2563EB'


class BackupWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('备份管理')
        self.setFixedSize(390, 560)
        self.selected_path = None
        self._items = []
        self._setup_ui()
        self._load()

    def _setup_ui(self):
        self.setStyleSheet(f"""
            QDialog {{ background: {BG}; color: {TXT}; font-family: 'Microsoft YaHei'; }}
            QListWidget {{
                background: {CARD}; border: none; border-radius: 10px;
                color: {TXT}; outline: none;
            }}
            QListWidget::item {{ padding: 10px 12px; border-bottom: 1px solid #333448; }}
            QListWidget::item:selected {{ background: #353649; border-radius: 6px; }}
            QPushButton#tool {{
                background: {CARD}; color: {TXT}; border-radius: 8px;
                padding: 6px 12px; font-size: 12px; border: none;
            }}
            QPushButton#tool:hover {{ background: #353649; }}
            QPushButton#red  {{ background: {RED};  color: {TXT}; border-radius: 8px;
                padding: 6px 14px; font-size: 12px; border: none; }}
            QPushButton#green{{ background: {GREEN};color: {TXT}; border-radius: 8px;
                padding: 6px 14px; font-size: 12px; border: none; }}
            QPushButton#blue {{ background: {BLUE}; color: {TXT}; border-radius: 8px;
                padding: 6px 14px; font-size: 12px; border: none; }}
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 14, 12, 12)
        root.setSpacing(10)

        # header
        hdr = QHBoxLayout()
        self._lbl_title = QLabel('备份管理[0/0] 剩:-- GB')
        f = QFont('Microsoft YaHei', 13)
        f.setBold(True)
        self._lbl_title.setFont(f)
        hdr.addWidget(self._lbl_title)
        hdr.addStretch()
        btn_new = QPushButton('+ 新建备份')
        btn_new.setObjectName('blue')
        btn_new.clicked.connect(self._do_new)
        hdr.addWidget(btn_new)
        root.addLayout(hdr)

        # list
        self._list = QListWidget()
        self._list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._list.itemSelectionChanged.connect(self._on_select)
        root.addWidget(self._list)

        # toolbar
        tb = QHBoxLayout()
        btn_all   = QPushButton('全选')
        btn_inv   = QPushButton('反选')
        btn_del   = QPushButton('删除')
        btn_rest  = QPushButton('还原')
        btn_all .setObjectName('tool')
        btn_inv .setObjectName('tool')
        btn_del .setObjectName('red')
        btn_rest.setObjectName('green')
        btn_all .clicked.connect(self._select_all)
        btn_inv .clicked.connect(self._select_inv)
        btn_del .clicked.connect(self._do_delete)
        btn_rest.clicked.connect(self._do_restore)
        for b in (btn_all, btn_inv, btn_del, btn_rest):
            tb.addWidget(b)
        root.addLayout(tb)

        btn_close = QPushButton('关闭')
        btn_close.setObjectName('tool')
        btn_close.clicked.connect(self.reject)
        root.addWidget(btn_close)

    def _load(self):
        from device_worker import load_backups, PROFILES_DIR
        self._items = load_backups()
        self._list.clear()
        for it in self._items:
            size_kb = it['size'] // 1024
            text = f"{it['name']}\n{it['idfv'][:18]}...  {it['mtime']}  {size_kb}KB"
            li = QListWidgetItem(text)
            li.setData(Qt.ItemDataRole.UserRole, str(it['path']))
            self._list.addItem(li)
        try:
            usage = shutil.disk_usage(str(PROFILES_DIR))
            free_gb = usage.free / 1024**3
        except Exception:
            free_gb = 0
        total = len(self._items)
        self._lbl_title.setText(f'备份管理[{total}] 剩:{free_gb:.1f} GB')

    def _on_select(self):
        sel = self._list.selectedItems()
        self.selected_path = sel[0].data(Qt.ItemDataRole.UserRole) if sel else None

    def _select_all(self):
        self._list.selectAll()

    def _select_inv(self):
        for i in range(self._list.count()):
            item = self._list.item(i)
            item.setSelected(not item.isSelected())

    def _do_new(self):
        from device_worker import PROFILES_DIR, next_backup_name
        active = PROFILES_DIR / 'active.json'
        if not active.exists():
            QMessageBox.warning(self, '提示', '尚无 active.json，请先执行一键新机')
            return
        name = next_backup_name()
        import shutil
        shutil.copy2(active, PROFILES_DIR / f'{name}.json')
        self._load()

    def _do_delete(self):
        sel = self._list.selectedItems()
        if not sel:
            return
        r = QMessageBox.question(self, '确认', f'删除 {len(sel)} 个备份？')
        if r != QMessageBox.StandardButton.Yes:
            return
        for item in sel:
            try:
                Path(item.data(Qt.ItemDataRole.UserRole)).unlink(missing_ok=True)
            except Exception:
                pass
        self._load()

    def _do_restore(self):
        if not self.selected_path:
            QMessageBox.information(self, '提示', '请先选择一个备份')
            return
        self.accept()
