import sys, io, logging
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

_LOG_PATH = Path(__file__).parent.parent / 'register.log'


def _setup_log():
    log = logging.getLogger()
    log.setLevel(logging.DEBUG)
    fmt = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(module)s:%(lineno)d] %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')

    class FlushHandler(logging.FileHandler):
        def emit(self, record):
            super().emit(record)
            self.flush()

    fh = FlushHandler(str(_LOG_PATH), mode='w', encoding='utf-8')
    fh.setFormatter(fmt)
    log.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    return log


log = _setup_log()

try:
    import platform
    log.info('启动 IOS-GDDT 一键新机')
    log.info('Python %s | %s', sys.version.split()[0], platform.platform())

    from PySide6.QtWidgets import QApplication
    from PySide6.QtGui import QFont

    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    font = QFont('Microsoft YaHei', 10)
    app.setFont(font)

    sys.path.insert(0, str(Path(__file__).parent))
    from login_window import LoginWindow
    from main_window import MainWindow

    login = LoginWindow()
    if login.exec() != LoginWindow.DialogCode.Accepted:
        log.info('用户取消登录，退出')
        sys.exit(0)

    log.info('卡密验证通过，打开主窗口')
    win = MainWindow()
    win.show()
    log.info('窗口已显示')
    code = app.exec()
    log.info('退出 code=%d', code)
    sys.exit(code)

except Exception:
    import traceback
    log.critical('启动崩溃:\n%s', traceback.format_exc())
    sys.exit(1)
