import logging
import logging.handlers

syslog_logger = logging.getLogger("METIS-Syslog")
syslog_logger.setLevel(logging.INFO)
handler = logging.handlers.SysLogHandler(address=("localhost", 514), facility=logging.handlers.SysLogHandler.LOG_USER)
syslog_logger.addHandler(handler)

def send_syslog_alert(message: str):
    syslog_logger.info(message)