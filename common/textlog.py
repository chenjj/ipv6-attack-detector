import dblog
import time

class TextDBLogger(dblog.DBLogger):
    def start(self, cfg):
        self.outfile = file(cfg.get('database_textlog', 'logfile'),'a')

    def write(self, msg):
        print msg
        self.outfile.write(msg)
        self.outfile.flush()

    def close(self):
        self.outfile.close()
