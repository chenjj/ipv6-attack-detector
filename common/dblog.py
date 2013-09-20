import time

class DBLogger(object):
    """Abstract class DBLogger to log attack message"""
    def __init__(self, cfg):
        self.cfg = cfg
        self.start(cfg)

    def start(self, cfg):
        pass

    def write(self):
        pass
