import sys
import optparse
import datetime
import logging
import string
logging.basicConfig(level=logging.CRITICAL)
import hpfeeds
from ConfigParser import ConfigParser

class HpfeedsPublish():
    def __init__(self):
        config=ConfigParser()
        CONFFILE = "./conf/hpfeeds.ini"
        config.read(CONFFILE)
        self.HOST=config.get("hpfeeds","HOST")
        self.PORT=config.get("hpfeeds","PORT")
        self.IDENT=config.get("hpfeeds","IDENT")
        self.SECRET=config.get("hpfeeds","SECRET")
        self.CHANNEL = config.get("hpfeeds","CHANNEL")
        self.handler =  hpfeeds.new(str(self.HOST), int(self.PORT), str(self.IDENT), str(self.SECRET))
    
    def publish(self,msg):
        self.handler.publish(self.CHANNEL, msg)

