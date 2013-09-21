#!/usr/bin/env python
import os, threading, time, sys
import signal
from Queue import Queue
from common import logger
from common.honeypot import Honeypot
from common.globalpot import Globalpot
import ConfigParser
from common import config
from common.common import *
from common import event
from common.textlog import *
from common.hpfeedslog import HpfeedsDBLogger
from common.mongodblog import MongoDBLogger

conf_dir = "./conf"
log_dir = "./log"
pcap_dir = "./pcap"

class SixGuard():
    """Main moulde for 6guard program"""
    def __init__(self, global_config="6guard.cfg"):
        """load the global config file, init SixGuard and start the event anaysis module"""
        #load global config from 6guard.cfg
        conf_parser = ConfigParser.ConfigParser()
        conf_parser.read(global_config)
        #dbloggers, log the attack messages in different ways
        self.dbloggers = []
        self.options = {
        "hpfeeds": conf_parser.get("database_hpfeeds", "enabled").encode('latin1'), 
        "mongodb": conf_parser.get("database_mongodb", "enabled").encode('latin1'),
        "textlog": conf_parser.get("database_textlog", "enabled").encode('latin1'), 
        "center_log": conf_parser.get("logging", "center_log").encode('latin1')
        }
        #set log options according to the global file
        if self.options["hpfeeds"] == "True":
            hpfeeds = HpfeedsDBLogger(conf_parser)
            self.dbloggers.append(hpfeeds)
        if self.options["mongodb"] == "True":
            mongodb = MongoDBLogger(conf_parser)
            self.dbloggers.append(mongodb)
        if self.options["textlog"] == "True":
            textlog = TextDBLogger(conf_parser)
            self.dbloggers.append(textlog)

        #center log, log the debug messages of 6guard program
        center_log_filename = self.options["center_log"]
        self.center_log = logger.Log(center_log_filename)
        
        # Honeypots and Globalpot
        self.honeypots = {} #{'name'-> [conf, thread_instance]}
        self.globalpot_cfg = None
        self.gp = None
        
        #message handle thread status
        self.msghandle_stop = False
        
        # Message management
        self.msg_queue = Queue()
        
        self.msg_handler = threading.Thread(target = self.handle_msg)
        self.msg_handler.setDaemon(True)
        self.msg_handler.start()
        
        # Handle the event message, sometimes will generate an attack message.
        self.event_handler = event.Analysis(self.msg_queue, self.honeypots)
    
    def log_dispatch(self, msg):
        """dispatch the log messages acccording to the options in dbloggers"""
        for dblog in self.dbloggers:
            dblog.write(msg) 
    
    def __del__(self):
        """close dblog and center log"""
        for dblog in self.dbloggers:
            dblog.close()
        self.center_log.close()
    
    def handle_msg(self):
        """Display, log, analyze, and report the EVENT/ATTACK messages."""
        while self.msghandle_stop == False:
            if self.msg_queue.qsize() > 0:
                msg = self.msg_queue.get()
                if msg['level'] == 'EVENT' and self.event_handler != None:
                    self.event_handler.analyze(msg)
                    self.log_dispatch(msg)
                else:
                    self.log_dispatch(msg)
            #TODO: use event to get notification.
    
    def load_config(self):
        """Load the configuration files of honeypots and globalpot."""
        cfg = ConfigParser.SafeConfigParser()
        for parent, dirnames, filenames in os.walk(conf_dir):
            for filename in filenames:
                split_name = filename.split('.')
                if len(split_name) == 2 and split_name[1] == 'ini':
                    conf_file = os.path.join(parent, filename)
                    cfg.read(conf_file)
                    try:
                        config.parse_config(cfg)
                    except config.ParsingError, err:
                        self.center_log.error(str(err))
                        continue
                    self.center_log.info("Configuration file <%s> loaded." % conf_file)
                    
                    if config.config['name'] == "Globalpot":
                        self.globalpot_cfg = config.config.copy()
                    else:
                        honeypot_cfg = config.config.copy()
                        name = honeypot_cfg['name']
                        if self.honeypots.has_key(name):
                            self.center_log.warning("Duplicate name of honeypots: %s\n", name)
                        else:
                            self.honeypots[name] = [honeypot_cfg, None]
                    config.config.clear()
        return
    
    def send_command(self, name, command):
        """Sent commands to honeypot.
           STATUS, START, STOP, RESTART
        """
        if not self.honeypots.has_key(name):
            self.center_log.error("Send a command [%s] to an unexist honeypot [%s].", (command,name))
            return False
        cfg, hp = self.honeypots[name]
        if command == "START":
            if hp == None:
                hp = Honeypot(cfg, self.msg_queue)
                hp.setDaemon(True)
                hp.start()
                self.honeypots[name][1] = hp
                self.center_log.info("[%s] starts." % name)
            return True
        elif command == "STOP":
            if hp != None:
                hp.stop = True
                hp.__del__()
                hp = None
                self.center_log.info("[%s] stops." % name)
            return True
        else:
            self.center_log.error("Send an unknown command [%s] to [%s]", command, name)
            return False
    
    def start_all_honeypots(self):
        """start honeypot moudle"""
        for cfg, hp in self.honeypots.values():
            if hp == None:
                self.send_command(cfg['name'], "START")
        return
    
    def stop_all_honeypots(self):
        """stop honeypots module"""
        for cfg, hp in self.honeypots.values():
            if hp != None:
                self.send_command(cfg['name'], "STOP")
        return
    
    def stop_msghandle(self):
        """stop distpach and analyze message"""
        if self.msg_handler != None:
            self.msghandle_stop = True
    
    def start_globalpot(self):
        """start globalpot moudle"""
        if self.globalpot_cfg != None:
            self.gp = Globalpot(self.globalpot_cfg, self.msg_queue)
            self.gp.setDaemon(True)
            self.gp.start()
        return
    
    def stop_globalpot(self):
        """stop globalpot moudle"""
        if self.gp !=None:
           self.gp.stop = True
    
def main():
    sixguard = SixGuard()
    sixguard.load_config()
    if len(sixguard.honeypots) == 0:
        print "No honeypot configuration files found."
        print "Please run `sudo ./conf_generator.py` to create some."
        sys.exit()
    if sixguard.globalpot_cfg == None:
        print "No globalpot configuration filel found."
        print "Please run `sudo ./conf_generator.py` to create one."
        sys.exit()
    sixguard.start_all_honeypots()
    sixguard.start_globalpot()
    
    if sixguard.event_handler != None:
        sixguard.event_handler.active_detection()
    
    def stop_6guard(signal, frame):
        sixguard.stop_msghandle()
        sixguard.stop_all_honeypots()
        sixguard.stop_globalpot()
        sys.exit()
    
    signal.signal(signal.SIGINT, stop_6guard)
    
    while True:
        raw_input("SixGuard is running...\nPress <Ctrl>+C to stop.\n")

if __name__ == "__main__":
    main()
