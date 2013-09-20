import dblog
from common import *
import time

class TextDBLogger(dblog.DBLogger):
    """Class TextDBLogger for logging attack message into file"""
    def start(self, cfg):
        """Load config and open log file"""
        self.outfile = file(cfg.get('database_textlog', 'logfile'),'a')

    def write(self, msg):
        """Write message to file"""
        msg_str = self.format_msg(msg)
        print msg_str
        self.outfile.write(msg_str)
        self.outfile.flush()

    def close(self):
        """Close file handle"""
        self.outfile.close()

    def format_msg(self, msg):
        """Format messages"""
        time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(msg['timestamp']))
        
        msg_str = "\n[%s]\n" % msg['level']
        msg_str += "Timestamp: %s\n" % time_str
        msg_str += "Reported by: %s\n" % msg['from']
        msg_str += "Type: %s\n" % msg['type']
        msg_str += "Name: %s\n" % msg['name']
        if msg['level'] == 'ATTACK':
            msg_str += "Attacker: [%s]" % msg['attacker']
            if msg.has_key("attacker_mac"):
                msg_str += "  %s (%s)\n" % (msg['attacker_mac'], mac2vendor(msg['attacker_mac']))
            else:
                msg_str += '\n'
            msg_str += "Victim  : [%s]" % msg['victim']
            if msg.has_key("victim_mac"):
                msg_str += "  %s (%s)\n" % (msg['victim_mac'], mac2vendor(msg['victim_mac']))
            else:
                msg_str += '\n'
        if msg.has_key('tgt'):
            msg_str += "Target [%s]\n" % msg['tgt']
        if msg.has_key("src"):
            msg_str += "Source: [%s]" % msg['src']
            if msg.has_key("lladdr"):
                msg_str += "  MAC: %s (%s)" % (msg['lladdr'], mac2vendor(msg['lladdr']))
            msg_str += "\n"
        msg_str += "Utility: %s\n" % msg['util']
        msg_str += "Packets: %s\n" % msg['pcap']
        return msg_str
