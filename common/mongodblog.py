import dblog
import time
import pymongo

class MongoDBLogger(dblog.DBLogger):
    """Class MongoDBLogger for logging attack message into mongodb database"""
    def get_db(self, host, port, name, user = '', passwd = ''):
        """Connect mongodb"""
        dbconn = pymongo.Connection(host, port)
        db = pymongo.database.Database(dbconn, name)
        db.authenticate(user, passwd)
        return db

    def start(self, config):
        """Load config and connect to database"""
        self.host = config.get("database_mongodb","host")
        self.port = config.get("database_mongodb","port")
        self.user = config.get("database_mongodb","user")
        self.password = config.get("database_mongodb","password")
        self.database = config.get("database_mongodb","database")
        self.collection = config.get("database_mongodb","collection")
        self.db = self.get_db(self.host, int(self.port), self.database, self.user, self.password)

    def write(self, msg):
        """Write attack message into mongodb"""
        self.db[self.collection].insert(msg)

    def close(self):
        """Close connection"""
        self.db.close()
