import dblog
import time
import pymongo

class MongoDBLogger(dblog.DBLogger):
    def get_db(self, host, port, name, user = '', passwd = ''):
        dbconn = pymongo.Connection(host, port)
        db = pymongo.database.Database(dbconn, name)
        db.authenticate(user, passwd)
        return db

    def start(self, config):
        self.host = config.get("database_mongodb","host")
        self.port = config.get("database_mongodb","port")
        self.user = config.get("database_mongodb","user")
        self.password = config.get("database_mongodb","password")
        self.database = config.get("database_mongodb","database")
        self.collection = config.get("database_mongodb","collection")
        self.db = self.get_db(self.host, int(self.port), self.database, self.user, self.password)

    def write(self, msg):
        self.db[self.collection].insert(msg)

    def close(self):
        self.db.close()
