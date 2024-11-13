import sqlite3
from optparse import OptionParser
import sys


parser = OptionParser()


parser.add_option("-c", "--cname", dest="cname",
	help="Enter Your Credential Name")

parser.add_option("-u", "--uname", dest="uname",
	help="Enter Your Username")

parser.add_option("-s", "--string", dest="string",
	help="Enter Your Secure String")

(options, args) = parser.parse_args()

try:
    sqliteConnection = sqlite3.connect('powerdatabase.db')
    cursor = sqliteConnection.cursor()
except:
    print("Database Connection Error")
    sys.exit(1)


query = f"INSERT INTO information (CName, UName, String) VALUES ('{options.cname}','{options.uname}','{options.string}')"

try:
    insert = cursor.execute(query)
    sqliteConnection.commit()
    cursor.close()
    print("Credential Inserted Successfully")
except:
    print("Inserting Data Failed")