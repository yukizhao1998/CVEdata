import sqlite3
import sys
from sqlite3 import Error
import configuration as cf

conn = None

def create_connection(db_file):
    """
    create a connection to sqlite3 database
    """
    try:
        return sqlite3.connect(db_file, timeout=10)  # connection via sqlite3
    except Error as e:
        cf.logger.critical(e)
        sys.exit(1)

def fetch_query(query):
    """
    checks whether table exists or not
    :returns boolean yes/no
    """
    cursor = conn.cursor()
    cursor.execute(query)
    result = cursor.fetchall()
    return result is not None else False

if __name__ == "__main__":
    conn = create_connection(cf.DATABASE)
    sql = "SELECT * FROM bug_inducing_commits"
    print(fetch_query(sql))