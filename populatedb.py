import sqlite3
import hashlib

# Create a connection to the database (or create a new one if it doesn't exist)
conn = sqlite3.connect('employees.db')

# Create a cursor object to execute SQL commands
cursor = conn.cursor()

 # Delete any old data
cursor.execute('''DROP TABLE IF EXISTS employees''')
# Create a table to store employee information
cursor.execute('''CREATE TABLE IF NOT EXISTS employees
					(employee_id INTEGER PRIMARY KEY,
					pin INTEGER,
					name TEXT,
					dob TEXT)''')
# Create employee data
employee_1 = [101,   5993,   "Dwayne Johnson",  "1972-05-02"]
employee_2 = [102,   2468,   "Shania Twain",    "1965-08-28"]
employee_3 = [103,   8723,   "Chris Rock",      "1965-02-07"]
employee_4 = [104,   9205,   "Rafael Grossi",   "1961-01-29"]
# Iterate through the employees
employees = [employee_1, employee_2, employee_3, employee_4]
msg = ''
for employee in employees:
	msg = msg + f'[INFO] Inserting {employee} into the database...\n'
	# Insert the employee information into the database
	cursor.execute("INSERT INTO employees VALUES (?, ?, ?, ?)", (employee[0], employee[1], employee[2], employee[3]))
# Commit the changes to the database

msg = msg + '[INFO] Database created successfully.'

print(msg)

## ACS users
cursor.execute('''DROP TABLE IF EXISTS auth''')

cursor.execute('''CREATE TABLE IF NOT EXISTS auth
		(employee_id INTEGER PRIMARY KEY,
		 username TEXT,
		 password TEXT,
		 permissions INTEGER)''')
'''
	Permissions:
		1:admin full read-write-execute
		0:user 	read-only
'''

# Create access control system admin and other account users.
admin = [901,	"oracle",	"7b7E0^Sh$mhx",	1]
user  = [902, 	"user",		"vQ2g0Gsb7",	0]
acs_users = [admin, user]

# Iterate through the Access Control System admin and user accounts.
for user in acs_users:
	hashpass = hashlib.md5(user[2].encode('utf8')).hexdigest()
	print('[i] Inserting {} into the database...'.format(user))
	cursor.execute("INSERT INTO auth VALUES (?, ?, ?, ?)", (user[0], user[1], hashpass, user[3]))

# Commit the changes to the database
conn.commit()


cursor.execute('''SELECT * FROM employees;''')
db_rows = cursor.fetchall()
print(db_rows)

cursor.execute('''SELECT * FROM auth;''')
db_rows = cursor.fetchall()
print(db_rows)

#for row in db_rows:
#	print(row)

#print(cursor.fetchall())

# Close the database connection
conn.close()
