import sys
import signal
from flask import Flask, jsonify, request
import sqlite3
import hashlib
from datetime import datetime
import json
import pprint
import base64
import requests

from flask_cors import CORS




# Define DB objects
conn = None
cursor = None


# By default skip the database creation step.
SKIP_SETUP = True
# If a command line argument is supplied (len(sys.argv) is always at least 1 - the program itself is an argument)
if len(sys.argv) > 1 and "initdb" in sys.argv:
    # If the user types `python3 frs.py initdb`
    SKIP_SETUP = False

# Define app, ip address, and port number
app = Flask(__name__)


CORS(app)
# ip_addr =  '192.168.10.66'
# port = 4040

# Facial Recognition System (used for requests later)
frs_ip = "192.168.10.209"
frs_port = 4410

sensitivity_threshold = 0.8


# Route for default request @ http://{ip_addr}:{port}/
# Requires:         None
# Returns:          message:JSON - Information message identifying the program.
# Expected Action:  Returns a fairly standard default JSON message to the request
@app.route("/")
def hello():
    return jsonify(
        message="[INFO] Connection established to the Central Access Control System. Please use API commands."
    )


# Function to log to `all.log` and a specific file of the user's choosing
# Requires:         filename:string - the filename of the user-chosen log
# 					request:string - the request that is being processed,
#                                       use `ip_addr` (this machine's IP if it's just an internal method call)
# 					src_ip:string - the source ip address that made the request - can be 127.0.0.1 if an internal call (e.g. auth.log)
# 					log_type:int - a number representing the type of log, 0=INFO, 1=ERROR, 2=FATAL
# 					content:string - data to be written to the file
# Returns:          return_code:int - a return code for the logging attempt, 0=FAIL, 1=SUCCESS
# Expected Action:  Open log file, write JSON data, close file
def log(filename, request, src_ip, log_type, content):
    filename = "log/" + filename

    return_code = 0  # Default = FAIL

    # Get timestamp
    date_time = datetime.now()
    timestamp = date_time.strftime("%d-%m-%Y @ %H:%M:%S")

    # Set the string for the log_type

    # log_type = 0 # info - information including authentication success and failure
    # log_type = 1 # error - errors in program execution
    # log_type = 2 # fatal - fatal errors that cause the program to exit/shutdown
    if log_type == 0:
        str_log_type = "INFO"
    elif log_type == 1:
        str_log_type = "ERROR"
    elif log_type == 2:
        str_log_type = "FATAL"
    else:
        print("[ERROR] Error writing to log file!")
        return return_code

    req = str(request)
    ip = str(src_ip)
    log_content = content

    log_entry = {
        "timestamp": timestamp,
        "request": req,
        "source_ip": ip,
        "log_type": str_log_type,
        "log_content": log_content,
    }
    log_entry_dump = json.dumps(log_entry, indent=4)

    # Write to master log
    try:
        with open("log/all.log", "a") as file:
            file.write(log_entry_dump)
            file.close()
            return_code = 1
    except:
        print("[ERROR] Error writing to log file!")

    # Write to individual log
    try:
        with open(filename, "a") as file:
            file.write(log_entry_dump)
            file.close()
            return_code = 1
    except:
        print("[ERROR] Error writing to log file!")

    pprint.pprint(log_entry)

    return return_code


# Function for authenticating requests to this system. NOT authentication logic for physical access.
# Requires:			username:string - a username to lookup in the database
# 					password:string - a password for the given username in the database
# Returns:			auth_result:int - 0 = authentication failed, 1 = authentication successful
# Expected Action:	Hash the given password, lookup the pre-hashed password in the db for the username provided, compare the two, log (info) and return auth_result
def authenticate_request(username, password):
    req = "internal_method_call"
    src_ip = "localhost"

    msg = f"[ATTEMPT] Attempted login for user: {username}..."

    # Check for blank requests
    if username is None or password is None:
        msg = msg + " " + "[FAIL] Username or password was not provided."
        log("auth.log", req, src_ip, 0, msg)
        return 0
    global cursor
    cursor.execute("""SELECT password FROM auth WHERE username = (?);""", (username,))
    retrieved_password = cursor.fetchone()
    retrieved_password = retrieved_password[0]
    hashpass = hashlib.md5(password.encode("utf8")).hexdigest()
    # print(hashpass, retrieved_password)
    if hashpass != retrieved_password:
        auth_result = 0
        msg = msg + " " + "[FAIL] Incorrect username or password provided."
    else:
        auth_result = 1
        msg = msg + " " + f"[SUCCESS] Authenticated successfully for user: {username}."

    log("auth.log", req, src_ip, 0, msg)
    return auth_result


# Route to create the database
# Requires:			None, but requests are authenticated unless called from within the program (here)
# Returns:			JSON(msg:string)
# Expected Action:	Authenticate request, execute query, logs
@app.route("/setup_db", methods=["GET", "POST"])
def setup_db():
    msg = ""

    if request.authorization:
        # print(request)
        username = request.authorization.username
        password = request.authorization.password

        req = str(request)
        src_ip = str(request.remote_addr)

        msg = msg + " " + "[INFO] DB creation requested..."
        msg = msg + " " + "[INFO] Authenticating request..."

        auth_result = authenticate_request(username, password)
    else:
        req = "internal_method_call"
        src_ip = "localhost"

        msg = msg + " " + "[INFO] DB creation requested..."
        auth_result = 1

    if auth_result:
        global cursor
        try:
            msg = msg + " " + "[INFO] DB creation initiated..."
            # Delete any old data
            cursor.execute("""DROP TABLE IF EXISTS employees""")
            # Create a table to store employee information
            cursor.execute(
                """CREATE TABLE IF NOT EXISTS employees
                              (employee_id INTEGER PRIMARY KEY,
                              pin INTEGER,
                              name TEXT,
                              dob TEXT)"""
            )
            # Create employee data
            employee_1 = [101, 5993, "Dwayne Johnson", "1972-05-02"]
            employee_2 = [102, 2468, "Shania Twain", "1965-08-28"]
            employee_3 = [103, 8723, "Chris Rock", "1965-02-07"]
            employee_4 = [104, 9205, "Rafael Grossi", "1961-01-29"]
            # Iterate through the employees
            employees = [employee_1, employee_2, employee_3, employee_4]
            for employee in employees:
                msg = (
                    msg
                    + " "
                    + "[INFO] Inserting {} into the database...".format(employee)
                )
                # Insert the employee information into the database
                cursor.execute(
                    "INSERT INTO employees VALUES (?, ?, ?, ?)",
                    (employee[0], employee[1], employee[2], employee[3]),
                )
            # Commit the changes to the database
            conn.commit()
            msg = msg + " " + "[INFO] Database created successfully."
        except:
            msg = msg + " " + "[FATAL] Error in database creation..."
            log("system_state.log", req, src_ip, 2, msg)
            sys.exit(0)
    else:
        msg = msg + " " + "[FAIL] Authentication failed."

    log("system_state.log", req, src_ip, 0, msg)
    return jsonify(message=msg)


# Route to read all data from the database
# Requires:			None, but requests are authenticated
# Returns:			JSON(data:list OR msg:string) - a JSON endoded list of the database, row by row
# Expected Action:	Authenticate request, execute query, return results or message
@app.route("/read_all_data", methods=["GET", "POST"])
def read_all_data():
    global cursor

    msg = ""

    username = request.authorization.username
    password = request.authorization.password

    req = str(request)
    src_ip = str(request.remote_addr)

    # Check for blank requests
    auth_result = authenticate_request(username, password)

    if auth_result:
        msg = msg + " " + "[INFO] Reading all data from database."
        try:
            cursor.execute("""SELECT * FROM employees;""")
            db_rows = cursor.fetchall()
            msg = msg + " " + "[INFO] Data read successfully."
            log("read_all.log", req, src_ip, 0, msg)
            return jsonify(data=db_rows)
        except Exception as e:
            msg = msg + "[ERROR] Error executing command! Could not read all data."

            log("read_all.log", req, src_ip, 1, msg)
            return jsonify(message=msg)
    else:
        msg = msg + "[FAIL] Authentication failed."
        log("read_all.log", req, src_ip, 1, msg)
        return jsonify(message=msg)


# Route to adjust the sensitivity threshold for facial recognition confidence scores
# Requires:			new_threshold:float - the new sensitivity threshold, between 0 and 1
# Returns:			None
# Expected Action:	Receive threshold, sanity check, edit sensitivity, log
@app.route("/set_sensitivity/<threshold>", methods=["GET", "POST"])
def set_sensitivity(threshold):
    global sensitivity_threshold

    req = str(request)
    src_ip = str(request.remote_addr)

    try:
        threshold = float(threshold)
        if threshold > 1.0:
            sensitivity_threshold = 1.0
        elif sensitivity_threshold < 0:
            sensitivity_threshold = 0
        else:
            sensitivity_threshold = threshold
        msg = f"[INFO] New sensitivity threshold set to {sensitivity_threshold}"
        log("threshold.log", req, src_ip, 0, msg)
    except Exception as e:
        msg = f"[ERROR] Cannot parse the following supplied input: <{threshold}>."
        log("config.log", req, src_ip, 1, msg)
        print(e)
    return jsonify(msg)


# Route to accept employee ID, PIN code, and face image and perform authentication.
# Requires:			employee_id:int - the ID of the employee attempting to gain access
#                   pin:int - the pin of the employee attempting to gain access
#                   image:b64(*.jpg) - base64-encoded bytestring of face image of the employee attempting to gain access
# Returns:			JSON(auth_result:int,message:str) - the JSON encoded integer authentication result, 0=FAIL, 1=SUCCESS, and a message explaining the reason for the result
# Expected Action:	Receive ID, PIN, and Image, lookup the ID in the database, send image to the Facial Recognition System (FRS), ensure FRS ID returns matching ID, check PIN, return result and/or open door
@app.route('/access_request', methods=['POST'])
def access_request():
    global cursor
    global sensitivity_threshold
    face_check = 0
    pin_check = 0
    auth_result = 0
    # TODO: authentication logic here
    req = str(request)
    src_ip = str(request.remote_addr)
    #print(f'{req} from {src_ip}')
    
    # Get data
    data = request.json
    employee_id = data['employee_id']
    #print(type(employee_id))
    employee_pin = data['pin']
    encoded_string = base64.b64decode(data['image'])
    # Decode and store face temporarily
    with open("tmp_face.jpg", "wb") as fh:
        fh.write(encoded_string)

    msg = f'[INFO] Attempting to authenticate access control request for Employee ID {employee_id}.'
    
    # Employee Lookup
    try: # Get Employee ID from DB
        cursor.execute('''SELECT pin FROM employees WHERE employee_id = (?)''', (employee_id,))
        pin_lookup = cursor.fetchone()
        pin_lookup = pin_lookup[0]
    except:
        auth_result = 0
        msg = msg + ' ' + f'[FAIL] Employee ID {employee_id} not found in database.'
        # Log the result.
        log('access.log', req, src_ip, 1, msg)
        return jsonify(auth_result=auth_result, message=msg)

    try: # Encode and send face to Facial Recognition System for analysis 
        with open("tmp_face.jpg", "rb") as image_file:
            encoded_image = base64.b64encode(image_file.read()).decode('utf-8')
        data = {"image":encoded_image}
        url = 'http://' + str(frs_ip) + ':' + str(frs_port) + '/match'
        response = requests.post(url, json=data)
        
        frs_resp = response.json()
        frs_ID = frs_resp['data'][0]
        frs_score = frs_resp['data'][1]
        # print(f'frs_ID:{frs_ID} && frs_score:{frs_score} && employee_id:{employee_id}')
        # print('frs_ID:', type(frs_ID), ' && frs_score:', type(frs_score), ' && employee_id:', type(employee_id))
        
        # Facial Recognition Check
        if frs_ID == int(employee_id):
            face_check = 1
        else:
            face_check = 0
            auth_result = 0
            msg = msg + ' ' + f'[FAIL] Facial Recognition System could not recognise face for Employee {employee_id}.'
            # Log the result.
            log('access.log', req, src_ip, 1, msg)
            return jsonify(auth_result=auth_result, message=msg)
    except:
        auth_result = 0
        msg = msg + ' ' + f'[FAIL] Error during Facial Recognition System lookup for Employee {employee_id}.'
        # Log the result.
        log('access.log', req, src_ip, 1, msg)
        return jsonify(auth_result=auth_result, message=msg)
    
    # Pin check
    try: # Check PINs match
        if employee_pin == pin_lookup:
            pin_check = 1
        else:
            auth_result = 0
            msg = msg + ' ' + f'[FAIL] Incorrect PIN for Employee {employee_id}.'
            # Log the result.
            log('access.log', req, src_ip, 1, msg)
            return jsonify(auth_result=auth_result, message=msg)
    except:
        msg = msg + ' ' + f'[FAIL] Error checking PIN for Employee {employee_id}.'
         # Log the result.
        log('access.log', req, src_ip, 1, msg)
        return jsonify(auth_result=auth_result, message=msg)
            
    if face_check & pin_check:
        auth_result = 1
        msg = msg + ' ' + f'[SUCCESS] Employee {employee_id} successfully authenticated. Access granted.'
         # Log the result.
        log('access.log', req, src_ip, 0, msg)
        return jsonify(auth_result=auth_result, message=msg)
    else: 
        msg = msg + ' ' + '[FAIL] Authentication Failure - check pin or try again...'
        auth_result = 0
         # Log the result.
        log('access.log', req, src_ip, 1, msg)
        return jsonify(auth_result=auth_result, message=msg)
   
    # Log the result.
    log('access.log', req, src_ip, 0, msg)
    
    return jsonify(auth_result=auth_result, message=msg)


# Function to open a connection to the employees database
# Requires:			None
# Returns:			None
# Expected Action:	Connect to database and log
def db_connect():
    with app.app_context():
        global conn
        global cursor

        req = "internal_method_call"
        src_ip = "localhost"
        msg = "[INFO] Connecting to database."

        try:
            # Create a connection to the database (or create a new one if it doesn't exist)
            conn = sqlite3.connect("employees.db", check_same_thread=False)
            # Create a cursor object to execute SQL commands
            cursor = conn.cursor()
            msg = msg + " " + "[INFO] Connected successfully to database."
            log("db_conn.log", req, src_ip, 0, msg)
        except:
            msg = (
                msg
                + " "
                + "[FATAL] Database connection failed - check .db file exists. Exiting program."
            )
            log("db_conn.log", req, src_ip, 2, msg)
            sys.exit(0)


# Function to catch ctrl+c inputs and close the connection
# Requires:			sig:signal - the signal to close the connection
# 					frame:frame - unsure
# Returns:			None
# Expected Action:	Program exits with error message and database connection closed gracefully.
def signal_handler(sig, frame):
    global conn
    conn.close()
    msg = "[EXIT] Program terminated. Exiting gracefully..."
    # log('system_state.log', 'CTRL+C', ip_addr, 2, msg)
    sys.exit(0)



def format_recent_logs(input_file, output_file, limit):
    # Read data from the input file
    with open(input_file, 'r') as file:
        log_entries = file.read().strip()
 
    # Modify the delimiter to properly split JSON objects
    json_objects = []
    start = 0
    for end in range(len(log_entries)):
        if log_entries[end] == '}':
            json_objects.append(json.loads(log_entries[start:end + 1]))
            start = end + 1

    # Limit the number of logs to the specified 'limit' from the end
    json_objects = json_objects[-limit:]
 
    # Write formatted data into the output JSON file
    with open(output_file, 'w') as file:
        file.write(json.dumps(json_objects, indent=20))

# Example usage:
input_file_path = 'log/all.log'
output_file_path = 'formatted_all.log.json'
format_recent_logs(input_file_path, output_file_path, limit=20)



@app.route('/api/get_data', methods=['GET'])
def get_data():
    # Read your JSON file and return it
    # For simplicity, let's assume you have a file named data.json in the same directory
    with open('formatted_all.log.json', 'r') as file:
        data = file.read()
    return data


# Main Program!
if __name__ == "__main__":
    print("[START] Program started.")
    signal.signal(signal.SIGINT, signal_handler)
    db_connect()
    if SKIP_SETUP == False:
        with app.test_request_context("/setup_db", method="POST"):
            setup_db()
    else:
        print("[INFO] Skipping database initialisation.")
    flask_msg = "[FLASK] Starting Flask Server..."
    
    log("system_state.log", "__main__", "localhost", 0, flask_msg)
    app.run(debug=True, port=8001)