# Physical Protection System (PPS) Central Access Control System (CACS)

## Description and Purpose

This is a Flask server designed to:

1. Take inputs from the MFA Access Control Panel (ID, PIN, Image)
2. Ask the Facial Recognition System (FRS) what employee ID best matches the image provided (matching the face)
3. Looking up the PIN and checking that the PIN and ID matches as it should.
4. Send the response back to the MFA Access Control Panel

## Installation Instructions 

**Python Version:** `3.8.10`

**APT Extras:** None

**PIP Packages:**
```bash
pip install requirements.txt
```

## Directory Structure

`log` - folder containing log files

`tmp` - test folder, can be ignored

## Starting the Server

**If database file `employees.db` is missing** you can execute the `populatedb.py` file:

````bash
python3 populatedb.py
````

If you require the `employees` (not the `auth`) table to be reset, you can stop the server and then run the main script with the following argument:

```bash
python3 access_ctrl_server.py initdb
```

Be advised - running the commands above will delete the database tables and replace them with *whatever* is in the script... so check if you really need to wipe the tables, and if so, what you're wiping them with...

**Otherwise, for NORMAL execution**, simply run the following code:

```bash
python3 access_ctrl_server.py
```