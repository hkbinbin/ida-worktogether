from enum import Enum

# config list
PINCODE = "7a29293b1919e727162fa2362a"

# pg_database config
USER = 'postgres'
PASSWORD = '123456'
PG_IP = "127.0.0.1"
PG_PORT = 5432
# TODO fix

class ClientAction(Enum):
    RENAME_FUNC = 1
    EDIT_CMT = 2
    RENAME_LVAR = 3
    REQUEST_LVAR = 4