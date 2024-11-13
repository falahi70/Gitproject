import datetime
import uuid




def current_time():
    return str(datetime.datetime.now())[:19]

def generate_new_GUID():
    uuidFour = uuid.uuid4()
    return uuidFour

