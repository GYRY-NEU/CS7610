import requests
import json
import functools

functionid = ""
def get(key):
    global functionid
    r = requests.get("http://127.0.0.1:12000/value", headers={"key": key, "Host": functionid})
    return r.json()

def put(key, value):
    global functionid
    r = requests.put("http://127.0.0.1:12000/value", headers={
        "Host": functionid
    }, data=json.dumps({
        "value": value,
        "key": key
    }))
    return r.json()

def get_bucket(key):
    global functionid
    r = requests.get("http://127.0.0.1:12000/bucket", headers={"key": key, "Host": functionid})
    return r.json()

def put_bucket(key, value):
    global functionid
    r = requests.put("http://127.0.0.1:12000/bucket", headers={
        "Host": functionid
    }, data=json.dumps({
        "value": value,
        "key": key
    }))
    return r.json()

def async_launch(func):
    pass

def export(func):
    @functools.wraps(func)
    def wrapper(func_args):
        v = json.loads(func_args)
        global functionid
        functionid = v["functionid"]
        retval = func(v)
        print(json.dumps(retval))
        return retval
    return wrapper
