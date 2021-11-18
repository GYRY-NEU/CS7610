import requests
import json

def get(key):
    r = requests.get("http://127.0.0.1:12000/value", headers={"key": key})
    return r.json()

def put(key, value):
    r = requests.put("http://127.0.0.1:12000/value", data=json.dumps({"value": value, "key": key}))
    return r.json()

def export(func):
    import functools
    import json

    @functools.wraps(func)
    def wrapper(func_args):
        v = json.loads(func_args)
        retval = func(v)
        print(json.dumps(retval))
        return retval
    return wrapper
