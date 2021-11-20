from numpy.lib.shape_base import dsplit
import requests
import random
import sys
import time
import json

def singleClient(functionid, endpoint):
    ROUND = requests.get(endpoint+"/getRound", headers={"Host": functionid})
    ROUND = ROUND.json()

    model = requests.get(endpoint+"/getModel", headers={"Host": functionid})
    model = model.json()

    size_outer = len(model)
    size_inner = len(model[0])

    time.sleep(2)

    newmodel = [[random.randint(0, 100) / 100 for i in range(size_inner)] for j in range(size_outer)]
    res = requests.get(endpoint+"/clientUpload", headers={"Host": functionid, "data": json.dumps({
        "model": newmodel,
        "round": ROUND,
    })})

    return res.json()

def main():
    fid = sys.argv[1]
    master = sys.argv[2]
    masterport = sys.argv[3]
    ok = False
    while not ok:
        start = time.perf_counter()
        ok = singleClient(fid, "http://{}:{}".format(master, masterport))
        stop = time.perf_counter()
        print(ok, stop - start)

if __name__ == "__main__":
    main()
