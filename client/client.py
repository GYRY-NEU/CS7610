from numpy.lib.shape_base import dsplit
import requests
import random
import sys
from multiprocessing import Pool
import time

def singleClient(endPoint):
    
    model = requests.get(endPoint)
    
    model = model.json()
    size_outer = len(model)
    size_inner = len(model[0])

    time.sleep(2)
    return [[random.randint(0,100) / 100 for i in range(size_inner)] for j in range(size_outer)]


def main():
    endPoint = sys.argv[1]
    with Pool(processes=4) as pool: 

        while True:
            print(pool.map(singleClient,[endPoint]*4))

if __name__ == "__main__":
    main()
