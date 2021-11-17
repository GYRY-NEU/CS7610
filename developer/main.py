
import storage

def init():
    model = [[2.2, 1.21, 1.21],
             [3.2, 2.22, 1.21],
             [0.2, 2.21, 2.21],
             [2.2, 4.21, 1.21]]
    storage.put("model", model)
    ROUND = 0
    storage.put("ROUND", ROUND)
    alpha = 0.2
    storage.put("alpha", alpha)

def updateModel(list_weights):

    """
        list_weights : 3D list of shape : (clientNumber,modelOuter, modelInner)
        It contains all the models for each client
    """

    model = storage.get("model")
    ROUND = storage.get("ROUND")
    alpha = storage.get("alpha")

    # this part will change developer to developer
    # one can just take avg
    # or one can discard smallest and largest than take average
    # this example just takes avg without use of external library


    # getting shape of 3D array
    number_clients = len(list_weights)
    size_outer = len(list_weights[0])
    size_inner = len(list_weights[0][0])

    # constructing a new 2D array of zeros of same size
    newModel = [ [0 for j in range(size_inner)] for i in range(size_outer)]

    # validate new created shape
    assert(len(newModel) == size_outer)
    assert(len(newModel[0]) == size_inner)

    # sum for all the clients
    for weights in list_weights:
        for outerIndex, outerList in enumerate(weights):
            for innerIndex, innerVal in enumerate(outerList):
                newModel[outerIndex][innerIndex] += innerVal

    # average it by number of clients
    for outerIndex, outerList in enumerate(newModel):
        for innerIndex, innerVal in enumerate(outerList):
            newModel[outerIndex][innerIndex] /= number_clients

    # now update the model using the learning rate using below formula
    # model = (1-a) * model  + a * new_model
    # Prev. part and next part could be merged for efficiency but readability they implemented with two loops

    # Iterate over model

    for outerIndex, outerList in enumerate(newModel):
        for innerIndex, innerVal in enumerate(outerList):
            model[outerIndex][innerIndex] *= 1-alpha
            model[outerIndex][innerIndex] += alpha * newModel[outerIndex][innerIndex]
    # Finally update round number

    ROUND += 1

    storage.put("model", model)
    storage.put("ROUND", ROUND)
    storage.put("alpha", alpha)

def getModel():
    return storage.get("model")

def main(argv):
    import json
    v = json.loads(argv)

    init()
    print(v)
    ROUND = storage.get("ROUND")
    ROUND += 1
    storage.put("ROUND", ROUND)
    #updateModel(v["data"])
