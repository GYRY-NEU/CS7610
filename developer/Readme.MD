# Developer

- Each .py file represents a different developer running their own Federated Learning Algorithm.
- A Developer specificies its models executation.
- Developer files are follows belows standard.

## Standard

- developer file must have model object. (2D array) (shape : n * m)
- developer file must have roundNumber, single integer
- developer file must have learning rate alpha, a float in range 0-1
- developer file must have updateModel function
- developer file must have getModel function

###  Model Object

- consist of two 2D float arr.
- i.e : model = [[212.2, 21.21 , 321.21] ,[3.2, 2.22 , 1.21],[0.2, 2.21 , 2.21],[2.2, 4.21 , 1.21]]


### Round Number 

- single integer
- i.e : roundNumber  = 1

### updateModel Function
- should take list of weights as input
- should update model
- should increment roundNumber by 1
- void function does not return anything

### learningRate alpha
- a float between 0 and 1
- ie, alpha = 0.2
### getModel
- simple returns model


```
python
# Full Example ...
# developer_1.py
model = [[212.2, 21.21 , 321.21] ,[3.2, 2.22 , 1.21],[0.2, 2.21 , 2.21],[2.2, 4.21 , 1.21]]
round_number =0
alpha = 0.2
def updateModel(list_weights):

    """ 
        list_weights : 3D list of shape : (clientNumber,modelOuter, modelInner)
        It contains all the models for each client
    """

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
    assert(len(newModel[0] == size_inner))

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
            model[outerIndex][innerIndex] += 0.2 * newModel[outerIndex][innerIndex]

    # Finally update round number
    round_number +=1

def getModel():
    return model

```