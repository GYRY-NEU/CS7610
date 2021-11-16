# files check correctness of developer_1.py
# single taking average sum, and weighted average is error prune
# compare the results with external libray this file does not produce a assert so implementation is correct
import developer_1
import numpy as np

assert(developer_1.ROUND == 0)
assert(developer_1.model == [[212.2, 21.21 , 321.21] ,[3.2, 2.22 , 1.21],[0.2, 2.21 , 2.21],[2.2, 4.21 , 1.21]])
assert(developer_1.model == developer_1.getModel())
assert(developer_1.alpha == 0.2)

developer_1.updateModel([[[212.2, 21.21 , 321.21] ,[3.2, 2.22 , 1.21],[0.2, 2.21 , 2.21],[2.2, 4.21 , 1.21]],[[212.2, 21.21 , 321.21] ,[3.2, 2.22 , 1.21],[0.2, 2.21 , 2.21],[2.2, 4.21 , 1.21]],[[212.2, 21.21 , 321.21] ,[3.2, 2.22 , 1.21],[0.2, 2.21 , 2.21],[2.2, 4.21 , 1.21]]])
assert(developer_1.ROUND == 1)
assert(np.allclose(np.array(developer_1.model) ,np.array( [[212.2, 21.21 , 321.21] ,[3.2, 2.22 , 1.21],[0.2, 2.21 , 2.21],[2.2, 4.21 , 1.21]])))
prevModel = developer_1.getModel()
prevModel = np.array(prevModel)
newWeights = [[[1, 1 , 1] ,[2, 2 , 2],[3, 3 , 3],[4, 4 , 4]],[[212.2, 21.21 , 321.21] ,[3.2, 2.22 , 1.21],[0.2, 2.21 , 2.21],[2.2, 4.21 , 1.21]],[[212.2, 21.21 , 321.21] ,[3.2, 2.22 , 1.21],[0.2, 2.21 , 2.21],[2.2, 4.21 , 1.21]]]
developer_1.updateModel(newWeights)
assert(developer_1.ROUND == 2)
assert(np.allclose(np.array(developer_1.model),  prevModel * (1- developer_1.alpha)  + np.mean(np.array(newWeights),axis=0) * developer_1.alpha ))
print("Success!..")