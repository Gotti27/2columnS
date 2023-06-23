from sklearn import linear_model
import pandas
import joblib

model = linear_model.SGDOneClassSVM(nu=0.1,verbose=1 )

train = list(pandas.read_csv('processed_dataset.csv').values) 

model.fit(train)

joblib.dump(model, 'svm_model.pkl')

