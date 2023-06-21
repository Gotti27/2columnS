from sklearn import svm
import pandas
import joblib

model = svm.OneClassSVM(nu=0.01, kernel='rbf', gamma=0.1)

train = list(pandas.read_csv('processed_dataset.csv').values) 

model.fit(train)

joblib.dump(model, 'svm_model.pkl')

