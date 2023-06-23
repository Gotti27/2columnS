from sklearn import linear_model
import pandas
import joblib

model = linear_model.SGDOneClassSVM(nu=0.01,verbose=1) #,  kernel='rbf', gamma=0.1 )

train = list(pandas.read_csv('processed_dataset.csv').values) 

# train = list(filter(lambda p: p[0] < 3000, train))
print(max(list(map(lambda p: p[0], train))))
model.fit(train)

joblib.dump(model, 'svm_model.pkl')

