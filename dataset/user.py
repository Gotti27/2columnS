from sklearn import svm
import pandas
import joblib

model = joblib.load('svm_model.pkl')

test = [[59,13,2.1666666666666665,1,12,715.6271186440678,4.538461538461538]]

pred = model.predict(test)

print(pred)

