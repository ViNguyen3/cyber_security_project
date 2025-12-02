import ipaddress

import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import warnings
import glob

from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn import metrics

warnings.filterwarnings("ignore")


pathPattern = r"C:\Users\jikem\PycharmMiscProject\TrafficLabelling\*.pcap_ISCX.csv"
fileList = glob.glob(pathPattern)

dataFrame = pd.concat([pd.read_csv(file, encoding='cp1252') for file in fileList], ignore_index=True)
dataFrame.columns = dataFrame.columns.str.strip()
dataFrame.columns = dataFrame.columns.str.upper()

#missing_counts = dataFrame.isnull().sum()
#print("Missing value counts per column:")
#print(missing_counts[missing_counts > 0])      #debug code to find that we have entirely missing rows

dataFrame = dataFrame.dropna(how='all',axis=0)
dataFrame = dataFrame.reset_index(drop=True)
#print(dataFrame.info())   #check the columns are aligned correctly

dataFrame = dataFrame.drop('FLOW ID', axis=1)
X = dataFrame.drop('LABEL', axis=1)
Y, uniqueLabels = pd.factorize(dataFrame['LABEL'])
#print(uniqueLabels)    #check we got the correct labels out
#print(f"Y shape: {Y.shape}")
#print(f"X shape: {X.shape}")    #check we have the right shapes


ipColumns = ['SOURCE IP','DESTINATION IP']
for ipCol in ipColumns:
    new_octects = X[ipCol].str.split('.',expand=True).astype(int)
    new_octects.columns = [f'{ipCol} {i}' for i in range(4)]
    X=pd.concat([X, new_octects], axis=1)

X = X.drop(ipColumns, axis=1)

timestampCol = 'TIMESTAMP'
X[timestampCol] = pd.to_datetime(X[timestampCol])
X['DAY']=X[timestampCol].dt.day
X['DAY OF WEEK']=X[timestampCol].dt.dayofweek
X['MONTH']=X[timestampCol].dt.month
X['YEAR']=X[timestampCol].dt.year
X['MINUTE']=X[timestampCol].dt.minute
X['HOUR']=X[timestampCol].dt.hour
X = X.drop(timestampCol, axis=1)



numClasses = len(uniqueLabels)

XNumPy = X.to_numpy()
XNumPy[np.isinf(XNumPy)] =np.nan    #replaces inf with nans
XNumPy = np.nan_to_num(XNumPy, nan=0)   #replaces nans with 0s
#print(f"X Object Type:{type(XNumPy)}")
#print(f"X Shape:{XNumPy.shape}")
#print(f"Y Object Type: {type(Y)}")
#print(f"Y Shape: {Y.shape}")


XTrain, XTest, YTrain, YTest = train_test_split(XNumPy, Y, test_size=0.2, random_state=42, stratify=Y)

print("--- Data Split Complete ---")
print(f"XTrain shape: {XTrain.shape}")
print(f"XTest shape: {XTest.shape}")
print(f"YTrain shape: {YTrain.shape}")
print(f"YTest shape: {YTest.shape}")


model = XGBClassifier(
    objective='multi:softmax',
    num_class=numClasses,
    eval_metric='mlogloss',
    random_state=42,
    n_estimators=100,
    learning_rate=0.1,
)

#print("Xtrain nans:",np.isnan(XTrain).sum())
#print("YTrain nans:",np.isnan(YTrain).sum())
#print("XTest nans:",np.isnan(XTest).sum())
#print("YTest nans:",np.isnan(YTest).sum())
#see where the nans are popping up. it's just in the X values thankfully








evalSet = [(XTest, YTest)]

model.fit(XTrain, YTrain, eval_set=evalSet, early_stopping_rounds=5, verbose=True)     #True for debugging, false for clean
YPred = model.predict(XTest)
print("Evaluation metrics")
accuracy=accuracy_score(YTest, YPred)
print("Accuracy:", accuracy)

print("Classification Report:")
print(metrics.classification_report(YTest, YPred))
print("Confusion matrix:")
print(metrics.confusion_matrix(YTest, YPred))

report_dictionary = metrics.classification_report(YTest, YPred, output_dict=True)
metricsDataFrame = pd.DataFrame(report_dictionary).transpose()

metricsDataFrame.loc['overall accuracy'] = pd.Series({'precision':accuracy,'recall':accuracy,'f1-score':accuracy})
metricsDataFrame.to_csv('metrics.csv',index=True)

modelFilename = "XGBoost_classifier.json"
joblib.dump(model, modelFilename)