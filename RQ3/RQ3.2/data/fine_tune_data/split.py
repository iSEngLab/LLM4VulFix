import json
import random

import pandas as pd
def shuffle():
    for types in ['train', 'val']:
        df = pd.read_csv(f'cve_fixes_{types}.csv')
        json_obj = json.loads(df.to_json())
        datas = list(zip(
            json_obj['source'].values(),
            json_obj['target'].values(),
        ))
        print(f'{types} length before: {len(datas)}')
        random.Random(1901).shuffle(datas)
        df_data = pd.DataFrame(list(datas))
        df_data.columns = ['source', 'target']
        df_data.to_csv(f'cve_fixes_{types}_shuffle.csv')

def split(splitfactor,type):
    df = pd.read_csv("cve_fixes_{}_shuffle.csv".format(type))
    source = df["source"].tolist()
    target = df["target"].tolist()
    source = source[:int(len(source)*splitfactor)]
    target = target[:int(len(target)*splitfactor)]
    df = pd.DataFrame()
    df["source"] = source
    df["target"] = target
    df.to_csv("cve_fixes_{}_{}.csv".format(type,splitfactor))
if __name__ =="__main__":
    # shuffle()
    splits = [0.2,0.4,0.6,0.8]
    for i in splits:
        split(i, "val")
        split(i, "train")