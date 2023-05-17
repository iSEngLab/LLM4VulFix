import pandas as pd
from numpy import *
def cwesta(path):
    f = open(path,'r',encoding="utf-8")
    res = {}
    cwe = []
    match = []
    preds = f.read().splitlines()
    for i in range(len(preds)):
        if preds[i] == "source:":
            cwe_tem =preds[i+1].split()[0]
            cwe.append(cwe_tem)
        if preds[i] == "match:":
            if preds[i+1] =="0" or preds[i+1] == "1":
                match.append(int(preds[i + 1]))
            else:
                if preds[i+1] == "False":
                    match.append(0)
                else:
                    match.append(1)
    cwe_id = []
    success = []
    all = []
    rate = []
    for c, p in zip(cwe, match):
        if c in res:
            if p == 1:
                res['{}'.format(c)][0] += 1
            res['{}'.format(c)][1] += 1
        else:
            res['{}'.format(c)] = [0, 1]
            if p == 1:
                res['{}'.format(c)][0] += 1
    for i in res:
        cwe_id.append(i)
        success.append(res[i][0])
        all.append(res[i][1])
        rate.append(res[i][0] / res[i][1])
    df = pd.DataFrame()
    df['cwe_id'] = cwe_id
    df['correctly_predicted'] = success
    df['all'] = all
    df['accuracy'] = rate
    df.to_csv("stat_{}.csv".format(path.split("/")[1]))
def cwestatwhole():
    res = {}
    df1 = pd.read_csv("cve_fixes_train.csv")
    df2 = pd.read_csv("cve_fixes_val.csv")
    df3 = pd.read_csv("cve_fixes_test.csv")
    cwe_train = []
    cwe_val = []
    for i in df1["source"]:
        cwe_train.append(i.split()[0])
    for i in df2["source"]:
        cwe_val.append(i.split()[0])
    df1["cwe_id"] = cwe_train
    df2["cwe_id"] = cwe_val
    df = pd.DataFrame()
    df = df1.append(df2)
    df = df.append(df3)
    cwe = df["cwe_id"]
    for i in cwe:
        if i not in res.keys():
            res[i] = 1
        else:
            res[i] +=1
    cwes = list(res.keys())
    nums = list(res.values())
    df = pd.DataFrame()
    df["cwe_id"] = cwes
    df["nums"] = nums
    df.to_csv("stat_whole.csv")
def cwestat(type):
    res = {}
    df1 = pd.read_csv("cve_fixes_{}.csv".format(type))
    cwe_train = []
    for i in df1["source"]:
        cwe_train.append(i.split()[0])
    df1["cwe_id"] = cwe_train
    cwe = df1["cwe_id"]
    for i in cwe:
        if i not in res.keys():
            res[i] = 1
        else:
            res[i] +=1
    cwes = list(res.keys())
    nums = list(res.values())
    df = pd.DataFrame()
    df["cwe_id"] = cwes
    df["nums"] = nums
    df.to_csv("stat_{}.csv".format(type))
def cwelenstat():
    res = {}
    df = pd.read_csv("cve_fixes_whole.csv")
    cwe = df["cwe_id"]
    source = df["source"]
    from transformers import RobertaTokenizer
    tokenizer = RobertaTokenizer.from_pretrained("Salesforce/codet5-base")
    tokenizer.add_tokens(["<S2SV_StartBug>", "<S2SV_EndBug>", "<S2SV_blank>", "<S2SV_ModStart>", "<S2SV_ModEnd>"])
    tokenlen = []
    for s in source:
        tokenlen.append(len(tokenizer.encode(s)))
    for c,l in zip(cwe,tokenlen):
        if c not in res.keys():
            res[c]=[]
        res[c].append(l)
    for c in res.keys():
        res[c]=mean(res[c])
    df = pd.DataFrame()
    df["cwe"]=res.keys()
    df["average_len"] = res.values()
    df.to_csv("cwe_token_len_stat.csv")
if __name__=="__main__":
    # cwesta("ori/CodeBERT/CodeBERT_ori.txt")
    # cwesta("ori/CodeT5/CodeT5_ori.txt")
    # cwesta("ori/GraphCodeBERT/GraphCodeBERT_ori.txt")
    # cwesta("ori/UniXcoder/UniXcoder_ori.txt")
    # cwestat("train")
    # cwestat("val")
    # cwestat("test")
    # cwelenstat()
    cwesta("ori/CodeGPT/CodeGPT_ori.txt")

