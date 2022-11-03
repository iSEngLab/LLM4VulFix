import math

import pandas as pd
def tokenlenstat(path1,tokenizer_name):
    model_name = path1.split("/")[2]
    model_name = model_name.split("_")[0]
    f = open(path1,'r',encoding="utf-8")
    preds = f.read().splitlines()
    from transformers import RobertaTokenizer
    tokenizer = RobertaTokenizer.from_pretrained(tokenizer_name)
    tokenizer.add_tokens(["<S2SV_StartBug>", "<S2SV_EndBug>", "<S2SV_blank>", "<S2SV_ModStart>", "<S2SV_ModEnd>"])
    source = []
    match = []
    tokenlen = []
    for i in range(len(preds)):
        if preds[i]=="match:":
            match.append(int(preds[i+1]))
        if preds[i] == "source:":
            source.append(preds[i+1])
            tokenlen.append(len(tokenizer.encode(preds[i+1])))
    m_all = []
    len_all = []
    idx = []
    for i in range(5):
        idx.append("{}-{}".format(100*i,100*(i+1)))
    idx.append(">500")
    for i in range(6):
        m_all.append(0)
        len_all.append(0)
    for m,t,s in zip(match,tokenlen,source):
        if t>500:
            len_all[5]+=1
            if m ==1:
                m_all[5]+=1
        else:
            to_go = math.floor(t/100)
            len_all[to_go] += 1
            if m == 1:
                m_all[to_go] += 1
    df = pd.DataFrame()
    df["source"] = source
    df["match"] = match
    df["tokenlen"] = tokenlen
    df.to_csv("./Original/{}_stat.csv".format(model_name))
    df2 = pd.DataFrame()
    df2["idx"]=idx
    df2["match"]=m_all
    df2["all"] = len_all
    accu = []
    for i in range(6):
        accu.append(m_all[i]/len_all[i])
    df2["accuracy"] = accu
    df2.to_csv("./Original/{}_stat4.csv".format(model_name))

if __name__ =="__main__":
    tokenlenstat("./Original/CodeBERT_ori.txt","microsoft/codebert-base")
    tokenlenstat("./Original/CodeT5_ori.txt", "Salesforce/codet5-base")
    tokenlenstat("./Original/GraphCodeBERT_ori.txt", "microsoft/graphcodebert-base")
    tokenlenstat("./Original/UniXcoder_ori.txt", "microsoft/unixcoder-base")