import math

import numpy as np
import pandas as pd
from transformers import AutoTokenizer


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
def tokenlenstatcsv(path1,tokenizer_name):
    model_name = path1.split("/")[2]
    model_name = model_name.split("_")[0]
    df = pd.read_csv(path1)
    s = df["source"]
    from transformers import RobertaTokenizer
    tokenizer = RobertaTokenizer.from_pretrained(tokenizer_name)
    # tokenizer.add_tokens(["<S2SV_StartBug>", "<S2SV_EndBug>", "<S2SV_blank>", "<S2SV_ModStart>", "<S2SV_ModEnd>"])
    source = []
    match = []
    tokenlen = []
    for i in range(len(s)):
        source.append(s[i])
        tokenlen.append(len(tokenizer.encode(s[i])))
    print(np.mean((tokenlen)))

def tokenlenstatGPT(output_path,target_path,tokenizername,model_name):
    tokenizer = AutoTokenizer.from_pretrained(tokenizername, do_lower_case=False, \
                                  bos_token='<s>', eos_token='</s>', pad_token='<pad>', unk_token='<|UNKNOWN|>',
                                  sep_token='concode_elem_sep')
    output = open(output_path,'r',encoding='utf-8').readlines()
    target = open(target_path,'r',encoding='utf-8').readlines()
    output = [x.split('\t')[1] for x in output]
    target = [x.split('\t')[1] for x in target]
    source = []
    match = []
    tokenlen = []
    for o,t in zip(output,target):
        source.append(o)
        match.append(1 if o==t else 0)
        tokenlen.append(len(tokenizer.encode(o)))
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
    df2["idx"] = idx
    df2["match"] = m_all
    df2["all"] = len_all
    accu = []
    for i in range(6):
        accu.append(m_all[i] / len_all[i])
    df2["accuracy"] = accu
    df2.to_csv("./Original/{}_stat4.csv".format(model_name))
if __name__ =="__main__":
    # tokenlenstat("./Original/CodeBERT_ori.txt","microsoft/codebert-base")
    # tokenlenstat("./Original/CodeT5_ori.txt", "Salesforce/codet5-base")
    # tokenlenstat("./Original/GraphCodeBERT_ori.txt", "microsoft/graphcodebert-base")
    # tokenlenstat("./Original/UniXcoder_ori.txt", "microsoft/unixcoder-base")
    # tokenlenstatcsv("./Original/dl_whole.csv", "microsoft/codebert-base")
    tokenlenstatGPT("./Original/CodeGPT/test_-1.output","./Original/CodeGPT/test_-1.gold","microsoft/CodeGPT-small-java-adaptedGPT2","CodeGPT")
    tokenlenstatGPT("./Original/CodeGen/test_-1.output", "./Original/CodeGen/test_-1.gold",
                    "Salesforce/codegen-350M-multi", "CodeGen")