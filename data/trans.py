import math
import os
import random
import re
import subprocess
import time
from tqdm import tqdm
import numpy as np
import pandas as pd
from tqdm.contrib import tzip
def command(cmd, timeout=30):
    """执行命令cmd，返回命令输出的内容。
    如果超时将会抛出TimeoutError异常。
    cmd - 要执行的命令
    timeout - 最长等待时间，单位：秒
    """
    p = subprocess.Popen(cmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
    t_beginning = time.time()
    seconds_passed = 0
    while True:
        if p.poll() is not None:
            break
        seconds_passed = time.time() - t_beginning
        if timeout and seconds_passed > timeout:
            p.terminate()
            raise TimeoutError(cmd, timeout)
    return p.stdout.read()
def findabsstr(str,start_token,end_token):
    tofind = str.split()
    res_idx =[]
    for idx in range(len(tofind)):
        if tofind[idx]==start_token:
            res_idx.append([idx,start_token])
    for idx in range(len(tofind)):
        if tofind[idx]==end_token:
            res_idx.append([idx,end_token])
    return sorted(res_idx, key=lambda x:x[0])
def modDetect(t_to_do):
    to_do = t_to_do.split()
    res = []
    split_res = findabsstr(t_to_do,"<S2SV_ModStart>","<S2SV_ModEnd>")
    i=0
    while True:
        if split_res[i][1]=="<S2SV_ModStart>" and i+1==len(split_res) :
            type ="add"
            context1 = " ".join(to_do[split_res[i][0]+1:split_res[i][0]+4])
            new = " ".join(to_do[split_res[i][0]+4:])
            context2 = ""
            res.append([type,context1,new,context2,len(new.split())])
            i+=1
        elif split_res[i][1]=="<S2SV_ModStart>" and split_res[i+1][1]=="<S2SV_ModStart>":
            type ="add"
            context1 = " ".join(to_do[split_res[i][0]+1:split_res[i][0]+4])
            new = " ".join(to_do[split_res[i][0]+4:split_res[i+1][0]])
            context2 = ""
            res.append([type,context1,new,context2,len(new.split())])
            i+=1
        elif split_res[i][1]=="<S2SV_ModStart>" and split_res[i+1][1]=="<S2SV_ModEnd>":
            if split_res[i+1][0]-split_res[i][0]==4:
                type="delete"
                context1 = " ".join(to_do[split_res[i][0] + 1:split_res[i][0] + 4])
                new = ""
                context2 = " ".join(to_do[split_res[i+1][0] + 1:split_res[i+1][0] + 4])
                res.append([type, context1, new, context2,len(new.split())])
            elif split_res[i+1][0]-split_res[i][0]!=4:
                type="replace"
                context1 = " ".join(to_do[split_res[i][0] + 1:split_res[i][0] + 4])
                new = " ".join(to_do[split_res[i][0] + 4:split_res[i+1][0]])
                context2 = " ".join(to_do[split_res[i+1][0] + 1:split_res[i+1][0] + 4])
                res.append([type, context1, new, context2,len(new.split())])
            i+=2
        if i >len(split_res)-1:
            break
    return res
def noctx(type):
    df = pd.read_csv("cve_fixes_{}.csv".format(type), encoding='utf-8')
    source = np.array(df["source"])
    target = np.array(df["target"])
    res_source = []
    res_target = []
    for s in source:
        s_to_do = s.strip()
        split_res_s = findabsstr(s_to_do, "<S2SV_StartBug>", "<S2SV_EndBug>")
        s_to_do = s_to_do.split()
        tem_source = ""
        if len(split_res_s)==0:
            tem_source = "\n"
        for i in range(0, len(split_res_s), 2):
            tem_source += "<S2SV_StartBug> " + " ".join(
                s_to_do[split_res_s[i][0] + 1:split_res_s[i + 1][0]]) + " <S2SV_EndBug> "
        res_source.append(tem_source)
    for t in target:
        t_to_do = t.strip()
        if t_to_do=="":
            res_target.append("\n")
            continue
        mods = modDetect(t_to_do)
        tem_target = ""
        for mod in mods:
            if mod[0] == "add":
                tem_target += "<S2SV_ModStart> " + mod[2] + " "
            if mod[0] == "delete":
                tem_target += "<S2SV_ModStart> " + mod[2] + " <S2SV_ModEnd> "
            if mod[0] == "replace":
                tem_target += "<S2SV_ModStart> " + mod[2] + " <S2SV_ModEnd> "
        res_target.append(tem_target)
    res_source = pd.DataFrame(res_source)
    res_target = pd.DataFrame(res_target)
    df["source"] = res_source
    df["target"] = res_target
    df.to_csv("cve_fixes_{}_no_ctx.csv".format(type), encoding='utf-8')
def filterdata4abs(type):
    df = pd.read_csv("cve_fixes_{}.csv".format(type), encoding='utf-8')
    source = np.array(df["source"])
    target = np.array(df["target"])
    count_s =0
    count_t =0
    wrong=[]
    idx =0
    res_source = []
    res_target = []
    for s,t in zip(source,target):
        if "#" in s :
            s=s.replace("#","")
            s=s.replace("endif","")
            s=s.replace("define", "")
            s=s.replace("undef", "")
            s=s.replace("elif", "else if")
            res_source.append(s)
            count_s+=1
        else:
            res_source.append(s)
        if "#" in t :
            wrong.append(idx)
            res_target.append(t)
            count_t+=1
        else:
            res_target.append(t)
        idx +=1

    print(count_s)
    print(count_t)
    df["source"]=pd.DataFrame(res_source)
    df["target"]=pd.DataFrame(res_target)
    df=df.drop(wrong)
    df.to_csv("cve_fixes_{}_filtered.csv".format(type), encoding='utf-8')
def delNull(context):
    s_c = context.split()
    count = 0
    while "<S2SV_null>" in s_c:
        s_c.remove("<S2SV_null>")
        count+=1
    return " ".join(s_c),count
def generateMap(map):
    lines = map.read().splitlines()
    mapper = {}
    for i in range(1,15,4):
        ori = lines[i].strip().split()
        abs = lines[i+1].strip().split()
        for o,a in zip(ori,abs):
            mapper[o]=a
    return mapper
def updateSplit(split_res,idx,leng):
    to_alt = 0
    for i in range(len(split_res)):
        if split_res[i][0]>idx:
            to_alt=i
            break
    for i in range(to_alt,len(split_res)):
        split_res[i][0]+=leng
    return split_res
def getAbsbyReplace(type):
    df = pd.read_csv("./cve_fixes_{}_filtered.csv".format(type), encoding='utf-8')
    source = np.array(df["source"]).tolist()
    target = np.array(df["target"]).tolist()
    res_source = []
    res_target = []
    res_ori_source = []
    res_ori_target = []
    idx = 0
    for s,t in tzip(source,target):
        s=s.strip()
        t=t.strip()
        if s=="" or t=="":
            continue
        res_ori_source.append(s)
        res_ori_target.append(t)
        #处理source
        cwe_id = s.split()[0]
        #去除CWE_ID
        s_to_do = " ".join(s.split()[1:])
        #去掉tag并记录tag位置
        split_res_s = findabsstr(s_to_do, "<S2SV_StartBug>", "<S2SV_EndBug>")
        s_to_do = s_to_do.replace("<S2SV_StartBug>", "")
        s_to_do = s_to_do.replace("<S2SV_EndBug>", "")
        s_removed = s_to_do
        #写文件
        f = open("{}_abs/source_input{}.c".format(type, idx), 'w', encoding='utf-8')
        f.write(s_removed)
        f.flush()
        f.close()
        #处理target
        t_to_do = t
        mods = modDetect(t_to_do)
        t_source = s_removed
        split_res_t = split_res_s
        t_source = t_source.split()
        mod_idx = []
        last_ctx1 = 0
        last_ctx2 = 0
        #还原修改
        for mod in mods:
            m_type = mod[0]
            context1 = mod[1]
            new = mod[2]
            context2 = mod[3]
            if m_type == "add":
                if "<S2SV_null>" in context1:
                    start_idx_ctx1 = 0
                    context1, count = delNull(context1)
                    start_idx_new = 3 - count
                    tem_idx = start_idx_new
                    tokens = new.split()
                    for t in tokens:
                        t_source.insert(tem_idx, t)
                        tem_idx += 1
                    mod_idx.append(["add", start_idx_ctx1, 3 - count, start_idx_new, len(tokens), 0, 0])
                    split_res_t=updateSplit(split_res_t,start_idx_new,len(tokens))
                else:
                    start_idx_ctx1 = 0
                    is_find = False
                    for i in range(last_ctx1, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context1:
                            start_idx_ctx1 = i
                            last_ctx1 = i + 3
                            is_find = True
                            break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    start_idx_new = start_idx_ctx1 + 3
                    tem_idx = start_idx_new
                    tokens = new.split()
                    for t in tokens:
                        t_source.insert(tem_idx, t)
                        tem_idx += 1
                    mod_idx.append(["add", start_idx_ctx1, 3, start_idx_new, len(tokens), 0, 0])
                    split_res_t = updateSplit(split_res_t, start_idx_new, len(tokens))
            elif m_type == "delete":
                if "<S2SV_null>" in context1:
                    start_idx_ctx1 = 0
                    context1, count = delNull(context1)
                    start_idx_ctx2 = 0
                    is_find = False
                    for i in range(last_ctx2, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context2:
                            if i > start_idx_ctx1:
                                start_idx_ctx2 = i
                                last_ctx2 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - start_idx_ctx1 - 3 + count
                    tem_idx = start_idx_ctx1 + 3 - count
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    mod_idx.append(["delete", start_idx_ctx1, 3 - count, 0, 0, start_idx_ctx2, 3])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3 - count, -origin_len)
                elif "<S2SV_null>" in context2:
                    start_idx_ctx1 = 0
                    context2, count = delNull(context2)
                    start_idx_ctx2 = len(t_source) - (3 - count)
                    is_find = False
                    for i in range(last_ctx1, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context1:
                            if i < start_idx_ctx2:
                                start_idx_ctx1 = i
                                last_ctx1 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - start_idx_ctx1 - 3
                    tem_idx = start_idx_ctx1 + 3
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    mod_idx.append(["delete", start_idx_ctx1, 3, 0, 0, start_idx_ctx2, 3 - count])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3, -origin_len)
                else:
                    start_idx_ctx1 = 0
                    start_idx_ctx2 = 0
                    is_find = False
                    for i in range(last_ctx2, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context1:
                            start_idx_ctx1 = i
                            last_ctx1 = i + 3
                            is_find = True
                            break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    is_find = False
                    for i in range(last_ctx1, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context2:
                            if i > start_idx_ctx1:
                                start_idx_ctx2 = i
                                last_ctx2 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - start_idx_ctx1 - 3
                    tem_idx = start_idx_ctx1 + 3
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    mod_idx.append(["delete", start_idx_ctx1, 3, 0, 0, start_idx_ctx2, 3])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3, -origin_len)
            elif m_type == "replace":
                if "<S2SV_null>" in context1:
                    start_idx_ctx1 = 0
                    context1, count = delNull(context1)
                    start_idx_ctx2 = 0
                    is_find = False
                    for i in range(last_ctx2, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context2:
                            if i > start_idx_ctx1:
                                start_idx_ctx2 = i
                                last_ctx2 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - start_idx_ctx1 - 3 + count
                    tem_idx = start_idx_ctx1 + 3 - count
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    start_idx_new = start_idx_ctx1 + 3 - count
                    tokens = new.split()
                    tem_idx = start_idx_new
                    for t in tokens:
                        t_source.insert(tem_idx, t)
                        tem_idx += 1
                        start_idx_ctx2 += 1
                    mod_idx.append(["replace", start_idx_ctx1, 3 - count, start_idx_new, len(tokens), start_idx_ctx2, 3])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3 - count, len(tokens)-origin_len)
                elif "<S2SV_null>" in context2:
                    start_idx_ctx1 = 0
                    context2, count = delNull(context2)
                    start_idx_ctx2 = len(t_source) - (3 - count)
                    is_find = False
                    for i in range(last_ctx1, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context1:
                            if i < start_idx_ctx2:
                                start_idx_ctx1 = i
                                last_ctx1 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - start_idx_ctx1 - 3
                    tem_idx = start_idx_ctx1 + 3
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    start_idx_new = start_idx_ctx1 + 3
                    tokens = new.split()
                    tem_idx = start_idx_new
                    for t in tokens:
                        t_source.insert(tem_idx, t)
                        tem_idx += 1
                        start_idx_ctx2 += 1
                    mod_idx.append(
                        ["replace", start_idx_ctx1, 3, start_idx_new, len(tokens), start_idx_ctx2, 3 - count])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3, len(tokens) - origin_len)
                else:
                    start_idx_ctx1 = 0
                    start_idx_ctx2 = 0
                    is_find = False
                    for i in range(last_ctx2, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context1:
                            start_idx_ctx1 = i
                            last_ctx1 = i + 3
                            is_find = True
                            break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    is_find = False
                    for i in range(last_ctx1, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context2:
                            if i > start_idx_ctx1:
                                start_idx_ctx2 = i
                                last_ctx2 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - 3 - start_idx_ctx1
                    tem_idx = start_idx_ctx1 + 3
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    start_idx_new = start_idx_ctx1 + 3
                    tokens = new.split()
                    tem_idx = start_idx_new
                    for t in tokens:
                        t_source.insert(tem_idx, t)
                        tem_idx += 1
                        start_idx_ctx2 += 1
                    mod_idx.append(["replace", start_idx_ctx1, 3, start_idx_new, len(tokens), start_idx_ctx2, 3])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3, len(tokens) - origin_len)
        # 写文件
        f = open("{}_abs/target_input{}.c".format(type, idx), 'w', encoding='utf-8')
        f.write(" ".join(t_source))
        f.flush()
        f.close()
        #执行抽象化
        cmd = "java -jar cabs.jar {}_abs/source_input{}.c {}_abs/target_input{}.c {}_abs/source_output{}.c {}_abs/target_output{}.c {}_abs/map{}.map".format(
            type,
            idx, type, idx, type, idx,
            type,
            idx,
            type,
            idx)
        os.system(cmd)
        try:
            f = open("{}_abs/source_output{}.c".format(type, idx), 'r', encoding='utf-8')
        except FileNotFoundError:
            s_to_do = "<error>"
            res_source.append(s_to_do)
            res_target.append(s_to_do)
            idx += 1
            continue
        try:
            s_to_do = f.readline().strip()
        except UnicodeDecodeError:
            s_to_do = "<error>"
            res_source.append(s_to_do)
            res_target.append(s_to_do)
            idx += 1
            continue
        if "<error>" in s_to_do:
            s_to_do = "<error>"
            res_source.append(s_to_do)
            res_target.append(s_to_do)
            idx += 1
            continue
        try:
            f = open("{}_abs/target_output{}.c".format(type, idx), 'r', encoding='utf-8')
        except FileNotFoundError:
            s_to_do = "<error>"
            res_source.append(s_to_do)
            res_target.append(s_to_do)
            idx += 1
            continue
        try:
            s_to_do = f.readline().strip()
        except UnicodeDecodeError:
            s_to_do = "<error>"
            res_source.append(s_to_do)
            res_target.append(s_to_do)
            idx += 1
            continue
        if "<error>" in s_to_do:
            s_to_do = "<error>"
            res_source.append(s_to_do)
            res_target.append(s_to_do)
            idx += 1
            continue
        map =open("{}_abs/map{}.map".format(type,idx))
        mapper = generateMap(map)
        s_ori = s.split()[1:]
        newmapper ={}
        method_count = 0
        var_count = 0
        type_count = 0
        struct_count = 0
        #重新排列mapper
        for i in range(len(s_ori)):
            tem_s = s_ori[i]
            if tem_s in mapper:
                type_s = mapper[tem_s].split("_")[0]
                if type_s=="METHOD":
                    newmapper[tem_s] = "METHOD_{}".format(method_count)
                    method_count+=1
                    s_ori[i] = newmapper[tem_s]
                if type_s=="VAR":
                    newmapper[tem_s] = "VAR_{}".format(var_count)
                    var_count+=1
                    s_ori[i] = newmapper[tem_s]
                if type_s=="TYPE":
                    newmapper[tem_s] = "TYPE_{}".format(type_count)
                    type_count+=1
                    s_ori[i] = newmapper[tem_s]
                if type_s=="STRUCT":
                    newmapper[tem_s] = "STRUCT_OR_UNION_{}".format(struct_count)
                    struct_count+=1
                    s_ori[i] = newmapper[tem_s]
        for i in mapper:
            if i not in newmapper:
                type_s = mapper[i].split("_")[0]
                if type_s=="METHOD":
                    newmapper[i] = "METHOD_{}".format(method_count)
                    method_count+=1
                if type_s=="VAR":
                    newmapper[i] = "VAR_{}".format(var_count)
                    var_count+=1
                if type_s=="TYPE":
                    newmapper[i] = "TYPE_{}".format(type_count)
                    type_count+=1
                if type_s=="STRUCT":
                    newmapper[i] = "STRUCT_OR_UNION_{}".format(struct_count)
                    struct_count+=1
        res_source.append(cwe_id+" "+" ".join(s_ori))
        t_to_do =t_to_do.split()
        for i in range(len(t_to_do)):
            t = t_to_do[i]
            if t in newmapper:
                t_to_do[i] = newmapper[t]
        res_target.append(" ".join(t_to_do))
        idx +=1
    assert len(res_source)==len(res_target)
    res_source_filtered = []
    res_target_filtered = []
    res_ori_source_filtered = []
    res_ori_target_filtered = []
    for s, t, os1, or1 in zip(res_source, res_target, res_ori_source, res_ori_target):
        if not "<error>" in s and not "<error>" in t:
            res_source_filtered.append(s)
            res_target_filtered.append(t)
            res_ori_source_filtered.append(os1)
            res_ori_target_filtered.append(or1)
    df = pd.DataFrame()
    df["source"] = res_source_filtered
    df["target"] = res_target_filtered
    df["original_source"] = res_ori_source_filtered
    df["original_target"] = res_ori_target_filtered
    df.to_csv("cve_fixes_{}_absreplace.csv".format(type), encoding='utf-8')
def diff(type):
    df = pd.read_csv("cve_fixes_{}.csv".format(type), encoding='utf-8')
    source = np.array(df["source"]).tolist()
    target = np.array(df["target"]).tolist()
    res_source = []
    res_target = []
    group = []
    idx = 0
    group_idx = 0
    for s,t in tzip(source,target):
        s=s.strip()
        t=t.strip()
        if s=="" or t=="":
            continue
        #处理source
        cwe_id = s.split()[0]
        #去除CWE_ID
        s_to_do = " ".join(s.split()[1:])
        #去掉tag并记录tag位置
        split_res_s = findabsstr(s_to_do, "<S2SV_StartBug>", "<S2SV_EndBug>")
        s_to_do = s_to_do.replace("<S2SV_StartBug>", "")
        s_to_do = s_to_do.replace("<S2SV_EndBug>", "")
        s_removed = s_to_do

        s_after_abs = s_removed
        #处理target
        t_to_do = t
        mods = modDetect(t_to_do)
        t_source = s_removed
        split_res_t = split_res_s
        t_source = t_source.split()
        mod_idx = []
        last_ctx1 = 0
        last_ctx2 = 0
        #还原修改
        for mod in mods:
            m_type = mod[0]
            context1 = mod[1]
            new = mod[2]
            context2 = mod[3]
            if m_type == "add":
                if "<S2SV_null>" in context1:
                    start_idx_ctx1 = 0
                    context1, count = delNull(context1)
                    start_idx_new = 3 - count
                    tem_idx = start_idx_new
                    tokens = new.split()
                    for t in tokens:
                        t_source.insert(tem_idx, t)
                        tem_idx += 1
                    mod_idx.append(["add", start_idx_ctx1, 3 - count, start_idx_new, len(tokens), 0, 0])
                    split_res_t=updateSplit(split_res_t,start_idx_new,len(tokens))
                else:
                    start_idx_ctx1 = 0
                    is_find = False
                    for i in range(last_ctx1, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context1:
                            start_idx_ctx1 = i
                            last_ctx1 = i + 3
                            is_find = True
                            break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    start_idx_new = start_idx_ctx1 + 3
                    tem_idx = start_idx_new
                    tokens = new.split()
                    for t in tokens:
                        t_source.insert(tem_idx, t)
                        tem_idx += 1
                    mod_idx.append(["add", start_idx_ctx1, 3, start_idx_new, len(tokens), 0, 0])
                    split_res_t = updateSplit(split_res_t, start_idx_new, len(tokens))
            elif m_type == "delete":
                if "<S2SV_null>" in context1:
                    start_idx_ctx1 = 0
                    context1, count = delNull(context1)
                    start_idx_ctx2 = 0
                    is_find = False
                    for i in range(last_ctx2, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context2:
                            if i > start_idx_ctx1:
                                start_idx_ctx2 = i
                                last_ctx2 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - start_idx_ctx1 - 3 + count
                    tem_idx = start_idx_ctx1 + 3 - count
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    mod_idx.append(["delete", start_idx_ctx1, 3 - count, 0, 0, start_idx_ctx2, 3])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3 - count, -origin_len)
                elif "<S2SV_null>" in context2:
                    start_idx_ctx1 = 0
                    context2, count = delNull(context2)
                    start_idx_ctx2 = len(t_source) - (3 - count)
                    is_find = False
                    for i in range(last_ctx1, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context1:
                            if i < start_idx_ctx2:
                                start_idx_ctx1 = i
                                last_ctx1 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - start_idx_ctx1 - 3
                    tem_idx = start_idx_ctx1 + 3
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    mod_idx.append(["delete", start_idx_ctx1, 3, 0, 0, start_idx_ctx2, 3 - count])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3, -origin_len)
                else:
                    start_idx_ctx1 = 0
                    start_idx_ctx2 = 0
                    is_find = False
                    for i in range(last_ctx2, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context1:
                            start_idx_ctx1 = i
                            last_ctx1 = i + 3
                            is_find = True
                            break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    is_find = False
                    for i in range(last_ctx1, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context2:
                            if i > start_idx_ctx1:
                                start_idx_ctx2 = i
                                last_ctx2 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - start_idx_ctx1 - 3
                    tem_idx = start_idx_ctx1 + 3
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    mod_idx.append(["delete", start_idx_ctx1, 3, 0, 0, start_idx_ctx2, 3])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3, -origin_len)
            elif m_type == "replace":
                if "<S2SV_null>" in context1:
                    start_idx_ctx1 = 0
                    context1, count = delNull(context1)
                    start_idx_ctx2 = 0
                    is_find = False
                    for i in range(last_ctx2, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context2:
                            if i > start_idx_ctx1:
                                start_idx_ctx2 = i
                                last_ctx2 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - start_idx_ctx1 - 3 + count
                    tem_idx = start_idx_ctx1 + 3 - count
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    start_idx_new = start_idx_ctx1 + 3 - count
                    tokens = new.split()
                    tem_idx = start_idx_new
                    for t in tokens:
                        t_source.insert(tem_idx, t)
                        tem_idx += 1
                        start_idx_ctx2 += 1
                    mod_idx.append(["replace", start_idx_ctx1, 3 - count, start_idx_new, len(tokens), start_idx_ctx2, 3])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3 - count, len(tokens)-origin_len)
                elif "<S2SV_null>" in context2:
                    start_idx_ctx1 = 0
                    context2, count = delNull(context2)
                    start_idx_ctx2 = len(t_source) - (3 - count)
                    is_find = False
                    for i in range(last_ctx1, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context1:
                            if i < start_idx_ctx2:
                                start_idx_ctx1 = i
                                last_ctx1 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - start_idx_ctx1 - 3
                    tem_idx = start_idx_ctx1 + 3
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    start_idx_new = start_idx_ctx1 + 3
                    tokens = new.split()
                    tem_idx = start_idx_new
                    for t in tokens:
                        t_source.insert(tem_idx, t)
                        tem_idx += 1
                        start_idx_ctx2 += 1
                    mod_idx.append(
                        ["replace", start_idx_ctx1, 3, start_idx_new, len(tokens), start_idx_ctx2, 3 - count])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3, len(tokens) - origin_len)
                else:
                    start_idx_ctx1 = 0
                    start_idx_ctx2 = 0
                    is_find = False
                    for i in range(last_ctx2, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context1:
                            start_idx_ctx1 = i
                            last_ctx1 = i + 3
                            is_find = True
                            break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    is_find = False
                    for i in range(last_ctx1, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context2:
                            if i > start_idx_ctx1:
                                start_idx_ctx2 = i
                                last_ctx2 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - 3 - start_idx_ctx1
                    tem_idx = start_idx_ctx1 + 3
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    start_idx_new = start_idx_ctx1 + 3
                    tokens = new.split()
                    tem_idx = start_idx_new
                    for t in tokens:
                        t_source.insert(tem_idx, t)
                        tem_idx += 1
                        start_idx_ctx2 += 1
                    mod_idx.append(["replace", start_idx_ctx1, 3, start_idx_new, len(tokens), start_idx_ctx2, 3])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3, len(tokens) - origin_len)
        t_after_abs = " ".join(t_source)
        s_after_abs = s_after_abs.replace("{", "{\n")
        s_after_abs = s_after_abs.replace("}", "}\n")
        s_after_abs = s_after_abs.replace(";", ";\n")
        f_s = open("{}_abs/source_output_line{}.c".format(type, idx), 'w', encoding='utf-8')
        f_s.write(s_after_abs)
        f_s.close()
        t_after_abs = t_after_abs.replace("{", "{\n")
        t_after_abs = t_after_abs.replace("}", "}\n")
        t_after_abs = t_after_abs.replace(";", ";\n")
        f_t = open("{}_abs/target_output_line{}.c".format(type, idx), 'w', encoding='utf-8')
        f_t.write(t_after_abs)
        f_t.close()

        cmd = "git diff {}_abs/source_output_line{}.c {}_abs/target_output_line{}.c".format(type,
            idx, type,idx)
        try:
            res = str(command(cmd))
        except TimeoutError:
            continue
        res = res.replace("\\n","\n")
        res = res.split("\n")
        st_idx = []
        for i in range(len(res)):
            if res[i].startswith('@'):
                st_idx.append(i+1)
        for i in range(len(st_idx)):
            if i==len(st_idx)-1:
                tem_res = res[st_idx[i]:len(res)]
            else:
                tem_res = res[st_idx[i]:st_idx[i+1]]
            buggy_code = ""
            fixed_code = ""
            for line in tem_res:
                if line.startswith('-'):
                    line = line[1:]
                    line = line.strip()
                    buggy_code += line
                if line.startswith('+'):
                    line = line[1:]
                    line = line.strip()
                    fixed_code += line
            res_source.append(buggy_code)
            res_target.append(fixed_code)
            group.append(group_idx)
        idx +=1
        group_idx+=1
    assert len(res_source)==len(res_target)
    res_source_filtered = []
    res_target_filtered = []
    group_filtered = []
    for s, t, g in zip(res_source, res_target,group):
        if not g==-1:
            if s=="":
                s="\n"
            if t=="":
                t="\n"
            res_source_filtered.append(s)
            res_target_filtered.append(t)
            group_filtered.append(g)
    df = pd.DataFrame()
    df["source"] = res_source_filtered
    df["target"] = res_target_filtered
    df["group"] = group_filtered
    df.to_csv("cve_fixes_{}_diff.csv".format(type), encoding='utf-8')
def prompt(type):
    df = pd.read_csv("cve_fixes_{}.csv".format(type), encoding='utf-8')
    source = np.array(df["source"]).tolist()
    target = np.array(df["target"]).tolist()
    res_source = []
    res_target = []
    group = []
    idx = 0
    group_idx = 0
    for s,t in tzip(source,target):
        s=s.strip()
        t=t.strip()
        if s=="" or t=="":
            continue
        #处理source
        cwe_id = s.split()[0]
        #去除CWE_ID
        s_to_do = " ".join(s.split()[1:])
        #去掉tag并记录tag位置
        split_res_s = findabsstr(s_to_do, "<S2SV_StartBug>", "<S2SV_EndBug>")
        s_to_do = s_to_do.replace("<S2SV_StartBug>", "")
        s_to_do = s_to_do.replace("<S2SV_EndBug>", "")
        s_removed = s_to_do

        s_after_abs = s_removed
        #处理target
        t_to_do = t
        mods = modDetect(t_to_do)
        t_source = s_removed
        split_res_t = split_res_s
        t_source = t_source.split()
        mod_idx = []
        last_ctx1 = 0
        last_ctx2 = 0
        #还原修改
        for mod in mods:
            m_type = mod[0]
            context1 = mod[1]
            new = mod[2]
            context2 = mod[3]
            if m_type == "add":
                if "<S2SV_null>" in context1:
                    start_idx_ctx1 = 0
                    context1, count = delNull(context1)
                    start_idx_new = 3 - count
                    tem_idx = start_idx_new
                    tokens = new.split()
                    for t in tokens:
                        t_source.insert(tem_idx, t)
                        tem_idx += 1
                    mod_idx.append(["add", start_idx_ctx1, 3 - count, start_idx_new, len(tokens), 0, 0])
                    split_res_t=updateSplit(split_res_t,start_idx_new,len(tokens))
                else:
                    start_idx_ctx1 = 0
                    is_find = False
                    for i in range(last_ctx1, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context1:
                            start_idx_ctx1 = i
                            last_ctx1 = i + 3
                            is_find = True
                            break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    start_idx_new = start_idx_ctx1 + 3
                    tem_idx = start_idx_new
                    tokens = new.split()
                    for t in tokens:
                        t_source.insert(tem_idx, t)
                        tem_idx += 1
                    mod_idx.append(["add", start_idx_ctx1, 3, start_idx_new, len(tokens), 0, 0])
                    split_res_t = updateSplit(split_res_t, start_idx_new, len(tokens))
            elif m_type == "delete":
                if "<S2SV_null>" in context1:
                    start_idx_ctx1 = 0
                    context1, count = delNull(context1)
                    start_idx_ctx2 = 0
                    is_find = False
                    for i in range(last_ctx2, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context2:
                            if i > start_idx_ctx1:
                                start_idx_ctx2 = i
                                last_ctx2 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - start_idx_ctx1 - 3 + count
                    tem_idx = start_idx_ctx1 + 3 - count
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    mod_idx.append(["delete", start_idx_ctx1, 3 - count, 0, 0, start_idx_ctx2, 3])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3 - count, -origin_len)
                elif "<S2SV_null>" in context2:
                    start_idx_ctx1 = 0
                    context2, count = delNull(context2)
                    start_idx_ctx2 = len(t_source) - (3 - count)
                    is_find = False
                    for i in range(last_ctx1, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context1:
                            if i < start_idx_ctx2:
                                start_idx_ctx1 = i
                                last_ctx1 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - start_idx_ctx1 - 3
                    tem_idx = start_idx_ctx1 + 3
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    mod_idx.append(["delete", start_idx_ctx1, 3, 0, 0, start_idx_ctx2, 3 - count])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3, -origin_len)
                else:
                    start_idx_ctx1 = 0
                    start_idx_ctx2 = 0
                    is_find = False
                    for i in range(last_ctx2, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context1:
                            start_idx_ctx1 = i
                            last_ctx1 = i + 3
                            is_find = True
                            break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    is_find = False
                    for i in range(last_ctx1, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context2:
                            if i > start_idx_ctx1:
                                start_idx_ctx2 = i
                                last_ctx2 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - start_idx_ctx1 - 3
                    tem_idx = start_idx_ctx1 + 3
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    mod_idx.append(["delete", start_idx_ctx1, 3, 0, 0, start_idx_ctx2, 3])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3, -origin_len)
            elif m_type == "replace":
                if "<S2SV_null>" in context1:
                    start_idx_ctx1 = 0
                    context1, count = delNull(context1)
                    start_idx_ctx2 = 0
                    is_find = False
                    for i in range(last_ctx2, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context2:
                            if i > start_idx_ctx1:
                                start_idx_ctx2 = i
                                last_ctx2 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - start_idx_ctx1 - 3 + count
                    tem_idx = start_idx_ctx1 + 3 - count
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    start_idx_new = start_idx_ctx1 + 3 - count
                    tokens = new.split()
                    tem_idx = start_idx_new
                    for t in tokens:
                        t_source.insert(tem_idx, t)
                        tem_idx += 1
                        start_idx_ctx2 += 1
                    mod_idx.append(["replace", start_idx_ctx1, 3 - count, start_idx_new, len(tokens), start_idx_ctx2, 3])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3 - count, len(tokens)-origin_len)
                elif "<S2SV_null>" in context2:
                    start_idx_ctx1 = 0
                    context2, count = delNull(context2)
                    start_idx_ctx2 = len(t_source) - (3 - count)
                    is_find = False
                    for i in range(last_ctx1, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context1:
                            if i < start_idx_ctx2:
                                start_idx_ctx1 = i
                                last_ctx1 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - start_idx_ctx1 - 3
                    tem_idx = start_idx_ctx1 + 3
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    start_idx_new = start_idx_ctx1 + 3
                    tokens = new.split()
                    tem_idx = start_idx_new
                    for t in tokens:
                        t_source.insert(tem_idx, t)
                        tem_idx += 1
                        start_idx_ctx2 += 1
                    mod_idx.append(
                        ["replace", start_idx_ctx1, 3, start_idx_new, len(tokens), start_idx_ctx2, 3 - count])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3, len(tokens) - origin_len)
                else:
                    start_idx_ctx1 = 0
                    start_idx_ctx2 = 0
                    is_find = False
                    for i in range(last_ctx2, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context1:
                            start_idx_ctx1 = i
                            last_ctx1 = i + 3
                            is_find = True
                            break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    is_find = False
                    for i in range(last_ctx1, len(t_source) - 2):
                        if " ".join([t_source[i], t_source[i + 1], t_source[i + 2]]) == context2:
                            if i > start_idx_ctx1:
                                start_idx_ctx2 = i
                                last_ctx2 = i + 3
                                is_find = True
                                break
                    if not is_find:
                        mod_idx.append(["error"])
                        continue
                    if start_idx_ctx2 <= start_idx_ctx1:
                        mod_idx.append(["error"])
                        continue
                    origin_len = start_idx_ctx2 - 3 - start_idx_ctx1
                    tem_idx = start_idx_ctx1 + 3
                    for i in range(origin_len):
                        t_source.pop(tem_idx)
                        start_idx_ctx2 -= 1
                    start_idx_new = start_idx_ctx1 + 3
                    tokens = new.split()
                    tem_idx = start_idx_new
                    for t in tokens:
                        t_source.insert(tem_idx, t)
                        tem_idx += 1
                        start_idx_ctx2 += 1
                    mod_idx.append(["replace", start_idx_ctx1, 3, start_idx_new, len(tokens), start_idx_ctx2, 3])
                    split_res_t = updateSplit(split_res_t, start_idx_ctx1 + 3, len(tokens) - origin_len)
        t_after_abs = " ".join(t_source)
        s_after_abs = s_after_abs.replace("{", "{\n")
        s_after_abs = s_after_abs.replace("}", "}\n")
        s_after_abs = s_after_abs.replace(";", ";\n")
        f_s = open("{}_abs/source_output_line{}.c".format(type, idx), 'w', encoding='utf-8')
        f_s.write(s_after_abs)
        f_s.close()
        t_after_abs = t_after_abs.replace("{", "{\n")
        t_after_abs = t_after_abs.replace("}", "}\n")
        t_after_abs = t_after_abs.replace(";", ";\n")
        f_t = open("{}_abs/target_output_line{}.c".format(type, idx), 'w', encoding='utf-8')
        f_t.write(t_after_abs)
        f_t.close()

        cmd = "git diff {}_abs/source_output_line{}.c {}_abs/target_output_line{}.c".format(type,
            idx, type,idx)
        try:
            res = str(command(cmd))
        except TimeoutError:
            continue
        res = res.replace("\\n","\n")
        res = res.split("\n")
        st_idx = []
        for i in range(len(res)):
            if res[i].startswith('@'):
                st_idx.append(i+1)
        for i in range(len(st_idx)):
            if i==len(st_idx)-1:
                tem_res = res[st_idx[i]:len(res)]
            else:
                tem_res = res[st_idx[i]:st_idx[i+1]]
            buggy_code = ""
            fixed_code = ""
            for line in tem_res:
                if line.startswith('-'):
                    line = line[1:]
                    line = line.strip()
                    buggy_code += line
                if line.startswith('+'):
                    line = line[1:]
                    line = line.strip()
                    fixed_code += line
            tem_res = "buggy line: "+buggy_code+"cwe id:"+cwe_id+ "context: " +s_removed
            res_source.append(tem_res)
            res_target.append(fixed_code)
            group.append(group_idx)
        idx +=1
        group_idx+=1
    assert len(res_source)==len(res_target)
    res_source_filtered = []
    res_target_filtered = []
    group_filtered = []
    for s, t, g in zip(res_source, res_target,group):
        if not g==-1:
            if s=="":
                s="\n"
            if t=="":
                t="\n"
            res_source_filtered.append(s)
            res_target_filtered.append(t)
            group_filtered.append(g)
    df = pd.DataFrame()
    df["source"] = res_source_filtered
    df["target"] = res_target_filtered
    df["group"] = group_filtered
    df.to_csv("cve_fixes_{}_prompt.csv".format(type), encoding='utf-8')
def notag(type):
    df = pd.read_csv("cve_fixes_{}.csv".format(type), encoding='utf-8')
    source = np.array(df["source"])
    target = np.array(df["target"])
    res_source = []
    res_target = []
    for s in source:
        s_to_do = s.strip()
        if s_to_do=="":
            res_source.append("\n")
            continue
        s_to_do = s_to_do.replace("<S2SV_StartBug>", "")
        s_to_do = s_to_do.replace("<S2SV_EndBug>", "")
        s_to_do = s_to_do.replace("<S2SV_null>", "")
        s_to_do = s_to_do.replace("<S2SV_blank>", "")
        res_source.append(s_to_do)
    for t in target:
        t_to_do = t.strip()
        if t_to_do=="":
            res_target.append("\n")
            continue
        t_to_do = t_to_do.replace("<S2SV_ModStart>", "")
        t_to_do = t_to_do.replace("<S2SV_ModEnd>", "")
        t_to_do = t_to_do.replace("<S2SV_null>", "")
        t_to_do = t_to_do.replace("<S2SV_blank>", "")
        res_target.append(t_to_do)
    res_source = pd.DataFrame(res_source)
    res_target = pd.DataFrame(res_target)
    df["source"] = res_source
    df["target"] = res_target
    df.to_csv("cve_fixes_{}_no_tag.csv".format(type), encoding='utf-8')
def nocve(type):
    df = pd.read_csv("cve_fixes_{}.csv".format(type), encoding='utf-8')
    source = np.array(df["source"])
    target = np.array(df["target"])
    res_source = []
    res_target = []
    for s in source:
        s_to_do = s.strip()
        if s_to_do=="":
            res_source.append("\n")
            continue
        s_to_do = " ".join(s_to_do.split()[1:])
        res_source.append(s_to_do)
    for t in target:
        t_to_do = t.strip()
        if t_to_do=="":
            res_target.append("\n")
            continue
        t_to_do = " ".join(t_to_do.split()[1:])
        res_target.append(t_to_do)
    res_source = pd.DataFrame(res_source)
    res_target = pd.DataFrame(res_target)
    df["source"] = res_source
    df["target"] = res_target
    df.to_csv("cve_fixes_{}_no_cve.csv".format(type), encoding='utf-8')
def notagcve(type):
    df = pd.read_csv("cve_fixes_{}.csv".format(type), encoding='utf-8')
    source = np.array(df["source"])
    target = np.array(df["target"])
    res_source = []
    res_target = []
    for s in source:
        s_to_do = s.strip()
        if s_to_do=="":
            res_source.append("\n")
            continue
        s_to_do = " ".join(s_to_do.split()[1:])
        s_to_do = s_to_do.replace("<S2SV_StartBug>", "")
        s_to_do = s_to_do.replace("<S2SV_EndBug>", "")
        s_to_do = s_to_do.replace("<S2SV_null>", "")
        s_to_do = s_to_do.replace("<S2SV_blank>", "")
        res_source.append(s_to_do)
    for t in target:
        t_to_do = t.strip()
        if t_to_do=="":
            res_target.append("\n")
            continue
        t_to_do = " ".join(t_to_do.split()[1:])
        t_to_do = t_to_do.replace("<S2SV_ModStart>", "")
        t_to_do = t_to_do.replace("<S2SV_ModEnd>", "")
        t_to_do = t_to_do.replace("<S2SV_null>", "")
        t_to_do = t_to_do.replace("<S2SV_blank>", "")
        res_target.append(t_to_do)
    res_source = pd.DataFrame(res_source)
    res_target = pd.DataFrame(res_target)
    df["source"] = res_source
    df["target"] = res_target
    df.to_csv("cve_fixes_{}_no_tagcve.csv".format(type), encoding='utf-8')
def shuffledata(split,type):
    df = pd.read_csv("cve_fixes_{}.csv".format(type))
    source = df["source"]
    target = df["target"]
    random.shuffle(source)
    random.shuffle(target)
    source = source[:int(len(source)*split)]
    target = target[:int(len(target)*split)]
    print(source)
if __name__=="__main__":
    shuffledata(0.2,"test")
    # noctx("train")
    # noctx("val")
    # noctx("test")
    # filterdata4abs("train")
    # filterdata4abs("val")
    # filterdata4abs("test")
    # getAbsbyReplace("train")
    # getAbsbyReplace("val")
    # getAbsbyReplace("test")
    # notag("train")
    # notag("val")
    # notag("test")
    # nocve("train")
    # nocve("val")
    # nocve("test")
    # notagcve("train")
    # notagcve("val")
    # notagcve("test")
    # diff("train")
    # diff("val")
    # diff("test")
    # prompt("train")
    # prompt("val")
    # prompt("test")