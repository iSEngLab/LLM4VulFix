import os

import pandas as pd
import json
import random

df1 = pd.read_csv("cve_fixes_test_no_ctx.csv")
df2 = pd.read_csv("cve_fixes_val_no_ctx.csv")
df3 = pd.read_csv("cve_fixes_train_no_ctx.csv")
df = pd.DataFrame()
df = df1.append(df2)
df = df.append(df3)
df.to_csv("no_ctx_whole.csv")
df=pd.read_csv("no_ctx_whole.csv")
json_obj = json.loads(df.to_json())
datas = list(zip(
    json_obj['source'].values(),
    json_obj['target'].values(),
))


# df_train = pd.DataFrame(datas)
# df_train.columns = ['cwe_id', 'source', 'target', 'project_and_commit_id', 'cve_id', 'original_address', 'time']
# df_train.to_csv("cve_fixes_shuffled.csv")
#
# all_count = len(datas)
# train_count = 5937
# val_count = 839
# test_count = 1706

for i in range(5):
    os.mkdir(f'{i}')
    tmp_datas = list(datas)

    test_start = 1706 * i
    df_data = pd.DataFrame(list(tmp_datas[test_start:test_start + 1706]))
    df_data.columns = ['source', 'target']
    df_data.to_csv(f"{i}/cve_fixes_test.csv")
    del tmp_datas[test_start:test_start + 1706]

    val_start = test_start if i != 4 else 0
    df_data = pd.DataFrame(tmp_datas[val_start:val_start + int(1706 / 2)])
    df_data.columns = ['source', 'target']
    df_data.to_csv(f"{i}/cve_fixes_val.csv")
    del tmp_datas[val_start:val_start + int(2434 / 2)]

    df_data = pd.DataFrame(tmp_datas)
    df_data.columns = ['source', 'target']
    df_data.to_csv(f"{i}/cve_fixes_train.csv")
