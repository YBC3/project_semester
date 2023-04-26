import pandas as pd
import ray
#ray.shutdown()
ray.init()

@ray.remote
def update_df(dframe1):
    dframe2 = pd.DataFrame(columns=[f'packet length {i}' for i in range(32)])
    for idx in range(911737):
        da = dframe1.iloc[idx]
        length = da['TLS option 1']
        len_bin = bin(length)
        bin_string = len_bin[2:].zfill(32)
        row = {f'packet length {i}': int(bin_string[i]) for i in range(32)}
        #row['Label'] = da['Label']
        dframe2 = dframe2.append(row, ignore_index=True)
        if idx % 10000 == 0:
            print(idx)
    return dframe2
d = pd.read_csv('output_data.csv')
d2 = d.dropna()

r = update_df.remote(d2)

df_1 = ray.get(r)
ray.shutdown()