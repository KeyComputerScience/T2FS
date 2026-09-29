import pandas as pd, os, json

ROOT="../logs_template"
OUT="../output/energy_results.json"

def calc(path):
    df=pd.read_csv(path)
    result={}
    for s,g in df.groupby("scheme"):
        e=g.voltage*g.current*g.duration_ms/1000
        result[s]={
            "mean_mj":float(e.mean()),
            "std_mj":float(e.std())
        }
    return result

if __name__=="__main__":
    out={}
    for root,_,files in os.walk(ROOT):
        if "energy.csv" in files:
            out[root]=calc(os.path.join(root,"energy.csv"))
    json.dump(out,open(OUT,"w"),indent=4)
    print("energy analysis completed")
