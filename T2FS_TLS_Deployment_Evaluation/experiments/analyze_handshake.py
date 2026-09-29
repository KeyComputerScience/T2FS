import pandas as pd, os, json

ROOT="../logs_template"
OUT="../output/handshake_results.json"

def analyze(path):
    df=pd.read_csv(path)
    out={}
    for s,g in df.groupby("scheme"):
        out[s]={
            "mean_ms":float(g.latency_ms.mean()),
            "std_ms":float(g.latency_ms.std()),
            "bytes":float(g.bytes.mean())
        }
    return out

if __name__=="__main__":
    result={}
    for root,_,files in os.walk(ROOT):
        if "handshake.csv" in files:
            result[root]=analyze(os.path.join(root,"handshake.csv"))
    json.dump(result,open(OUT,"w"),indent=4)
    print("handshake analysis completed")
