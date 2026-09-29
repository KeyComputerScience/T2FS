import pandas as pd, os, json

ROOT="../logs_template"
OUT="../output/security_results.json"

if __name__=="__main__":
    result={}
    for root,_,files in os.walk(ROOT):
        if "attack.csv" in files:
            df=pd.read_csv(os.path.join(root,"attack.csv"))
            result[root]={}
            for a,g in df.groupby("attack"):
                result[root][a]={
                    "total":len(g),
                    "reject":int((g.result=="reject").sum())
                }
    json.dump(result,open(OUT,"w"),indent=4)
    print("security validation completed")
