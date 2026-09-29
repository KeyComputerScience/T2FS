import csv, json, os

ROOT="../logs_template"
OUT="../output/resource_results.json"

def run():
    results=[]
    for root,_,files in os.walk(ROOT):
        if "memory.csv" in files:
            with open(os.path.join(root,"memory.csv")) as f:
                results.extend(list(csv.DictReader(f)))
    with open(OUT,"w") as f:
        json.dump(results,f,indent=4)

if __name__=="__main__":
    run()
    print("resource analysis completed")
