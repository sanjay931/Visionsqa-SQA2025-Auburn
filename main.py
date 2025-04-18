import sys
import os
import typer
import pandas as pd
from forensics import forensics_decorator
import scanner
import constants

@forensics_decorator
def getCountFromAnalysis(ls_):
    list2ret = []
    for tup_ in ls_:
        within_sec_cnt = 0 
        dir_name       = tup_[0]
        script_name    = tup_[1]        
        within_secret  = tup_[2]  
        within_sec_cnt = len(within_secret[0]) + len(within_secret[1]) + len(within_secret[2])
        templa_secret  = tup_[3]
        taint_secret   = tup_[4]
        privilege_dic  = tup_[5]
        http_dict      = tup_[6]        
        secuContextDic = tup_[7]
        nSpaceDict     = tup_[8]                
        absentResoDict = tup_[9]                 
        rollUpdateDic  = tup_[10]
        netPolicyDict  = tup_[11]                
        pidfDict       = tup_[12]                
        ipcDict        = tup_[13]                 
        dockersockDic  = tup_[14]
        hostNetDict    = tup_[15]                        
        cap_sys_dic    = tup_[16]
        host_alias_dic = tup_[17]
        allow_priv_dic = tup_[18]
        unconfined_dic = tup_[19]
        cap_module_dic = tup_[20]
        k8s_flag       = tup_[21]
        helm_flag      = tup_[22]

        list2ret.append((
            dir_name, script_name, within_sec_cnt, len(taint_secret), len(privilege_dic), len(http_dict), 
            len(secuContextDic), len(nSpaceDict), len(absentResoDict), len(rollUpdateDic), len(netPolicyDict), 
            len(pidfDict), len(ipcDict), len(dockersockDic), len(hostNetDict), len(cap_sys_dic), len(host_alias_dic), 
            len(allow_priv_dic), len(unconfined_dic), len(cap_module_dic), k8s_flag, helm_flag
        ))
    return list2ret

@forensics_decorator
def main():
    # Use current directory as default
    directory = "."
    
    # Get command line arguments if provided
    if len(sys.argv) > 1:
        directory = sys.argv[1]
    
    print(f"Processing directory: {directory}")
    
    # Validate the directory exists
    if not os.path.exists(directory):
        print(f"Error: Directory does not exist: {directory}")
        return
    
    # Run the scanner
    content_as_ls, sarif_json = scanner.runScanner(directory)

    # Write the SARIF output to file
    with open("SLIKUBE.sarif", "w") as f:
        f.write(sarif_json)

    # Process and save results
    df_all = pd.DataFrame(getCountFromAnalysis(content_as_ls))
    
    # Create output file in current directory (not in the scanned directory)
    outfile = "slikube_results.csv"
    df_all.to_csv(outfile, header=constants.CSV_HEADER, index=False, encoding=constants.CSV_ENCODING)
    print(f"Results saved to {outfile}")

if __name__ == '__main__':
    main()