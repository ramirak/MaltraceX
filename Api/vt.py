from datetime import datetime
import requests
import json 
import Data.files as files
import Data.enums as enums
from Analysis.harddisk import sha256sum


def get_report(filename, hash):
    conf = files.retrieve_from_file(enums.files.CONFIG.value)
    if conf == enums.results.FILE_NOT_FOUND.value:
        return conf

    api_k = conf["virus_total_key"]

    if api_k == "":
        return enums.results.API_KEY_NOT_FOUND.value
  
    result = "\n Checking " + filename + " - " + hash + ":\n"

    url = "https://www.virustotal.com/api/v3/files/" + hash
    headers = {"accept": "application/json", "x-apikey": api_k}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return enums.results.NO_MATCH_FOUND.value
    
    res = json.loads(response.text)
    report_attr = res["data"]["attributes"]
    result += "Total Malicious: " + str(report_attr["last_analysis_stats"]["malicious"]) + "\n"
    result += "Total Undetected: " + str(report_attr["last_analysis_stats"]["undetected"]) + "\n"
    result += "File Reputation: " + str(report_attr["reputation"]) + "\n"
    if "popular_threat_classification" in report_attr:
        result += "Suggested label: " + report_attr["popular_threat_classification"]["suggested_threat_label"] + "\n"
    engines_list = report_attr["last_analysis_results"]
    for i in engines_list:
        result += engines_list[i]["engine_name"] + " - " + engines_list[i]["category"] + "\n" 
    return result


