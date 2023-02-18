from datetime import datetime
import requests
import json 
import Data.files as files
import Data.enums as enums
from Analysis.harddisk import sha256sum
from Utils.string_utils import print_header


def get_report(hash):
    conf = files.retrieve_from_file(enums.files.CONFIG.value)
    api_k = conf["virus_total_key"]
    if api_k == "":
        return enums.results.API_KEY_NOT_FOUND.value

    url = "https://www.virustotal.com/api/v3/files/" + hash
    headers = {"accept": "application/json", "x-apikey": api_k}
    response = requests.get(url, headers=headers)
    result = ""
    if response.status_code != 200:
        return enums.results.NO_MATCH_FOUND.value
    
    res = json.loads(response.text)
    report_attr = res["data"]["attributes"]
    result += print_header("Virus Total report:")
    result += "Total Malicious: " + str(report_attr["last_analysis_stats"]["malicious"]) + "\n"
    result += "Total Undetected: " + str(report_attr["last_analysis_stats"]["undetected"]) + "\n"
    result += "File Reputation: " + str(report_attr["reputation"]) + "\n"
    if "popular_threat_classification" in report_attr:
        result += "Suggested label: " + report_attr["popular_threat_classification"]["suggested_threat_label"] + "\n"
    result += print_header("Engines results:")
    engines_list = report_attr["last_analysis_results"]
    for i in engines_list:
        result += engines_list[i]["engine_name"] + " - " + engines_list[i]["category"] + "\n" 
    return result


def write_vt_report(chosen_file):
    file_hash = sha256sum(chosen_file)
    if file_hash == None:
        return enums.results.FILE_NOT_FOUND.value
    report = get_report(file_hash)
    if report == enums.results.API_KEY_NOT_FOUND.value or report == enums.results.NO_MATCH_FOUND.value:
        return report
    log_file = enums.files.REPORT.value
    with open(log_file, "a+") as logfile:
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        logfile.write("\n-------------------- " + chosen_file + " - " + file_hash + ": " + dt_string + " --------------------\n")
        logfile.write(report + "\n")
    return enums.results.SUCCESS.value