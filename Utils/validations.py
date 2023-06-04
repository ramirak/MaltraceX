
import Data.enums as enums

def parse_res(res):
    if res == enums.results.GENERAL_FAILURE.value:
        print("General Failure.")
    elif res == enums.results.API_KEY_NOT_FOUND.value:
        print("Please set your API key.")
    elif res == enums.results.SNAPSHOT_NOT_FOUND.value:
        print("No snapshot found.")
    elif res == enums.results.NO_MATCH_FOUND.value:
        print("No match was found.")
    elif res == enums.results.NON_PE_FILE.value:
        print("Non PE file.")
    elif res == enums.results.FINISHED_WITH_ERRORS.value:
        print("Finished with errors.")
    elif res == enums.results.FILE_NOT_FOUND.value:
        print("File not found.")
    elif res == enums.results.SUCCESS.value:
        print("Done.")
        return 1
    else:
        return 0
    return -1
