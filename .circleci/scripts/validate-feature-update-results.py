import re
import sys
import os
import json
from collections import OrderedDict

REGRESSION_JOB_TYPE_SUCCESS_CRITERIA = {}

EXPECTED_ORDERED_REGRESSION_JOB_TYPE = [
    "build-artifact",
    "regression-target-testnet",
    "update-feature",
    "update-jar-files",
    "regression-run-accessory-tests"
]


REGRESSION_JOB_TYPE_MUST_PASS = {
    "build-artifact": True,
    "regression-target-testnet": True,
    "update-feature": True,
    "update-jar-files": True,
    "regression-run-accessory-tests": True
}


SUMMARY_REPORT_FILE = 'client-logs/feature-update-test-summary.txt'
each_job_status = OrderedDict()


def init():

    with open(os.path.join(os.environ.get("REPO"), ".circleci/scripts/resources/build_artifact_success_pattern.json"), "r") as f:
        data = json.load(f)
        build_artifact_success = data["build_artifact_success_pattern"]
#        print("build_artifact_success_pattern: {}".format(build_artifact_success))
        REGRESSION_JOB_TYPE_SUCCESS_CRITERIA["build-artifact"] = build_artifact_success

    with open(os.path.join(os.environ.get("REPO"), ".circleci/scripts/resources/target_testnet_success_pattern.json"), "r") as f:
        data = json.load(f)
        target_testnet_success = data["target_testnet_success_pattern"]
#        print("target_testnet_success_pattern: {}".format(target_testnet_success))
        REGRESSION_JOB_TYPE_SUCCESS_CRITERIA["regression-target-testnet"] = target_testnet_success

    with open(os.path.join(os.environ.get("REPO"), ".circleci/scripts/resources/update_feature_success_patterns.json"), "r") as f:
        data = json.load(f)
        update_feature_success = data["update-feature"]

        REGRESSION_JOB_TYPE_SUCCESS_CRITERIA["long-contract_txns6"] = update_feature_success

    with open(os.path.join(os.environ.get("REPO"), ".circleci/scripts/resources/update_jar_files_success_patterns.json"), "r") as f:
        data = json.load(f)
        update_jar_files_success = data["update_jar_files"]

        REGRESSION_JOB_TYPE_SUCCESS_CRITERIA["update-jar-files"] = update_jar_files_success

def circleci_job_succeeded(log_file, success_criteria, job_type, job):
    with open(log_file, 'r') as f:
        log_contents = f.read()
        if success_criteria is None:
            return True    # empty criteria means anything is fine or should it mean False for missing success criteria?
        for i in success_criteria:
#            print("Current pattern to be matched: {}".format(i))
            r = re.compile( i )
            if not r.search(log_contents):
                print("This test failed at step '{}' job \"{}\" not found.".format(i, job))
                return False
    return True


def report_regression_status(overall_status):
    full_report_path = os.path.join(os.environ.get("REPO"), SUMMARY_REPORT_FILE)
    with open(full_report_path, 'w+') as f:
        f.writelines('================== THIS REGRESSION TEST REPORT ===================\n')

        f.writelines(' Overall Status: {}\n'.format(overall_status))
        f.writelines('\n---------------- ITEMIZED REPORT --------------------\n')
        f.writelines("{0:30s}\t{1:10s}\n".format("JOB NAME", "STATUS"))
        for key, value in each_job_status.items():
            if value:
                status = "Passed"
            elif not value:
                status = "FAILED"
            else:
                status = "Not run"

            f.writelines("{0:30s}\t{1:10s}\n".format(key, status))

        f.writelines('================== END REPORT ===================\n')


def get_AWS_testnet_IPs(log_file):
    IPs = []
    with open(log_file, "r") as f:
        data = f.read()

        match = re.search("PLAY RECAP \*+\n((.*\n){4})", data)
        IP_lines = [line for line in match.group(1).split(sep='\n') if len(line) > 0]
#        IP_PATTERN = re.compile(r'\d+[.]\d+[.]\d+[.]\d+')
        for line in IP_lines:
            IP = re.search('(\d+\.\d+\.\d+\.\d+)[ \t]+:[ \t]+ok=\d+.*', line)
            IPs.append(IP.group(1))

    return IPs


def rebuild_success_criteria(success_criteria, log_file):
    IPs = get_AWS_testnet_IPs(log_file)
    new_criteria = []
    for IP in IPs:
        new_criteria.append(IP + success_criteria[0])

    return new_criteria



log_parent_path = '.'

if __name__ == '__main__':
    print("Summarize the test results of this workflow...")

    init()

    overall_status = 'Passed'

    if sys.argv[1] and os.path.exists(sys.argv[1]):
        log_parent_path = sys.argv[1]
        child_log_paths = [os.path.basename(os.path.normpath(child_log_path[0]))
                           for child_log_path in os.walk(log_parent_path)]

        for job_type in EXPECTED_ORDERED_REGRESSION_JOB_TYPE:
            r = re.compile(".*" + job_type + ".*")
            jobs = [job for job in child_log_paths if r.match(job)]
            if len(jobs) >= 1:
                for job in jobs:
                    log_file = os.path.join(log_parent_path, job, "hapi-client.log")
                    success_criteria = REGRESSION_JOB_TYPE_SUCCESS_CRITERIA.get(job_type)

                    if job_type == "regression-target-testnet":
                        success_criteria = rebuild_success_criteria(success_criteria, log_file)

                    current_status = circleci_job_succeeded(log_file, success_criteria, job_type, job)
                    if not current_status:
                        print("Job {} failed.".format(job))
                        each_job_status[job] = False
                        if REGRESSION_JOB_TYPE_MUST_PASS[job_type]:
                            overall_status = 'Failed'
                        elif overall_status == 'Passed':
                            overall_status = 'Passed with error'
                    else:
                        print("Job {} succeeded.".format(job))
                        each_job_status[job] = True

            else:
                print("Job {} not run.".format(job_type))
                each_job_status[job_type] = None
                if REGRESSION_JOB_TYPE_MUST_PASS[job_type]:
                    overall_status = 'Failed'
                elif overall_status == 'Passed':
                    overall_status = 'Passed with error'

    report_regression_status(overall_status)
