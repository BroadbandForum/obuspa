#!/usr/bin/env python3

#
# This script launches all packages with a specified tag on a given CDRouter
# system. After the packages have completed, the script creates an XML report in
# JUnit format that Gitlab can parse. The script also downloads each test's log
# and capture files to be stored as artifacts using Gitlab's CI/CD
# infrastructure. All created files are stored in out/ and can be saved as
# artifacts in the Gitlab CD/CD test job.
#
# Example job in a .gitlab-ci.yaml file:
#
#   cdrouter-test:
#     tags:
#       - cdrouter-gitlab-runner
#     stage: test
#     script:
#       - gitlab.py <CDRouter-URL> <token> nightly $CI_COMMIT_BRANCH,$CI_PIPELINE_ID
#     artifacts:
#       when: always
#       paths:
#         - out/*.zip
#       reports:
#         junit: out/results_*.xml
#
import sys
import time
import shutil
import os

from zipfile import ZipFile
from cdrouter import CDRouter
from cdrouter.jobs import Job
from cdrouter.jobs import Options
from cdrouter.testresults import TestResult
from cdrouter.cdrouter import CDRouterError

import subprocess

if len(sys.argv) < 5:
    print('usage: <base_url> <token> <run-tag> <result-tag>')
    print('       <base_url>    URL of CDRouter system')
    print('       <token>       CDRouter system API token')
    print('       <run-tag>     All packages with this tag will be launched')
    print('       <result-tag>  Results will be tagged with this tag or tags in a comma separated list')
    sys.exit(1)

base = sys.argv[1]
token = sys.argv[2]
tag_name = sys.argv[3]
result_tags = sys.argv[4]

result_tags_list = result_tags.split(",")
# create service
c = CDRouter(base, token=token)

packages = c.packages.iter_list(filter=['tags@>{'+tag_name+'}'])
jobs = [Job(package_id=p.id, options=Options(tags=result_tags_list)) for p in packages]

fails = 0
# launch all packages
for j in c.jobs.bulk_launch(jobs=jobs):
    while j.result_id is None:
        time.sleep(1)
        j = c.jobs.get(j.id)
    print('Test package launched. Result-ID: {0}'.format(j.result_id))
    print('Waiting for job to complete...')

    u = c.results.updates(j.result_id, None)
    while u:
        r = c.results.get(j.result_id)
        if r.status in ['completed', 'stopped', 'error']:
            break
        time.sleep(1)
        u = c.results.updates(j.result_id, u.id)

    result_url = base.strip('/') + '/results/' + str(r.id)
    print('Job status: {0}'.format(r.status))

    if r.status != 'completed':
        print('Error: test package "{0}" did not complete successfully ({1})'.format(r.package_name, r.status))
        print('Test report: {0}'.format(result_url))
        fails = 1

    print('Test results:')
    print('')
    print('{0:>21} : {1}'.format('Package',      r.package_name))
    print('{0:>21} : {1}'.format('Config',       r.config_name))
    print('{0:>21} : {1}'.format('Tags',         r.tags))
    print('{0:>21} : {1}'.format('Pass',         r.passed))
    print('{0:>21} : {1}'.format('Fail',         r.fail))
    print ('')
    for test in c.tests.iter_list(j.result_id):
        if test.name in ['start', 'final']: continue
        print('{0:>21} : {1}'.format(test.name, test.result))
    print('')

    cwd = os.getcwd()
    results_directory = os.path.join(cwd,'out')
    if not os.path.isdir(results_directory):
        os.mkdir(results_directory)
    os.chdir(results_directory)

    name = r.package_name
    file_name = name.replace(' ', '_')
    # Download & zip log and capture files
    zip_file_name = file_name + '.zip'
    with ZipFile(zip_file_name, mode='w') as archive:
        for t in c.tests.iter_list(j.result_id):
            url='{0}/results/{1}/tests/{2}'.format(base, j.result_id, t.seq)

            if len(t.log) == 0:
                continue
            with open(t.log, 'w') as logFile:
                logFile.write(c.tests.get_log_plaintext(t.id, t.seq))
                logFile.close()
                archive.write(t.log)
                os.remove(t.log)

                for caps in c.captures.list(t.id, t.seq):
                    b,capFileName = c.captures.download(t.id, t.seq, caps.interface)
                    with open(capFileName, 'wb') as capFile:
                        shutil.copyfileobj(b,capFile)
                    capFile.close()
                    archive.write(capFileName)
                    os.remove(capFileName)
    archive.close()

    # print junit
    junit_directory = os.path.join(results_directory,'test-results')
    if not os.path.isdir(junit_directory):
        os.mkdir(junit_directory)
    os.chdir(junit_directory)
    filename = f'results_{j.result_id}.xml'
    with open(filename, 'w') as f:
        f.write(f'<testsuite name="{name}" package="usp_conformance" failures="{r.fail}" tests="{r.tests}">\n')
        for t in c.tests.iter_list(j.result_id):
            f.write(f'    <testcase name="{t.name}">\n')
            if t.result in ['fail', 'fatal']:
                f.write('        <failure>\n')
                try:
                    logs = c.tests.list_log(t.id, t.seq, filter=['prefix=FAIL'], limit='100000')
                    for l in logs.lines:
                        f.write(f'            {l.message}\n')
                except CDRouterError as cdre:
                        print(f"            Cannot get logs for JUnit file, {cdre}")
                f.write('        </failure>\n')
            elif t.result in ['pending', 'skipped']:
                f.write('        <skipped/>\n')
            f.write('    </testcase>\n')
        f.write('</testsuite>\n')
    f.close()
    os.chdir(cwd)


exit(fails)
