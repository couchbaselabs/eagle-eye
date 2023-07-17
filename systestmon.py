import copy
import json
import logging
import re
import sys
from datetime import datetime, timedelta
import httplib2
import traceback
import socket
import time
import base64
import os
import ast
import zipfile
from couchbase.cluster import Cluster, PasswordAuthenticator

import paramiko
import requests
from collections import Mapping, Sequence, Set, deque

from scp import SCPClient


class SysTestMon():
    # Input map of keywords to be mined for in the logs
    configuration = [
        {
            "component": "memcached",
            "logfiles": "babysitter.log*",
            "services": "all",
            "keywords": ["exception occurred in runloop", "failover exited with reason", "Basic\s[a-zA-Z]\{10,\}",
                         "Menelaus-Auth-User:\["],
            "ignore_keywords": None,
            "check_stats_api": False,
            "collect_dumps": False
        },
        {
            "component": "memcached",
            "logfiles": "memcached.log.*",
            "services": "all",
            "keywords": ["CRITICAL", "Basic\s[a-zA-Z]\{10,\}", "Menelaus-Auth-User:\[", "exception occurred in runloop", "Invalid packet header detected"],
            "ignore_keywords": None,
            "check_stats_api": False,
            "collect_dumps": False
        },
        {
            "component": "index",
            "logfiles": "indexer.log*",
            "services": "index",
            "keywords": ["panic", "fatal", "Error parsing XATTR", "zero", "protobuf.Error", "Encounter planner error",
                         "corruption", "processFlushAbort", "Basic\s[a-zA-Z]\{10,\}", "Menelaus-Auth-User:\[",
                         "Failed to initialize metadata provider", "found missing page", "invalid last page",
                         "Storage corrupted and unrecoverable", "ensureMonotonicTs  Align seqno smaller than lastFlushTs",
                         "TS falls out of snapshot boundary", "invalid length of composite element filters in scan request",
                         "Internal error while creating new scan request", "StorageMgr::handleCreateSnapshot Disk commit timestamp is not snapshot aligned"],
            "ignore_keywords": ["fatal remote"],
            "check_stats_api": True,
            "stats_api_list": ["stats/storage", "stats"],
            "port": "9102",
            "collect_dumps": True
        },
        {
            "component": "analytics",
            "logfiles": "analytics_error*",
            "services": "cbas",
            "keywords": ["fata", "Analytics Service is temporarily unavailable", "Failed during startup task", "HYR0",
                         "ASX", "IllegalStateException", "Basic\s[a-zA-Z]\{10,\}", "Menelaus-Auth-User:\[", "panic", "LEAK: ByteBuf.release() was not called",
                         "failed to migrate metadata partition"],
            "ignore_keywords": ["HYR0010","HYR0115","ASX3110","HYR0114"],
            "check_stats_api": False,
            "collect_dumps": False
        },
        {
            "component": "eventing",
            "logfiles": "eventing.log*",
            "services": "eventing",
            "keywords": ["panic", "fatal", "Basic\s[a-zA-Z]\{10,\}", "Menelaus-Auth-User:\["],
            "ignore_keywords": None,
            "check_stats_api": False,
            "collect_dumps": False
        },
        {
            "component": "fts",
            "logfiles": "fts.log*",
            "services": "fts",
            "keywords": ["panic", "fatal", "authPassword", "\[ERRO\]", "Basic\s[a-zA-Z]\{10,\}",
                         "Menelaus-Auth-User:\["],
            "ignore_keywords": ["Fatal:false", "use of closed network connection",
                                "Reschedule failed, failing request", "TLS handshake error", "cannot unmarshal object",
                                "bleve.Index is not copyable"],
            "check_stats_api": True,
            "stats_api_list": ["api/stats"],
            "port": "8094",
            "collect_dumps": True
        },
        {
            "component": "xdcr",
            "logfiles": "*xdcr*.log*",
            "services": "kv",
            "keywords": ["Failed on calling", "panic", "fatal", "Basic\s[a-zA-Z]\{10,\}", "Menelaus-Auth-User:\[",
             "non-recoverable error from xmem client", "Unable to respond to caller",
             "Unable to generate req or resp", "error when making rest call or unmarshalling data",
             "unable to find last known target manifest version", "net/http: request canceled",
             "has payloadCompressed but no payload after deserialization",
             "Error converting VBTask to DCP Nozzle Task",
	     "Xmem is stuck"],
            "ignore_keywords": None,
            "check_stats_api": False,
            "collect_dumps": False,
            "outgoing_mutations_threshold": 1000000
        },
        {
            "component": "projector",
            "logfiles": "projector.log*",
            "services": "kv",
            "keywords": ["panic", "Error parsing XATTR", "Basic\s[a-zA-Z]\{10,\}", "Menelaus-Auth-User:\[", "seq order violation"],
            #"keywords": ["panic", "Error parsing XATTR", "Basic\s[a-zA-Z]\{10,\}", "Menelaus-Auth-User:\["],
            "ignore_keywords": None,
            "check_stats_api": False,
            "port": "9999",
            "collect_dumps": True
        },
        {
            "component": "rebalance",
            "logfiles": "error.log*",
            "services": "all",
            "keywords": ["rebalance exited", "failover exited with reason", "Basic\s[a-zA-Z]\{10,\}",
                         "Menelaus-Auth-User:\[","Join completion call failed"],
            "ignore_keywords": None,
            "check_stats_api": False,
            "collect_dumps": False
        },
        {
            "component": "crash",
            "logfiles": "info.log*",
            "services": "all",
            "keywords": ["exited with status", "failover exited with reason", "Basic\s[a-zA-Z]\{10,\}",
                         "Menelaus-Auth-User:\["],
            "ignore_keywords": ["exited with status 0"],
            "check_stats_api": False,
            "collect_dumps": False
        },
        {
            "component": "query",
            "logfiles": "query.log*",
            "services": "n1ql",
            "keywords": ["panic", "fatal", "Encounter planner error", "Basic\s[a-zA-Z]\{10,\}",
                         "Menelaus-Auth-User:\[", "invalid byte in chunk length"],
            "ignore_keywords": ["not available"],
            "check_stats_api": False,
            "collect_dumps": True,
            "port": "8093"
        },
        {
            "component": "autofailover",
            "logfiles": "info.log*",
            "services": "all",
            "keywords": ["due to operation being unsafe for service index"],
            "ignore_keywords": None,
            "check_stats_api": False,
            "collect_dumps": False
        },
        {
            "component": "backup",
            "logfiles": "backup_service.log*",
            "services": "backup",
            "keywords": ["panic", "fatal", "warn", "Failed Task",
                         "Basic\s[a-zA-Z]\{10,\}", "Menelaus-Auth-User:\["],
            "ignore_keywords": None,
            "check_stats_api": False,
            "collect_dumps": True,
            "port": "8097"
        }
    ]
    # Frequency of scanning the logs in seconds
    scan_interval = 3600
    # Level of memory usage after which alert should be raised
    mem_threshold = 90
    # Level of CPU usage after which alert should be raised
    cpu_threshold = 90

    # 1. Get service map for cluster
    # 2. For each component, get nodes for the requested service
    # 3. SSH to those nodes, grep for specified keywords in specified files
    # 4. Reporting

    ignore_list = ["Port exited with status 0", "Fatal:false", "HyracksDataException: HYR0115: Local network error",
                   "No such file or directory"]

    def run(self, master_node, rest_username, rest_password, ssh_username, ssh_password,
            cbcollect_on_high_mem_cpu_usage, print_all_logs, email_recipients, state_file_dir, run_infinite, logger,
            should_collect_dumps, docker_host, cb_host):
        # Logging configuration
        if not logger:
            self.logger = logging.getLogger("systestmon")
            self.logger.setLevel(logging.DEBUG)
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)
            timestamp = str(datetime.now().strftime('%Y%m%dT_%H%M%S'))
            fh = logging.FileHandler("./systestmon-{0}.log".format(timestamp))
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)
        else:
            self.logger = logger

        self.wait_for_cluster_init(master_node)

        try:
            self.cluster = self.get_cluster(cb_host)
            self.bucket = self.get_bucket("system_test_dashboard")
        except Exception:
            pass

        self.run_infinite = ast.literal_eval(run_infinite)
        self.should_collect_dumps = ast.literal_eval(should_collect_dumps)
        paramiko.util.log_to_file('./paramiko.log')

        timestamp = str(datetime.now().strftime('%Y-%m-%dT%H:%M:%S'))

        self.keyword_counts = {}
        self.keyword_counts["timestamp"] = timestamp
        self.state_file = state_file_dir + "/eagle-eye_" + master_node + ".state"
        last_scan_timestamp = ""
        iter_count = 1
        while True:
            if os.path.exists(self.state_file):
                s = open(self.state_file, 'r').read()
                prev_keyword_counts = ast.literal_eval(s)
                last_scan_timestamp = datetime.strptime(prev_keyword_counts["last_scan_timestamp"],
                                                        "%Y-%m-%d %H:%M:%S.%f")
            else:
                prev_keyword_counts = None
            self.dump_dir_name = "dump_collected_" + str(iter_count)
            if not os.path.isdir(self.dump_dir_name):
                os.mkdir(self.dump_dir_name)
            should_cbcollect = False
            message_content = ""
            message_sub = ""
            node_map = self.get_services_map(master_node, rest_username, rest_password)
            if not node_map:
                continue
            for component in self.configuration:
                nodes = self.find_nodes_with_service(node_map,
                                                     component["services"])
                self.logger.info(
                    "Nodes with {0} service : {1}".format(component["services"],
                                                          str(nodes)))
                for keyword in component["keywords"]:
                    key = component["component"] + "_" + keyword
                    self.logger.info(
                        "--+--+--+--+-- Parsing logs for {0} component looking for {1} --+--+--+--+--".format(
                            component["component"], keyword))
                    total_occurences = 0

                    for node in nodes:
                        if component["ignore_keywords"]:

                            command = "zgrep -i \"{0}\" /opt/couchbase/var/lib/couchbase/logs/{1} | grep -vE \"{2}\"".format(
                                keyword, component["logfiles"], "|".join(component["ignore_keywords"]))
                        else:
                            command = "zgrep -i \"{0}\" /opt/couchbase/var/lib/couchbase/logs/{1}".format(
                                keyword, component["logfiles"])
                        occurences = 0
                        try:
                            occurences, output, std_err = self.execute_command(
                                command, node, ssh_username, ssh_password)
                        except Exception as e:
                            self.logger.info("Found an exception {0}".format(e))
                            message_content = message_content + '\n\n' + node + " : " + str(component["component"])
                            message_content = message_content + '\n\n' + "Found an exception {0}".format(e) + "\n"
                        if occurences > 0:
                            self.logger.warn(
                                "*** {0} occurences of {1} keyword found on {2} ***".format(
                                    occurences,
                                    keyword,
                                    node))
                            message_content = message_content + '\n\n' + node + " : " + str(component["component"])
                            if print_all_logs.lower() == "true" or last_scan_timestamp == "":
                                self.logger.debug('\n'.join(output))
                                try:
                                    message_content = message_content + '\n' + '\n'.join(output)
                                except UnicodeDecodeError as e:
                                    self.logger.warn(str(e))
                                    message_content = message_content + '\n' + '\n'.join(output).decode("utf-8")
                            else:
                                message_content = self.print_output(output, last_scan_timestamp, message_content)
                            # for i in range(len(output)):
                            #    self.logger.info(output[i])
                        total_occurences += occurences

                    self.keyword_counts[key] = total_occurences
                    if prev_keyword_counts is not None and key in prev_keyword_counts.keys():
                        if total_occurences > int(prev_keyword_counts[key]):
                            self.logger.warn(
                                "There have been more occurences of keyword {0} in the logs since the last iteration. Hence performing a cbcollect.".format(
                                    keyword))
                            should_cbcollect = True
                    else:
                        if total_occurences > 0:
                            should_cbcollect = True

                for node in nodes:
                    if component["check_stats_api"]:
                        message_content = message_content + '\n\n' + node + " : " + str(component["component"])
                        try:
                            fin_neg_stat, message_content = self.check_stats_api(node, component, message_content)
                            if fin_neg_stat.__len__() != 0:
                                should_cbcollect = True
                        except Exception as e:
                            self.logger.info("Found an exception {0}".format(e))

                    if component["collect_dumps"] and self.should_collect_dumps:
                        message_content = message_content + '\n\n' + node + " : " + str(
                            component["component"]) + " Collecting dumps"
                        try:
                            message_content = self.collect_dumps(node, component, message_content)
                        except Exception as e:
                            self.logger.info("Found an exception {0}".format(e))

                # Check if all n1ql nodes are healthy
                if component["component"] == "query":
                    n1ql_nodes = self.find_nodes_with_service(node_map,"n1ql")
                    if n1ql_nodes:
                        # Check to make sure all nodes are healthy
                        self.logger.info("Checking if all query nodes are healthy")
                        should_collect, message = self.check_nodes_healthy(nodes=nodes, component=component, rest_username=rest_username, rest_password=rest_password, ssh_username=ssh_username, ssh_password=ssh_password)
                        if should_collect:
                            should_cbcollect = True
                        if not message == '':
                            message_content = message_content + '\n\n' + node + " : " + str(component["component"])
                            message_content = message_content + '\n\n' + message + "\n"
                        # Check system:completed_requests for errors
                        self.logger.info("Checking system:completed requests for errors")
                        should_collect, message = self.check_completed_requests(nodes=nodes, component=component, rest_username=rest_username, rest_password=rest_password, ssh_username=ssh_username, ssh_password=ssh_password)
                        if should_collect:
                            should_cbcollect = True
                        if not message == '':
                            message_content = message_content + '\n\n' + node + " : " + str(component["component"])
                            message_content = message_content + '\n\n' + message + "\n"
                        # Check active_requests to make sure that are no more than 1k active requests at a single time
                        self.logger.info("Checking system:active requests for too many requests")
                        should_collect, message = self.check_active_requests(nodes=nodes, component=component, rest_username=rest_username, rest_password=rest_password, ssh_username=ssh_username, ssh_password=ssh_password)
                        if should_collect:
                            should_cbcollect = True
                        if not message == '':
                            message_content = message_content + '\n\n' + node + " : " + str(component["component"])
                            message_content = message_content + '\n\n' + message + "\n"

                # # Check if XDCR outgoing mutations in the past hour > threshold
                # if component["component"] == "xdcr":
                #     threshold = component["outgoing_mutations_threshold"]
                #     src_buckets = self.get_xdcr_src_buckets(master_node)
                #     for src_bucket in src_buckets:
                #         bucket_stats = self.fetch_bucket_xdcr_stats(master_node, src_bucket)['op']['samples'][
                #                            'replication_changes_left'][-60:]
                #         if all(stat > threshold for stat in bucket_stats):
                #             self.logger.warn(
                #                 "XDCR outgoing mutations in the past hour on {0}\n{1} > {2}".format(
                #                     src_bucket,
                #                     bucket_stats,
                #                     threshold))
                #             should_cbcollect = True

            # Check for health of all nodes
            for node in node_map:
                if node["memUsage"] > self.mem_threshold:
                    self.logger.warn(
                        "***** ALERT : Memory usage on {0} is very high : {1}%".format(
                            node["hostname"], node["memUsage"]))
                    # if cbcollect_on_high_mem_cpu_usage:
                    #    should_cbcollect = True

                if node["cpuUsage"] > self.cpu_threshold:
                    self.logger.warn(
                        "***** ALERT : CPU usage on {0} is very high : {1}%".format(
                            node["hostname"], node["cpuUsage"]))
                    # if cbcollect_on_high_mem_cpu_usage:
                    #    should_cbcollect = True

                if node["status"] != "healthy":
                    self.logger.warn(
                        "***** ALERT : {0} is not healthy. Current status : {1}%".format(
                            node["hostname"], node["status"]))
                    if cbcollect_on_high_mem_cpu_usage:
                        should_cbcollect = True
                # self.check_on_ntp_status(node["hostname"])
                self.check_on_disk_usage(node["hostname"])

            last_scan_timestamp = datetime.now() - timedelta(minutes=10.0)
            self.logger.info("Last scan timestamp :" + str(last_scan_timestamp))
            self.keyword_counts["last_scan_timestamp"] = str(last_scan_timestamp)

            if docker_host != "None":
                try:
                    command = "docker ps -q | xargs docker inspect --format {{.LogPath}}"
                    occurences, output, std_err = self.execute_command(
                        command, docker_host, ssh_username, ssh_password)

                    self.docker_logs_dump = "docker_dump_collected_" + str(iter_count) \
                                            + "_" + str(datetime.now().strftime('%Y-%m-%dT%H:%M:%S'))
                    os.mkdir(self.docker_logs_dump)

                    ssh_client = self.get_ssh_client(docker_host, ssh_username, ssh_password)

                    for file in output:
                        with SCPClient(ssh_client.get_transport()) as scp:
                            scp.get(file, local_path=self.docker_logs_dump)

                    docker_logs_location = "{0}/{1}".format(os.getcwd(), self.docker_logs_dump)
                    message_content = message_content + '\n\n Docker logs collected at: ' + docker_logs_location

                    self.logger.info(
                        "Collecting all docker logs completed. Docker logs at : {0}".format(docker_logs_location))
                except Exception as e:
                    self.logger.info("Could not collect docker logs : {0}".format(str(e)))



            collected = False
            start_time = time.time()

            while should_cbcollect and not collected and time.time() < (start_time + (60 * 60)):
                self.logger.info("====== RUNNING CBCOLLECT_INFO ======")
                # command = "/opt/couchbase/bin/cbcollect_info outputfile.zip --multi-node-diag --upload-host=s3.amazonaws.com/bugdb/jira --customer=systestmon-{0}".format(
                #    timestamp)
                epoch_time = int(time.time())
                command = "/opt/couchbase/bin/couchbase-cli collect-logs-start -c {0} -u {1} -p {2} --all-nodes --upload --upload-host cb-jira.s3.us-east-2.amazonaws.com/logs --customer systestmon-{3}".format(
                    master_node, rest_username, rest_password, epoch_time)
                _, cbcollect_output, std_err = self.execute_command(
                    command, master_node, ssh_username, ssh_password)
                if std_err:
                    self.logger.error(
                        "Error seen while running cbcollect_info ")
                    self.logger.info(std_err)
                else:
                    for i in range(len(cbcollect_output)):
                        self.logger.info(cbcollect_output[i])

                while True:
                    command = "/opt/couchbase/bin/couchbase-cli collect-logs-status -c {0} -u {1} -p {2}".format(
                        master_node, rest_username, rest_password)
                    _, cbcollect_output, std_err = self.execute_command(
                        command, master_node, ssh_username, ssh_password)
                    if std_err:
                        self.logger.error(
                            "Error seen while running cbcollect_info ")
                        self.logger.info(std_err)
                        break
                    else:
                        # for i in range(len(cbcollect_output)):
                        #    print cbcollect_output[i]
                        if cbcollect_output[0] == "Status: completed":
                            cbcollect_upload_paths = []
                            for line in cbcollect_output:
                                if "url :" in line:
                                    cbcollect_upload_paths.append(line)
                            self.logger.info("cbcollect upload paths : \n")
                            self.logger.info('\n'.join(cbcollect_upload_paths))
                            message_content = message_content + '\n\ncbcollect logs: \n\n' + '\n'.join(
                                cbcollect_upload_paths)
                            # for i in range(len(cbcollect_upload_paths)):
                            #    print cbcollect_upload_paths[i]
                            collected = True
                            break
                        elif cbcollect_output[0] == "Status: running":
                            time.sleep(60)
                        elif cbcollect_output[0] == "Status: cancelled":
                            collected = False
                            break
                        else:
                            self.logger.error("Issue with cbcollect")
                            break

            self.update_state_file()

            self.logger.info(
                "====== Log scan iteration number {0} complete"
                "======".format(iter_count))
            message_sub = message_sub.join(
                "Node: {0} : Log scan iteration number {1} complete".format(master_node, iter_count))
            if should_cbcollect:
                self.send_email(message_sub, message_content, email_recipients)
                try:
                    self.store_results(message_sub, message_content)
                except Exception:
                    pass
            iter_count = iter_count + 1

            if not self.run_infinite:
                break
            if time.time() - start_time >= self.scan_interval:
                continue
            else:
                sleep_time = self.scan_interval - int(time.time() - start_time)
                self.logger.info(
                    "====== Sleeping for {0} seconds ======".format(sleep_time))
                time.sleep(sleep_time)

    def get_ssh_client(self, host, username, password):
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password, timeout=120, banner_timeout=120)
        return client

    def check_on_disk_usage(self, node):
        self.logger.info("=======" + node + "===========")
        command = "df -kh /data"
        _, df_output, std_err = self.execute_command(
            command, node, ssh_username, ssh_password)
        if std_err:
            self.logger.error(
                "Error seen while running df -kh ")
            self.logger.info(std_err)
        else:
            for i in range(len(df_output)):
                self.logger.info(df_output[i])

    def check_on_ntp_status(self, node):
        self.logger.info("=======" + node + "===========")
        command = "timedatectl status | grep NTP"
        _, df_output, std_err = self.execute_command(
            command, node, ssh_username, ssh_password)
        if std_err:
            self.logger.error(
                "Error seen while running df -kh ")
            self.logger.info(std_err)
        else:
            for i in range(len(df_output)):
                self.logger.info(df_output[i])

    def get_cluster(self, cb_host):
        try:
            cluster = Cluster('couchbase://{}'.format(cb_host))
            authenticator = PasswordAuthenticator('Administrator', 'password')
            cluster.authenticate(authenticator)
            return cluster
        except Exception:
            from couchbase.cluster import ClusterOptions
            cluster = Cluster('couchbase://{}'.format(cb_host), ClusterOptions(PasswordAuthenticator('Administrator', 'password')))
            return cluster

    def get_bucket(self, name):
        try:
            return self.cluster.open_bucket(name)
        except Exception:
            return self.cluster.bucket(name)

    def append_list(self, key, value):
        try:
            self.bucket.list_append(key, value, create=True)
        except Exception:
            self.bucket.default_collection().list_append(key, value, create=True)

    def store_results(self, message_sub, message_content):
        build_id = os.getenv("BUILD_NUMBER")
        if build_id is not None:
            key = "log_parser_results_" + build_id
            self.append_list(key, message_sub + "\n" + message_content)

    def send_email(self, message_sub, message_content, email_recipients):
        SENDMAIL = "/usr/sbin/sendmail"  # sendmail location

        FROM = "eagle-eye@couchbase.com"
        TO = email_recipients

        SUBJECT = message_sub

        TEXT = message_content

        # Prepare actual message

        message = ('From: %s\n'
                   'To: %s\n'
                   'Subject: %s\n'
                   '\n'
                   '%s\n') % (FROM, TO, SUBJECT, TEXT)

        # Send the mail
        import os

        p = os.popen("%s -t -i" % SENDMAIL, "w")
        try:
            p.write(message)
        except UnicodeEncodeError as e:
            self.logger.warn(str(e))
            p.write(message.encode("utf-8"))
        status = p.close()
        if status:
            print "Sendmail exit status", status

    def update_state_file(self):
        target = open(self.state_file, 'w')
        target.write(str(self.keyword_counts))

    def collect_dumps(self, node, component, message_content):
        goroutine_dump_name, cpupprof_dump_name, heappprof_dump_name = self.get_dumps(node, component["port"])
        message_content = message_content + '\n' + "Dump Location : " + '\n' + goroutine_dump_name + '\n' + cpupprof_dump_name + '\n' + heappprof_dump_name
        return message_content


    def check_stats_api(self, node, component, message_content):

        fin_neg_stat = []
        for stat in component["stats_api_list"]:
            stat_json = self.get_stats(stat, node, component["port"])
            neg_stat = self.check_for_negative_stat(stat_json)
            if neg_stat.__len__() != 0:
                fin_neg_stat.append(neg_stat)
            else:
                neg_stat = None
            self.logger.info(str(stat) + " : " + str(neg_stat))
            message_content = message_content + '\n' + str(stat) + " : " + str(neg_stat)

        return fin_neg_stat, message_content

    def check_for_negative_stat(self, stat_json):
        queue = deque([stat_json])
        neg_stats = []
        while queue:
            node = queue.popleft()
            nodevalue = node
            if type(node) is tuple:
                nodekey = node[0]
                nodevalue = node[1]

            if isinstance(nodevalue, Mapping):
                for k, v in nodevalue.items():
                    queue.extend([(k, v)])
            elif isinstance(nodevalue, (Sequence, Set)) and not isinstance(nodevalue, basestring):
                queue.extend(nodevalue)
            else:
                if isinstance(nodevalue, (int, long)) and nodevalue < 0 and "mutation_queue_size" not in nodekey:
                    neg_stats.append(node)

        return neg_stats

    def get_dumps(self, node, port):
        goroutine_dump_name = "{0}/{1}/goroutine_{2}".format(os.getcwd(), self.dump_dir_name, node)
        cpupprof_dump_name = "{0}/{1}/cpupprof_{2}".format(os.getcwd(), self.dump_dir_name, node)
        heappprof_dump_name = "{0}/{1}/heappprof_{2}".format(os.getcwd(), self.dump_dir_name, node)

        heap_dump_cmd = "curl http://{0}:{1}/debug/pprof/heap?debug=1 -u Administrator:password > {2}".format(node,
                                                                                                              port,
                                                                                                              heappprof_dump_name)
        cpu_dump_cmd = "curl http://{0}:{1}/debug/pprof/profile?debug=1 -u Administrator:password > {2}".format(node,
                                                                                                                port,
                                                                                                                cpupprof_dump_name)
        goroutine_dump_cmd = "curl http://{0}:{1}/debug/pprof/goroutine?debug=1 -u Administrator:password > {2}".format(
            node, port, goroutine_dump_name)

        self.logger.info(heap_dump_cmd)
        os.system(heap_dump_cmd)

        self.logger.info(cpu_dump_cmd)
        os.system(cpu_dump_cmd)

        self.logger.info(goroutine_dump_cmd)
        os.system(goroutine_dump_cmd)

        return goroutine_dump_name, cpupprof_dump_name, heappprof_dump_name

    def get_stats(self, stat, node, port):
        api = "http://{0}:{1}/{2}".format(node, port, stat)
        json_parsed = {}

        status, content, header = self._http_request(api)
        if status:
            json_parsed = json.loads(content)
            # self.logger.info(json_parsed)
        return json_parsed

    def convert_output_to_json(self, output):
        list_to_string = ''
        list_to_string = list_to_string.join(output)
        json_output = json.loads(list_to_string)
        return json_output

    def check_nodes_healthy(self, nodes, component, rest_username, rest_password, ssh_username, ssh_password):
        message_content = ''
        should_cbcollect = False
        for node in nodes:
            command = "curl http://{0}:{1}/query/service -u {2}:{3} -d 'statement=select 1'".format(node,
                                                                                                    component["port"],
                                                                                                    rest_username,
                                                                                                    rest_password)
            self.logger.info("Running curl: {0}".format(command))
            try:
                occurences, output, std_err = self.execute_command(
                    command, node, ssh_username, ssh_password)
                self.logger.info("Node:{0} Results:{1}".format(node, str(output)))
                if "Empty reply from server" in str(output) or "failed to connect" in str(output) or "timeout" in str(
                        output):
                    self.logger.error(
                        "The n1ql service appears to be unhealthy! Select 1 from node {0} failed! {1}".format(node,
                                                                                                              output))
                    should_cbcollect = True
            except Exception as e:
                self.logger.info("Found an exception {0}".format(e))
                message_content = message_content + '\n\n' + node + " : " + str(component["component"])
                message_content = message_content + '\n\n' + "Found an exception {0}".format(e) + "\n"

        return should_cbcollect, message_content

    def check_completed_requests(self, nodes, component, rest_username, rest_password, ssh_username, ssh_password):
        message_content = ''
        should_cbcollect = False
        collection_timestamp = time.time()
        collection_timestamp = datetime.fromtimestamp(collection_timestamp).strftime('%Y-%m-%dT%H:%M:%S')
        path = os.getcwd()
        file = "query_completed_requests_errors_{0}.txt".format(collection_timestamp)
        # Group the errors by the number of occurences of each distinct error message
        command = "curl http://{0}:{1}/query/service -u {2}:{3} -d 'statement=select count(errors[0].message) as errorCount, errors[0].message from system:completed_requests where errorCount > 0 group by errors[0].message'".format(
            nodes[0], component["port"], rest_username, rest_password)
        self.logger.info("Running curl: {0}".format(command))
        try:
            occurences, output, std_err = self.execute_command(
                command, nodes[0], ssh_username, ssh_password)
            # Convert the output to a json dict that we can parse
            results = self.convert_output_to_json(output)
            if results['metrics']['resultCount'] > 0:
                for result in results['results']:
                    if 'message' in result:
                        # Filter out known errors
                        # Some errors can be filtered out based on errors[0].message, add those error messages here
                        if "Timeout" in result['message'] and "exceeded" in result["message"]:
                            try:
                                self.logger.info("Error message {0} is a known error, we will skip it and remove it from completed_requests".format(result['message']))
                                command = "curl http://{0}:{1}/query/service -u {2}:{3} -d 'statement=delete from system:completed_requests where errors[0].message = \"{4}\"'".format(
                                    nodes[0], component["port"], rest_username, rest_password, result['message'])
                                self.logger.info("Running curl: {0}".format(command))
                                occurences, output, std_err = self.execute_command(
                                    command, nodes[0], ssh_username, ssh_password)
                                results = self.convert_output_to_json(output)
                            except Exception as e:
                                if "errors" in str(e):
                                    continue
                                else:
                                    self.loger.info("There was an exception {0}".format(str(e)))
                        # Some errors need to be checked out further in order to see if they need to be filtered
                        elif "Commit Transaction statement error" in result['message']:
                            try:
                                command = "curl http://{0}:{1}/query/service -u {2}:{3} -d 'statement=select * from system:completed_requests where errors[0].message = \"{4}\"'".format(
                                    nodes[0], component["port"], rest_username, rest_password, result['message'])
                                self.logger.info("Running curl: {0}".format(command))
                                occurences, output, std_err = self.execute_command(
                                    command, nodes[0], ssh_username, ssh_password)
                                # Convert the output to a json dict that we can parse
                                results = self.convert_output_to_json(output)
                                # Check the causes field for known errors, if we encounter one, remove them from completed_requests
                                for result in results['results']:
                                    if "cause" in result['errors'][0]:
                                        if "deadline expired before WWC" in result['errors'][0]['cause']['cause']['cause']:
                                            self.logger.info(
                                                "Error message {0} is a known error, we will skip it and remove it from completed_requests".format(
                                                    result['errors'][0]['cause']['cause']['cause']))
                                            command = "curl http://{0}:{1}/query/service -u {2}:{3} -d 'statement=delete from system:completed_requests where errors[0].cause.cause.cause = \"{4}\"'".format(
                                                nodes[0], component["port"], rest_username, rest_password,
                                                result['errors'][0]['cause']['cause']['cause'])
                                            self.logger.info("Running curl: {0}".format(command))
                                            occurences, output, std_err = self.execute_command(
                                                command, nodes[0], ssh_username, ssh_password)
                            except Exception as e:
                                if "errors" in str(e):
                                    continue
                                else:
                                    self.loger.info("There was an exception {0}".format(str(e)))
                            #add elifs here to mimic the above to filter more known causes of error messages
                command = "curl http://{0}:{1}/query/service -u {2}:{3} -d 'statement=select count(errors[0].message) as errorCount, errors[0].message from system:completed_requests where errorCount > 0 group by errors[0].message'".format(
                    nodes[0], component["port"], rest_username, rest_password)
                occurences, output, std_err = self.execute_command(
                    command, nodes[0], ssh_username, ssh_password)
                # Convert the output to a json dict that we can parse
                results = self.convert_output_to_json(output)
                if results['metrics']['resultCount'] > 0:
                    self.logger.info("Errors found: {0}".format(results['results']))
                    for result in results['results']:
                        if 'message' in result:
                            self.logger.info(
                                "Number of occurences of message '{0}':{1}".format(result['message'], result['errorCount']))
                            # Look for an example of each error message, and print it out timestamped
                            command = "curl http://{0}:{1}/query/service -u {2}:{3} -d 'statement=select * from system:completed_requests where errors[0].message = \"{4}\" limit 1'".format(
                                nodes[0], component["port"], rest_username, rest_password, result['message'])
                            self.logger.info("Running curl: {0}".format(command))
                            occurences, output, std_err = self.execute_command(
                                command, nodes[0], ssh_username, ssh_password)
                            # Convert the output to a json dict that we can parse
                            results = self.convert_output_to_json(output)
                            self.logger.info(
                                "Sample result for error message '{0}' at time {1}: {2}".format(result['message'],
                                                                                                results['results'][0][
                                                                                                    'completed_requests'][
                                                                                                    'requestTime'],
                                                                                                results['results']))
                            # Update message_content to show errors were found
                            message_content = message_content + '\n\n' + nodes[0] + " : " + str(component["component"])
                            message_content = message_content + '\n\n' + "Sample result for error message '{0}' at time {1}: {2}".format(result['message'],
                                                                                                results['results'][0][
                                                                                                    'completed_requests'][
                                                                                                    'requestTime'],
                                                                                                results['results']) + "\n"
                    # Get the entire completed_requests errors and dump them to a file
                    command = "curl http://{0}:{1}/query/service -u {2}:{3} -d 'statement=select * from system:completed_requests where errorCount > 0 order by requestTime desc'".format(
                        nodes[0], component["port"], rest_username, rest_password)
                    self.logger.info("Running curl: {0}".format(command))
                    try:
                        occurences, output, std_err = self.execute_command(
                            command, nodes[0], ssh_username, ssh_password)
                        # Convert the output to a json dict that we can parse
                        results = self.convert_output_to_json(output)
                        # If there are results store the results in a file
                        if results['metrics']['resultCount'] > 0:
                            self.logger.info("We found errors in completed requests, storing errors to a file")
                            with open(os.path.join(path, file), 'w') as fp:
                                json.dump(results, fp, indent=4)
                                fp.close()
                            zipname = path + "/query_completed_requests_errors_{0}.zip".format(
                                collection_timestamp)
                            zipfile.ZipFile(zipname, mode='w').write(file)
                            os.remove(file)
                            file = file.replace(".txt", ".zip")
                            self.logger.info(
                                "Errors from completed_requests stored at {0}/{1}".format(path, file))
                            self.logger.info(
                                "After storing competed_requests_errors we will delete them from the server")

                            command = "curl http://{0}:{1}/query/service -u {2}:{3} -d 'statement=delete from system:completed_requests where errorCount > 0'".format(
                                nodes[0], component["port"], rest_username, rest_password)
                            self.logger.info("Running curl: {0}".format(command))
                            occurences, output, std_err = self.execute_command(
                                command, nodes[0], ssh_username, ssh_password)
                            should_cbcollect = True
                    except Exception as e:
                        self.logger.info("Found an exception {0}".format(e))
                        message_content = message_content + '\n\n' + nodes[0] + " : " + str(component["component"])
                        message_content = message_content + '\n\n' + "Found an exception {0}".format(e) + "\n"

        except Exception as e:
            self.logger.info("Found an exception {0}".format(e))
            message_content = message_content + '\n\n' + nodes[0] + " : " + str(component["component"])
            message_content = message_content + '\n\n' + "Found an exception {0}".format(e) + "\n"

        return should_cbcollect, message_content

    def check_active_requests(self, nodes, component, rest_username, rest_password, ssh_username, ssh_password):
        message_content = ''
        should_cbcollect = False
        collection_timestamp = time.time()
        collection_timestamp = datetime.fromtimestamp(collection_timestamp).strftime('%Y-%m-%dT%H:%M:%S')
        path = os.getcwd()
        file = "query_active_requests_{0}.txt".format(collection_timestamp)
        command = "curl http://{0}:{1}/query/service -u {2}:{3} -d 'statement=select * from system:active_requests'".format(
            nodes[0], component["port"], rest_username, rest_password)
        self.logger.info("Running curl: {0}".format(command))
        try:
            occurences, output, std_err = self.execute_command(
                command, nodes[0], ssh_username, ssh_password)
            # Convert the output to a json dict that we can parse
            results = self.convert_output_to_json(output)
            # If there are results store the results in a file
            if results['metrics']['resultCount'] > 1000:
                self.logger.info(
                    "There are more than 1000 queries running at time {0}, this should not be the case. Storing active_requests for further review".format(collection_timestamp))
                message_content = message_content + '\n\n' + nodes[0] + " : " + str(component["component"])
                message_content = message_content + '\n\n' + "There are more than 1000 queries running at time {0}, this should not be the case. Storing active_requests for further review".format(collection_timestamp) + "\n"
                with open(os.path.join(path, file), 'w') as fp:
                    json.dump(results, fp, indent=4)
                    fp.close()
                zipname = path + "/query_active_requests_{0}.zip".format(collection_timestamp)
                zipfile.ZipFile(zipname, mode='w').write(file)
                os.remove(file)
                file = file.replace(".txt", ".zip")
                self.logger.info("Active requests stored at {0}/{1}".format(path, file))
                should_cbcollect = True
        except Exception as e:
            self.logger.info("Found an exception {0}".format(e))
            message_content = message_content + '\n\n' + nodes[0] + " : " + str(component["component"])
            message_content = message_content + '\n\n' + "Found an exception {0}".format(e) + "\n"

        return should_cbcollect, message_content

    def get_xdcr_src_buckets(self, node):
        src_buckets = []
        api = "http://" + node + ":8091/pools/default/replications"
        status, content, _ = self._http_request(api)
        repls =  json.loads(content)
        for repl in repls:
            src_buckets.append(repl["source"])
        return src_buckets

    def fetch_bucket_xdcr_stats(self, node, bucket, zoom="day"):
        api = "http://" + node + ":8091/pools/default/buckets/@xdcr-{0}/stats?zoom={1}".format(bucket, zoom)
        status, content, _ = self._http_request(api)
        return json.loads(content)


    def _create_headers(self):
        authorization = base64.encodestring('%s:%s' % ("Administrator", "password"))
        return {'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic %s' % authorization,
                'Accept': '*/*'}

    def _get_auth(self, headers):
        key = 'Authorization'
        if key in headers:
            val = headers[key]
            if val.startswith("Basic "):
                return "auth: " + base64.decodestring(val[6:])
        return ""

    def _http_request(self, api, method='GET', params='', headers=None, timeout=120):
        if not headers:
            headers = self._create_headers()
        end_time = time.time() + timeout
        self.logger.info("Executing {0} request for following api {1}".format(method, api))
        count = 1
        while True:
            try:
                response, content = httplib2.Http(timeout=timeout).request(api, method,
                                                                           params, headers)
                if response['status'] in ['200', '201', '202']:
                    return True, content, response
                else:
                    try:
                        json_parsed = json.loads(content)
                    except ValueError as e:
                        json_parsed = {}
                        json_parsed["error"] = "status: {0}, content: {1}" \
                            .format(response['status'], content)
                    reason = "unknown"
                    if "error" in json_parsed:
                        reason = json_parsed["error"]
                    message = '{0} {1} body: {2} headers: {3} error: {4} reason: {5} {6} {7}'. \
                        format(method, api, params, headers, response['status'], reason,
                               content.rstrip('\n'), self._get_auth(headers))
                    self.logger.error(message)
                    self.logger.debug(''.join(traceback.format_stack()))
                    return False, content, response
            except socket.error as e:
                if count < 4:
                    self.logger.error("socket error while connecting to {0} error {1} ".format(api, e))
                if time.time() > end_time:
                    self.logger.error("Tried ta connect {0} times".format(count))
                    raise Exception()
            except httplib2.ServerNotFoundError as e:
                if count < 4:
                    self.logger.error("ServerNotFoundError error while connecting to {0} error {1} " \
                                      .format(api, e))
                if time.time() > end_time:
                    self.logger.error("Tried ta connect {0} times".format(count))
                    raise Exception()
            time.sleep(3)
            count += 1

    def print_output(self, output, last_scan_timestamp, message_content):
        for line in output:
            match = re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', line)
            if match:
                timestamp_in_log = datetime.strptime(match.group(), '%Y-%m-%dT%H:%M:%S')
                if timestamp_in_log >= last_scan_timestamp and self.check_op_in_ignorelist(line):
                    self.logger.debug(line)
                    message_content = message_content + '\n' + line
            else:
                self.logger.debug(line)
                message_content = message_content + '\n' + line
                if line.strip() not in self.ignore_list:
                    self.ignore_list.append(line.strip())

        return message_content

    def check_op_in_ignorelist(self, line):
        for ignore_text in self.ignore_list:
            if ignore_text in line:
                return False
        return True

    def get_services_map(self, master, rest_username, rest_password):
        cluster_url = "http://" + master + ":8091/pools/default"
        node_map = []
        retry_count = 5
        while retry_count:
            try:
                # Get map of nodes in the cluster
                status, content, header = self._http_request(cluster_url)

                if status:
                    response = json.loads(str(content))

                    for node in response["nodes"]:
                        clusternode = {}
                        clusternode["hostname"] = node["hostname"].replace(":8091", "")
                        clusternode["services"] = node["services"]
                        mem_used = int(node["memoryTotal"]) - int(node["memoryFree"])
                        if node["memoryTotal"]:
                            clusternode["memUsage"] = round(
                                float(float(mem_used) / float(node["memoryTotal"]) * 100), 2)
                        else:
                            clusternode["memUsage"] = 0
                        clusternode["cpuUsage"] = round(
                            node["systemStats"]["cpu_utilization_rate"], 2)
                        clusternode["status"] = node["status"]
                        node_map.append(clusternode)

                    break
            except Exception, e:
                self.logger.info("Found an exception {0}".format(e))
                self.logger.info(status)
                self.logger.info(content)
                node_map = None

            time.sleep(300)
            retry_count -= 1
        return node_map

    def find_nodes_with_service(self, node_map, service):
        nodelist = []
        for node in node_map:
            if service == "all":
                nodelist.append(node["hostname"])
            else:
                if service in node["services"]:
                    nodelist.append(node["hostname"])
        return nodelist

    def wait_for_cluster_init(self, master_node):
        cluster_url = "http://" + master_node + ":8091/pools/default"
        while True:
            self.logger.info("Waiting for cluster {} init".format(master_node))
            try:
                status, content, _ = self._http_request(cluster_url)
                if status:
                    response = json.loads(content)
                    if all([node["clusterMembership"] == "active" for node in response["nodes"]]):
                        return
            except Exception:
                pass
            time.sleep(10)

    def execute_command(self, command, hostname, ssh_username, ssh_password):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=ssh_username, password=ssh_password,
                    timeout=120, banner_timeout=120)

        channel = ssh.get_transport().open_session()
        channel.get_pty()
        channel.settimeout(900)
        stdin = channel.makefile('wb')
        stdout = channel.makefile('rb')
        stderro = channel.makefile_stderr('rb')

        channel.exec_command(command)
        data = channel.recv(1024)
        temp = ""
        while data:
            temp += data
            data = channel.recv(1024)
        channel.close()
        stdin.close()

        output = []
        error = []
        for line in stdout.read().splitlines():
            if "No such file or directory" not in line:
                output.append(line)
        for line in stderro.read().splitlines():
            error.append(line)
        if temp:
            line = temp.splitlines()
            output.extend(line)
        stdout.close()
        stderro.close()

        # self.logger.info("Executing on {0}: {1}".format(hostname, command))
        # ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)

        # output = ""
        # while not ssh_stdout.channel.exit_status_ready():
        #    # Only print data if there is data to read in the channel
        #    if ssh_stdout.channel.recv_ready():
        #        rl, wl, xl = select.select([ssh_stdout.channel], [], [], 0.0)
        #        if len(rl) > 0:
        #            tmp = ssh_stdout.channel.recv(1024)
        #            output += tmp.decode()

        # output = output.split("\n")

        ssh.close()

        # return len(output) - 1, output, ssh_stderr
        return len(output), output, error


if __name__ == '__main__':
    master_node = sys.argv[1]
    rest_username = sys.argv[2]
    rest_password = sys.argv[3]
    ssh_username = sys.argv[4]
    ssh_password = sys.argv[5]
    cbcollect_on_high_mem_cpu_usage = sys.argv[6]
    print_all_logs = sys.argv[7]
    email_recipients = sys.argv[8]
    state_file_dir = sys.argv[9]
    run_infinite = sys.argv[10]
    logger = ast.literal_eval(sys.argv[11])
    should_collect_dumps = sys.argv[12]
    docker_host = sys.argv[13]
    try:
        cb_host = sys.argv[14]
    except IndexError:
        cb_host = "172.23.104.178"
    SysTestMon().run(master_node, rest_username, rest_password, ssh_username, ssh_password,
                     cbcollect_on_high_mem_cpu_usage, print_all_logs, email_recipients, state_file_dir, run_infinite,
                     logger, should_collect_dumps, docker_host, cb_host)
