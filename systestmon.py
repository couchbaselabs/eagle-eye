import argparse
import json
import logging
import re
from datetime import datetime, timedelta
from threading import Thread

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
from collections import Mapping, Sequence, Set, deque

from scp import SCPClient


class Globals(object):
    logger = logging.getLogger("systestmon")
    timestamp = str(datetime.now().strftime('%Y-%m-%dT%H:%M:%S'))
    sdk_client = None


class SDKClient(object):
    def __init__(self, cb_host):
        try:
            self.cluster = self.get_cluster(cb_host)
            self.bucket = self.get_bucket("system_test_dashboard")
        except Exception as e:
            print("SDK WARNING: %s" % e)

    def append_list(self, key, value):
        try:
            self.bucket.list_append(key, value, create=True)
        except Exception:
            self.bucket.default_collection().list_append(key, value, create=True)

    def store_results(self, msg_sub, msg_content):
        build_id = os.getenv("BUILD_NUMBER")
        if build_id is not None:
            key = "log_parser_results_" + build_id
            self.append_list(key, msg_sub + "\n" + msg_content)

    def get_cluster(self, cb_host):
        try:
            cluster = Cluster('couchbase://{}'.format(cb_host))
            authenticator = PasswordAuthenticator('Administrator', 'password')
            cluster.authenticate(authenticator)
            return cluster
        except Exception:
            from couchbase.cluster import ClusterOptions
            cluster = Cluster(
                'couchbase://{}'.format(cb_host),
                ClusterOptions(PasswordAuthenticator('Administrator',
                                                     'password')))
            return cluster

    def get_bucket(self, name):
        try:
            return self.cluster.open_bucket(name)
        except Exception:
            return self.cluster.bucket(name)


class Configuration(object):
    # Input map of keywords to be mined for in the logs
    configuration = [
        {
            "component": "memcached",
            "logfiles": "babysitter.log*",
            "services": "all",
            "keywords": ["exception occurred in runloop",
                         "failover exited with reason",
                         "Basic\s[a-zA-Z]\{10,\}",
                         "Menelaus-Auth-User:\["],
            "ignore_keywords": None,
            "check_stats_api": False,
            "collect_dumps": False
        },
        {
            "component": "memcached",
            "logfiles": "memcached.log.*",
            "services": "all",
            "keywords": ["CRITICAL", "Basic\s[a-zA-Z]\{10,\}",
                         "Menelaus-Auth-User:\[",
                         "exception occurred in runloop",
                         "Invalid packet header detected"],
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

    ignore_list = ["Port exited with status 0", "Fatal:false",
                   "HyracksDataException: HYR0115: Local network error",
                   "No such file or directory"]


class ScriptConfig(object):
    print_all_logs = False
    should_collect_dumps = False
    cbcollect_on_high_mem_cpu_usage = False
    scan_xdcr_destination = False

    docker_host = None
    email_recipients = ""
    state_file_dir = ""


class CBCluster(object):
    def __init__(self, cluster_name, master_node, rest_username, rest_password,
                 ssh_username, ssh_password):
        self.cluster_name = cluster_name
        self.master_node = master_node
        self.rest_username = rest_username
        self.rest_password = rest_password
        self.ssh_username = ssh_username
        self.ssh_password = ssh_password


class SysTestMon(object):
    # 1. Get service map for cluster
    # 2. For each component, get nodes for the requested service
    # 3. SSH to those nodes, grep for specified keywords in specified files
    # 4. Reporting

    def __init__(self, cluster, run_infinite, start_itr=1):
        self.logger = Globals.logger
        self.cluster = cluster
        self.run_infinite = run_infinite
        self.state_file = "{}/eagle-eye_{}.state" \
            .format(ScriptConfig.state_file_dir, cluster.master_node)

        self.keyword_counts = dict()
        self.keyword_counts["timestamp"] = Globals.timestamp

        self.dump_dir_name = ""
        self.docker_logs_dump = ""
        self.iter_count = start_itr
        self.token = None

    @staticmethod
    def append_msg_string(msg_text, file_text, msg_to_append):
        truncated = False
        file_text = file_text + msg_to_append
        msg_to_append = msg_to_append.split("\n")
        if len(msg_to_append) > 11:
            truncated = True
            msg_to_append = msg_to_append[:10]
        msg_to_append = "\n".join(msg_to_append)
        msg_to_append += "...[truncated]\n" if truncated else "\n"
        msg_text = msg_text + msg_to_append
        return msg_text, file_text

    def run(self):
        self.wait_for_cluster_init(self.cluster.master_node)
        last_scan_timestamp = ""
        xdcr_monitor_threads = list()
        while True:
            msg_sub = ""
            msg_content = ""
            file_content = ""
            should_cbcollect = False
            prev_keyword_counts = None
            self.dump_dir_name = "dump_collected_{}".format(self.iter_count)
            # Used to identify the current itr uniquely
            self.token = int(time.time())

            if os.path.exists(self.state_file):
                s = open(self.state_file, 'r').read()
                prev_keyword_counts = ast.literal_eval(s)
                last_scan_timestamp = datetime.strptime(
                    prev_keyword_counts["last_scan_timestamp"],
                    "%Y-%m-%d %H:%M:%S.%f")

            if not os.path.isdir(self.dump_dir_name):
                os.mkdir(self.dump_dir_name)
            node_map = self.get_services_map(self.cluster.master_node,
                                             self.cluster.rest_username,
                                             self.cluster.rest_password)
            if not node_map:
                continue

            if ScriptConfig.scan_xdcr_destination:
                for x_index, xdcr_ip in enumerate(self.get_xdcr_dest(self.cluster.master_node)):
                    self.logger.info("Starting XDCR log collection for {}"
                                     .format(xdcr_ip))
                    xdcr_cluster = CBCluster(
                        "xdcr_cluster_%s" % x_index, xdcr_ip,
                        self.cluster.rest_username, self.cluster.rest_password,
                        self.cluster.ssh_username, self.cluster.ssh_password)
                    t_sysmon_obj = SysTestMon(xdcr_cluster, False,
                                              start_itr=self.iter_count)
                    t_thread = Thread(name="XDCR_{}_thread".format(xdcr_ip),
                                      target=t_sysmon_obj.run)
                    xdcr_monitor_threads.append(t_thread)
                    t_thread.start()

            for component in Configuration.configuration:
                nodes = self.find_nodes_with_service(node_map,
                                                     component["services"])
                self.logger.info("{} ({}) - Nodes with {} service : {}"
                                 .format(self.cluster.master_node,
                                         self.cluster.cluster_name,
                                         component["services"], str(nodes)))
                for keyword in component["keywords"]:
                    key = component["component"] + "_" + keyword
                    self.logger.info(
                        "{} ({}) - Parsing for component: {}, looking for '{}'"
                        .format(self.cluster.master_node,
                                self.cluster.cluster_name,
                                component["component"], keyword))
                    total_occurrences = 0

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
                                command, node, self.cluster.ssh_username,
                                self.cluster.ssh_password)
                        except Exception as e:
                            self.logger.info("Exception {0}".format(e))

                            txt = '\n\n%s: %s\n\n ' \
                                  'Found an exception: %s' \
                                  % (node, component["component"], e)
                            msg_content, file_content = \
                                self.append_msg_string(msg_content,
                                                       file_content, txt)
                        if occurences > 0:
                            self.logger.warning(
                                "{} - {} occurrences of keyword '{}' found"
                                .format(node, occurences, keyword))
                            txt = "\n\n%s: %s" % (node, component["component"])
                            if ScriptConfig.print_all_logs \
                                    or last_scan_timestamp == "":
                                try:
                                    self.logger.debug('\n'.join(output))
                                    txt += "\n%s" % ('\n'.join(output))
                                except UnicodeDecodeError as e:
                                    self.logger.warning(str(e))
                                    txt += "\n%s" % ('\n'.join(output)
                                                     .decode("utf-8"))
                            else:
                                txt = self.print_output(output, last_scan_timestamp, txt)
                            msg_content, file_content = \
                                self.append_msg_string(msg_content,
                                                       file_content, txt)
                        total_occurrences += occurences

                    self.keyword_counts[key] = total_occurrences
                    if prev_keyword_counts is not None \
                            and key in prev_keyword_counts.keys():
                        if total_occurrences > int(prev_keyword_counts[key]):
                            self.logger.warning(
                                "There have been more occurences of keyword {0} "
                                "in the logs since the last iteration. Hence "
                                "performing a cbcollect.".format(keyword))
                            should_cbcollect = True
                    else:
                        if total_occurrences > 0:
                            should_cbcollect = True

                for node in nodes:
                    if component["check_stats_api"]:
                        txt = '\n\n%s: %s' % (node, component["component"])
                        try:
                            fin_neg_stat, txt = self.check_stats_api(node, component, txt)
                            if fin_neg_stat.__len__() != 0:
                                should_cbcollect = True
                        except Exception as e:
                            self.logger.info("Found an exception {0}".format(e))
                        msg_content, file_content = \
                            self.append_msg_string(msg_content,
                                                   file_content, txt)

                    if component["collect_dumps"] and ScriptConfig.should_collect_dumps:
                        txt = '\n\n%s: %s collecting dumps' % (node, component["component"])
                        try:
                            txt = self.collect_dumps(node, component, txt)
                        except Exception as e:
                            self.logger.info("Found an exception {0}".format(e))
                        msg_content, file_content = \
                            self.append_msg_string(msg_content,
                                                   file_content, txt)

                # Check if all n1ql nodes are healthy
                if component["component"] == "query":
                    n1ql_nodes = self.find_nodes_with_service(node_map, "n1ql")
                    if n1ql_nodes:
                        # Check to make sure all nodes are healthy
                        self.logger.info("Checking query nodes for health")
                        should_collect, message = self.check_nodes_healthy(
                            nodes=nodes, component=component,
                            rest_username=self.cluster.rest_username,
                            rest_password=self.cluster.rest_password,
                            ssh_username=self.cluster.ssh_username,
                            ssh_password=self.cluster.ssh_password)
                        if should_collect:
                            should_cbcollect = True
                        if not message == '':
                            txt = '\n\n%s: %s\n\n%s\n' \
                                  % (node, component["component"], message)
                            msg_content, file_content = \
                                self.append_msg_string(msg_content,
                                                       file_content, txt)
                        # Check system:completed_requests for errors
                        self.logger.info("Checking system:completed requests for errors")
                        should_collect, message = self.check_completed_requests(
                            nodes=nodes, component=component,
                            rest_username=self.cluster.rest_username,
                            rest_password=self.cluster.rest_password,
                            ssh_username=self.cluster.ssh_username,
                            ssh_password=self.cluster.ssh_password)
                        if should_collect:
                            should_cbcollect = True
                        if not message == '':
                            txt = '\n\n%s: %s\n\n%s\n' \
                                  % (node, component["component"], message)
                            msg_content, file_content = \
                                self.append_msg_string(msg_content,
                                                       file_content, txt)
                        # Check active_requests to make sure that are no more than 1k active requests at a single time
                        self.logger.info("Checking system:active requests for too many requests")
                        should_collect, message = self.check_active_requests(
                            nodes=nodes, component=component,
                            rest_username=self.cluster.rest_username,
                            rest_password=self.cluster.rest_password,
                            ssh_username=self.cluster.ssh_username,
                            ssh_password=self.cluster.ssh_password)
                        if should_collect:
                            should_cbcollect = True
                        if not message == '':
                            txt = '\n\n%s: %s\n\n%s\n' \
                                  % (node, component["component"], message)
                            msg_content, file_content = \
                                self.append_msg_string(msg_content,
                                                       file_content, txt)

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
                if node["memUsage"] > Configuration.mem_threshold:
                    self.logger.warning(
                        "***** ALERT : Memory usage on {0} is very high : {1}%"
                        .format(node["hostname"], node["memUsage"]))
                    # if cbcollect_on_high_mem_cpu_usage:
                    #    should_cbcollect = True

                if node["cpuUsage"] > Configuration.cpu_threshold:
                    self.logger.warning(
                        "***** ALERT : CPU usage on {0} is very high : {1}%"
                        .format(node["hostname"], node["cpuUsage"]))
                    # if cbcollect_on_high_mem_cpu_usage:
                    #    should_cbcollect = True

                if node["status"] != "healthy":
                    self.logger.warning(
                        "***** ALERT: {0} is not healthy. Current status: {1}%"
                        .format(node["hostname"], node["status"]))
                    if ScriptConfig.cbcollect_on_high_mem_cpu_usage:
                        should_cbcollect = True

                # Check NTP status
                # command = "timedatectl status | grep NTP"
                # self.record_command_output(node["hostname"], command)

                # Check disk usage
                command = "df -kh /data"
                self.record_command_output(node["hostname"], command)

            last_scan_timestamp = datetime.now() - timedelta(minutes=10.0)
            self.logger.info("Last scan timestamp:" + str(last_scan_timestamp))
            self.keyword_counts["last_scan_timestamp"] = str(last_scan_timestamp)

            if ScriptConfig.docker_host is not None:
                try:
                    command = "docker ps -q | xargs docker inspect --format {{.LogPath}}"
                    occurences, output, std_err = self.execute_command(
                        command, ScriptConfig.docker_host,
                        self.cluster.ssh_username, self.cluster.ssh_password)
                    self.docker_logs_dump = "docker_dump_collected_" + str(self.iter_count) \
                                            + "_" + str(datetime.now().strftime('%Y-%m-%dT%H:%M:%S'))
                    os.mkdir(self.docker_logs_dump)

                    ssh_client = self.get_ssh_client(
                        ScriptConfig.docker_host, self.cluster.ssh_username,
                        self.cluster.ssh_password)

                    for file in output:
                        with SCPClient(ssh_client.get_transport()) as scp:
                            scp.get(file, local_path=self.docker_logs_dump)

                    docker_logs_location = "{0}/{1}".format(os.getcwd(), self.docker_logs_dump)
                    txt = "\n\nDocker logs collected at: %s" % docker_logs_location
                    msg_content, file_content = \
                        self.append_msg_string(msg_content,
                                               file_content, txt)
                    self.logger.info("Collecting all docker logs completed. "
                                     "Docker logs at : {0}"
                                     .format(docker_logs_location))
                except Exception as e:
                    self.logger.info("Could not collect docker logs: %s" % e)

            collected = False
            cbcollect_urls = ""
            start_time = time.time()
            time_out_val = start_time + 3600

            while should_cbcollect and not collected \
                    and time.time() < time_out_val:
                self.logger.info("{} ({}) :: Running cbcollect_info"
                                 .format(self.cluster.master_node,
                                         self.cluster.cluster_name))
                command = \
                    "/opt/couchbase/bin/couchbase-cli collect-logs-start " \
                    "-c {0} -u {1} -p {2} --all-nodes --upload " \
                    "--upload-host cb-jira.s3.us-east-2.amazonaws.com/logs " \
                    "--customer systestmon-{3}"\
                    .format(self.cluster.master_node,
                            self.cluster.rest_username,
                            self.cluster.rest_password, self.token)
                _, cbcollect_output, std_err = self.execute_command(
                    command, self.cluster.master_node,
                    self.cluster.ssh_username, self.cluster.ssh_password)
                if std_err:
                    self.logger.error("Error while running cbcollect_info")
                    self.logger.info(std_err)
                else:
                    for i in range(len(cbcollect_output)):
                        self.logger.info(cbcollect_output[i])

                while True:
                    command = "/opt/couchbase/bin/couchbase-cli " \
                        "collect-logs-status -c {0} -u {1} -p {2}"\
                        .format(self.cluster.master_node,
                                self.cluster.rest_username,
                                self.cluster.rest_password)
                    _, cbcollect_output, std_err = self.execute_command(
                        command, self.cluster.master_node,
                        self.cluster.ssh_username, self.cluster.ssh_password)
                    if std_err:
                        self.logger.error("cbcollect_info error: %s" % std_err)
                        break
                    else:
                        if cbcollect_output[0] == "Status: running":
                            time.sleep(60)
                        elif cbcollect_output[0] == "Status: completed":
                            collected = True
                            cbcollect_upload_paths = list()
                            for line in cbcollect_output:
                                if "url :" in line:
                                    cbcollect_upload_paths.append(line)
                            cbcollect_urls = "\nCbcollect logs:\n\n%s" \
                                % ('\n'.join(cbcollect_upload_paths))
                            self.logger.info(cbcollect_urls)
                            break
                        elif cbcollect_output[0] == "Status: cancelled":
                            collected = False
                            cbcollect_upload_paths = list()
                            for line in cbcollect_output:
                                if "url :" in line:
                                    cbcollect_upload_paths.append(line)
                            cbcollect_urls = "\nCbcollect logs:\n\n%s" \
                                % ('\n'.join(cbcollect_upload_paths))
                            self.logger.info(cbcollect_urls)
                            break
                        else:
                            self.logger.error("Issue with cbcollect: %s"
                                              % cbcollect_output)
                            break
            self.update_state_file()

            txt = "{} ({}): Log scan iteration number {} complete" \
                .format(self.cluster.master_node,
                        self.cluster.cluster_name, self.iter_count)
            msg_sub = msg_sub.join(txt)
            if should_cbcollect:
                try:
                    msg_content += cbcollect_urls
                    file_content += cbcollect_urls
                    self.send_email(msg_sub, ScriptConfig.email_recipients,
                                    msg_content, file_content)
                except Exception as e:
                    self.logger.critical("Send mail exception: %s" % e)
                try:
                    Globals.sdk_client.store_results(msg_sub, msg_content)
                except Exception:
                    pass
            self.logger.info("========== %s ==========" % txt)

            if ScriptConfig.scan_xdcr_destination:
                for t_thread in xdcr_monitor_threads:
                    t_thread.join(1800)

            if not self.run_infinite:
                break
            self.iter_count = self.iter_count + 1

            if time.time() - start_time >= Configuration.scan_interval:
                continue
            else:
                sleep_time = Configuration.scan_interval \
                             - int(time.time() - start_time)
                self.logger.info("====== Sleeping for {0} seconds ======"
                                 .format(sleep_time))
                time.sleep(sleep_time)

    def get_ssh_client(self, host, username, password):
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password,
                       timeout=120, banner_timeout=120)
        return client

    def record_command_output(self, node, command):
        self.logger.info("{} :: Running '{}'".format(node, command))
        try:
            _, df_output, std_err = self.execute_command(
                command, node, self.cluster.ssh_username,
                self.cluster.ssh_password)
            if std_err:
                self.logger.error("std error while running '%s': %s"
                                  % (command, std_err))
            else:
                for i in range(len(df_output)):
                    self.logger.info(df_output[i])
        except Exception as e:
            self.logger.error(e)

    def send_email(self, msg_sub, email_recipients, msg_content, file_content):
        attachment = ""
        mail_from = "Eagle-Eye<eagle-eye@couchbase.com>"
        t_file_prefix = "/tmp/iter_{}_{}_{}"\
            .format(self.iter_count, self.cluster.master_node, self.token)

        # Dump the email body to file
        with open("{}_body.log".format(t_file_prefix), "w") as fp:
            fp.write(msg_content.strip())

        if file_content:
            # Dump full logs into file for attachment
            with open("{}.log".format(t_file_prefix), "w") as fp:
                fp.write(file_content.strip())

            # Zip the logs to compress
            p = os.popen("zip -jFSr {0}.zip {0}.log".format(t_file_prefix))
            status = p.close()
            if status:
                self.logger.info("Zip status: {}".format(status))

            attachment = "-a \"{0}.zip\"".format(t_file_prefix)

        # Send mail
        cmd = "mailx -s \"{}\" {} -r \"{}\" \"{}\" < \"{}_body.log\"" \
              .format(msg_sub, attachment, mail_from,
                      email_recipients, t_file_prefix)
        self.logger.info("Sending mail: %s" % cmd)
        p = os.popen(cmd)
        status = p.close()
        if status:
            self.logger.info("Sendmail exit status: {}".format(status))

        # Cleanup tmp files only if mail sent
        if status is None:
            p = os.popen("rm -f {}*".format(t_file_prefix))
            status = p.close()
            if status:
                self.logger.info("Del .log file status: {}".format(status))

    def update_state_file(self):
        target = open(self.state_file, 'w')
        target.write(str(self.keyword_counts))

    def collect_dumps(self, node, component, msg_content):
        goroutine_dump_name, cpupprof_dump_name, heappprof_dump_name = \
            self.get_dumps(node, component["port"])
        msg_content = msg_content + '\n' + "Dump Location : " + '\n' \
                      + goroutine_dump_name + '\n' + cpupprof_dump_name \
                      + '\n' + heappprof_dump_name
        return msg_content

    def check_stats_api(self, node, component, msg_content):
        fin_neg_stat = []
        for stat in component["stats_api_list"]:
            stat_json = self.get_stats(stat, node, component["port"])
            neg_stat = self.check_for_negative_stat(stat_json)
            if neg_stat.__len__() != 0:
                fin_neg_stat.append(neg_stat)
            else:
                neg_stat = None
            self.logger.info(str(stat) + " : " + str(neg_stat))
            msg_content = msg_content + '\n' + str(stat) + " : " + str(neg_stat)

        return fin_neg_stat, msg_content

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

        heap_dump_cmd = "curl http://{0}:{1}/debug/pprof/heap?debug=1 " \
                        "-u Administrator:password > {2}"\
                        .format(node, port, heappprof_dump_name)
        cpu_dump_cmd = "curl http://{0}:{1}/debug/pprof/profile?debug=1 " \
                       "-u Administrator:password > {2}"\
                       .format(node, port, cpupprof_dump_name)
        goroutine_dump_cmd = "curl http://{0}:{1}/debug/pprof/goroutine?debug=1 " \
                             "-u Administrator:password > {2}"\
                             .format(node, port, goroutine_dump_name)

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

        status, content, _ = self._http_request(api)
        if status:
            json_parsed = json.loads(content)
        return json_parsed

    def convert_output_to_json(self, output):
        list_to_string = ''
        list_to_string = list_to_string.join(output)
        json_output = json.loads(list_to_string)
        return json_output

    def check_nodes_healthy(self, nodes, component, rest_username, rest_password, ssh_username, ssh_password):
        msg_content = ''
        should_cbcollect = False
        for node in nodes:
            command = "curl http://{0}:{1}/query/service -u {2}:{3} " \
                      "-d 'statement=select 1'"\
                      .format(node, component["port"], rest_username,
                              rest_password)
            self.logger.info("Running curl: {0}".format(command))
            try:
                occurences, output, std_err = self.execute_command(
                    command, node, ssh_username, ssh_password)
                self.logger.info("Node:{0} Results:{1}".format(node, str(output)))
                if "Empty reply from server" in str(output) \
                        or "failed to connect" in str(output) \
                        or "timeout" in str(output):
                    self.logger.error(
                        "The n1ql service appears to be unhealthy! "
                        "Select 1 from node {0} failed! {1}"
                        .format(node, output))
                    should_cbcollect = True
            except Exception as e:
                self.logger.info("Found an exception {0}".format(e))
                msg_content = msg_content + '\n\n' + node + " : " + str(component["component"])
                msg_content = msg_content + '\n\n' + "Found an exception {0}".format(e) + "\n"
        return should_cbcollect, msg_content

    def check_completed_requests(self, nodes, component, rest_username,
                                 rest_password, ssh_username, ssh_password):
        msg_content = ''
        should_cbcollect = False
        collection_timestamp = time.time()
        collection_timestamp = datetime.fromtimestamp(collection_timestamp).strftime('%Y-%m-%dT%H:%M:%S')
        path = os.getcwd()
        file = "query_completed_requests_errors_{0}.txt".format(collection_timestamp)
        # Group the errors by the number of occurences of each distinct error message
        command = "curl http://{0}:{1}/query/service -u {2}:{3} " \
                  "-d 'statement=select count(errors[0].message) " \
                  "as errorCount, errors[0].message from system:completed_requests " \
                  "where errorCount > 0 group by errors[0].message'"\
                  .format(nodes[0], component["port"], rest_username,
                          rest_password)
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
                                    self.logger.info("There was an exception {0}".format(str(e)))
                        # Some errors need to be checked out further in order to see if they need to be filtered
                        elif "Commit Transaction statement error" in result['message']:
                            try:
                                command = "curl http://{0}:{1}/query/service -u {2}:{3} -d 'statement=select * from system:completed_requests where errors[0].message = \"{4}\"'".format(
                                    nodes[0], component["port"], rest_username, rest_password, result['message'])
                                self.logger.info("{} - Running curl: {0}".format(nodes[0], command))
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
                                            self.logger.info("{} - Running curl: {}".format(nodes[0], command))
                                            _, _, _ = self.execute_command(
                                                command, nodes[0],
                                                ssh_username, ssh_password)
                            except Exception as e:
                                if "errors" in str(e):
                                    continue
                                else:
                                    self.logger.info("There was an exception {0}".format(str(e)))
                            # add elifs here to mimic the above to filter more known causes of error messages
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
                                "Sample result for error message '{0}' at time {1}: {2}"
                                .format(result['message'],
                                        results['results'][0]['completed_requests']['requestTime'],
                                        results['results']))
                            # Update msg_content to show errors were found
                            msg_content = msg_content + '\n\n' + nodes[0] + " : " + str(component["component"])
                            msg_content = msg_content + '\n\n' + "Sample result for error message '{0}' at time {1}: {2}".format(result['message'],
                                                                                                results['results'][0][
                                                                                                    'completed_requests'][
                                                                                                    'requestTime'],
                                                                                                results['results']) + "\n"
                    # Get the entire completed_requests errors and dump them to a file
                    command = "curl http://{0}:{1}/query/service -u {2}:{3} " \
                              "-d 'statement=select * from system:completed_requests " \
                              "where errorCount > 0 order by requestTime desc'"\
                        .format(nodes[0], component["port"], rest_username,
                                rest_password)
                    self.logger.info("{} = Running curl: {0}".format(nodes[0], command))
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
                        msg_content = msg_content + '\n\n' + nodes[0] + " : " + str(component["component"])
                        msg_content = msg_content + '\n\n' + "Found an exception {0}".format(e) + "\n"

        except Exception as e:
            self.logger.info("Found an exception {0}".format(e))
            msg_content = msg_content + '\n\n' + nodes[0] + " : " + str(component["component"])
            msg_content = msg_content + '\n\n' + "Found an exception {0}".format(e) + "\n"

        return should_cbcollect, msg_content

    def check_active_requests(self, nodes, component, rest_username,
                              rest_password, ssh_username, ssh_password):
        msg_content = ''
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
                msg_content = msg_content + '\n\n' + nodes[0] + " : " + str(component["component"])
                msg_content = msg_content + '\n\n' + "There are more than 1000 queries running at time {0}, this should not be the case. Storing active_requests for further review".format(collection_timestamp) + "\n"
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
            msg_content = msg_content + '\n\n' + nodes[0] + " : " + str(component["component"])
            msg_content = msg_content + '\n\n' + "Found an exception {0}".format(e) + "\n"

        return should_cbcollect, msg_content

    def get_xdcr_dest(self, node):
        api = "http://" + node + ":8091/pools/default/remoteClusters"
        status, content, _ = self._http_request(api)
        content_array = json.loads(content)
        xdcr_dest_master_ip = list()
        for content in content_array:
            if 'hostname' in content:
                xdcr_dest_ip = content['hostname']
                xdcr_dest_master_ip.append(xdcr_dest_ip.split(':')[0])
        if len(xdcr_dest_master_ip) == 0:
            self.logger.info("No XDCR destinations found!")
        return xdcr_dest_master_ip

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

    def _http_request(self, api, method='GET', params='', headers=None,
                      timeout=120):
        if not headers:
            headers = self._create_headers()
        end_time = time.time() + timeout
        self.logger.info("Executing {0} request for following api {1}"
                         .format(method, api))
        count = 1
        while True:
            try:
                response, content = httplib2.Http(timeout=timeout)\
                    .request(api, method, params, headers)
                if response['status'] in ['200', '201', '202']:
                    return True, content, response
                else:
                    try:
                        json_parsed = json.loads(content)
                    except ValueError as e:
                        json_parsed = dict()
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
                    self.logger.error("Tried to connect {0} times".format(count))
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

    def print_output(self, output, last_scan_timestamp, msg_content):
        for line in output:
            match = re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', line)
            if match:
                timestamp_in_log = datetime.strptime(match.group(), '%Y-%m-%dT%H:%M:%S')
                if timestamp_in_log >= last_scan_timestamp \
                        and self.check_op_in_ignorelist(line):
                    self.logger.debug(line)
                    msg_content = msg_content + '\n' + line
            else:
                self.logger.debug(line)
                msg_content = msg_content + '\n' + line
                if line.strip() not in Configuration.ignore_list:
                    Configuration.ignore_list.append(line.strip())

        return msg_content

    def check_op_in_ignorelist(self, line):
        for ignore_text in Configuration.ignore_list:
            if ignore_text in line:
                return False
        return True

    def get_services_map(self, master, rest_username, rest_password):
        cluster_url = "http://" + master + ":8091/pools/default"
        node_map = list()
        retry_count = 5
        status = content = None
        while retry_count:
            try:
                # Get map of nodes in the cluster
                status, content, _ = self._http_request(cluster_url)
                if status:
                    response = json.loads(str(content))
                    for node in response["nodes"]:
                        clusternode = dict()
                        clusternode["hostname"] = node["hostname"].replace(":8091", "")
                        clusternode["services"] = node["services"]
                        mem_used = int(node["memoryTotal"]) - int(node["memoryFree"])
                        if node["memoryTotal"]:
                            clusternode["memUsage"] = round(
                                float(float(mem_used)
                                      / float(node["memoryTotal"]) * 100), 2)
                        else:
                            clusternode["memUsage"] = 0
                        clusternode["cpuUsage"] = round(
                            node["systemStats"]["cpu_utilization_rate"], 2)
                        clusternode["status"] = node["status"]
                        node_map.append(clusternode)

                    break
            except Exception as e:
                self.logger.info("Exception in get_service_map: {0}".format(e))
                self.logger.info("Status: {}, content: {}"
                                 .format(status, content))
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
        ssh.close()
        return len(output), output, error


def configure_logger():
    # Logging configuration
    Globals.logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    ch.setFormatter(formatter)
    Globals.logger.addHandler(ch)
    timestamp = str(datetime.now().strftime('%Y%m%dT_%H%M%S'))
    fh = logging.FileHandler("./systestmon-{0}.log".format(timestamp))
    fh.setFormatter(formatter)
    Globals.logger.addHandler(fh)

    # Set Paramiko logger
    paramiko.util.log_to_file('./paramiko.log')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run CB monitoring script')
    # Below are required args
    parser.add_argument('master_node', type=str,
                        help='IP of the master node for reference')
    parser.add_argument('rest_username', type=str,
                        help='Cluster REST username')
    parser.add_argument('rest_password', type=str,
                        help='Cluster REST password')
    parser.add_argument('ssh_username', type=str, help='SSH username')
    parser.add_argument('ssh_password', type=str, help='SSH password')
    parser.add_argument("email_recipients", type=str,
                        help="Comma separated list")
    parser.add_argument("state_file_dir", default="./",
                        help="Dir to store the state files")
    parser.add_argument("docker_host", default=None, help="Docker host")

    # Optional args
    parser.add_argument("--cb_host", default="172.23.104.178",
                        help="CB host for SDK connection")

    # Flags
    parser.add_argument("--cbcollect_on_high_mem_cpu_usage",
                        action="store_true", default=False,
                        help="Collect cb-logs during high mem/cpu usage")
    parser.add_argument("--print_all_logs", action="store_true",
                        default=False, help="Prints all logs")
    parser.add_argument("--run_infinite", action="store_true", default=False,
                        help="Flag to enable infinite log collection loops")
    parser.add_argument("--collect_dumps", action="store_true",
                        default=False, help="Flag to enable collection dumps")
    parser.add_argument("--scan_xdcr_destination", action="store_true",
                        default=False, help="Log-monitor XDCR connections")
    args = parser.parse_args()
    # End of command line options parsing

    # Configure log handlers
    configure_logger()

    # Set common configurations from cmd options
    ScriptConfig.cbcollect_on_high_mem_cpu_usage = args.cbcollect_on_high_mem_cpu_usage
    ScriptConfig.print_all_logs = args.print_all_logs
    ScriptConfig.email_recipients = args.email_recipients
    ScriptConfig.should_collect_dumps = args.collect_dumps
    ScriptConfig.docker_host = args.docker_host
    ScriptConfig.state_file_dir = args.state_file_dir
    ScriptConfig.scan_xdcr_destination = args.scan_xdcr_destination

    Globals.sdk_client = SDKClient(args.cb_host)

    # Create cluster object for managing purpose
    main_cluster = CBCluster("Main_cluster", args.master_node,
                             args.rest_username, args.rest_password,
                             args.ssh_username, args.ssh_password)

    # Create monitoring object and start monitoring
    main_sys_mon = SysTestMon(main_cluster, args.run_infinite)
    main_sys_mon.run()
