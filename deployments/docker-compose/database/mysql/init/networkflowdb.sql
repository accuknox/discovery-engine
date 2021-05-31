CREATE DATABASE IF NOT EXISTS `networkflowdb`;
USE `networkflowdb`;

CREATE TABLE IF NOT EXISTS `auto_policy_config` (
  `id` int NOT NULL AUTO_INCREMENT,
  `config_name` varchar(50) DEFAULT NULL,
  `status` int DEFAULT '0',
  `config_db` JSON DEFAULT NULL,
  `config_cilium_hubble` JSON DEFAULT NULL,
  `operation_mode` int DEFAULT NULL,
  `cronjob_time_interval` varchar(50) DEFAULT NULL,
  `one_time_job_time_selection` varchar(50) DEFAULT NULL,
  `network_log_from` varchar(50) DEFAULT NULL,
  `network_log_file` varchar(50) DEFAULT NULL,
  `network_policy_to` varchar(50) DEFAULT NULL,
  `network_policy_dir` varchar(50) DEFAULT NULL,
  `network_policy_types` int DEFAULT NULL,
  `network_policy_rule_types` int DEFAULT NULL,
  `network_policy_cidr_bits` int DEFAULT NULL,
  `network_policy_ignoring_flows` JSON DEFAULT NULL,
  `network_policy_l3_level` int DEFAULT NULL,
  `network_policy_l4_level` int DEFAULT NULL,
  `network_policy_l7_level` int DEFAULT NULL,
  `system_log_from` varchar(50) DEFAULT NULL,
  `system_log_file` varchar(50) DEFAULT NULL,
  `system_policy_to` varchar(50) DEFAULT NULL,
  `system_policy_dir` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

CREATE TABLE IF NOT EXISTS `network_log` (
  `id` int NOT NULL AUTO_INCREMENT,
  `time` int DEFAULT NULL,
  `cluster_name` varchar(100) DEFAULT NULL,
  `verdict` varchar(50) DEFAULT NULL,
  `drop_reason` INT DEFAULT NULL,
  `ethernet` JSON DEFAULT NULL,
  `ip` JSON DEFAULT NULL,
  `l4` JSON DEFAULT NULL,
  `l7` JSON DEFAULT NULL,
  `reply` BOOLEAN,
  `source` JSON DEFAULT NULL,
  `destination` JSON DEFAULT NULL,
  `type` varchar(50) DEFAULT NULL,
  `node_name` varchar(100) DEFAULT NULL,
  `event_type` JSON DEFAULT NULL,
  `source_service` JSON DEFAULT NULL,
  `destination_service` JSON DEFAULT NULL,
  `traffic_direction` varchar(50) DEFAULT NULL,
  `policy_match_type` int DEFAULT NULL,
  `trace_observation_point` varchar(100) DEFAULT NULL,
  `summary` varchar(1000) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

CREATE TABLE IF NOT EXISTS `network_policy` (
  `id` int NOT NULL AUTO_INCREMENT,
  `apiVersion` varchar(20) DEFAULT NULL,
  `kind` varchar(20) DEFAULT NULL,
  `flow_ids` JSON DEFAULT NULL,
  `name` varchar(50) DEFAULT NULL,
  `cluster_name` varchar(50) DEFAULT NULL,
  `namespace` varchar(50) DEFAULT NULL,
  `type` varchar(10) DEFAULT NULL,
  `rule` varchar(30) DEFAULT NULL,
  `status` varchar(10) DEFAULT NULL,
  `outdated` varchar(50) DEFAULT NULL,
  `spec` JSON DEFAULT NULL,
  `generatedTime` int DEFAULT NULL,
  PRIMARY KEY (`id`)
);

CREATE TABLE IF NOT EXISTS `system_log` (
  `id` int NOT NULL AUTO_INCREMENT,
  `timestamp` int NOT NULL,
  `updatedTime` varchar(30) NOT NULL,
  `clusterName` varchar(100) NOT NULL,
  `hostName` varchar(100) NOT NULL,
  `namespaceName` varchar(100) NOT NULL,
  `podName` varchar(200) NOT NULL,
  `containerID` varchar(200) NOT NULL,
  `containerName` varchar(200) NOT NULL,
  `hostPid` int NOT NULL,
  `ppid` int NOT NULL,
  `pid` int NOT NULL,
  `uid` int NOT NULL,
  `type` varchar(20) NOT NULL,
  `source` varchar(4000) NOT NULL,
  `operation` varchar(20) NOT NULL,
  `resource` varchar(4000) NOT NULL,
  `data` varchar(1000) DEFAULT NULL,
  `result` varchar(200) NOT NULL,
  PRIMARY KEY (`id`)
);

CREATE TABLE IF NOT EXISTS `system_policy` (
  `id` int NOT NULL AUTO_INCREMENT,
  `apiVersion` varchar(20) DEFAULT NULL,
  `kind` varchar(20) DEFAULT NULL,
  `flow_ids` JSON DEFAULT NULL,
  `name` varchar(50) DEFAULT NULL,
  `cluster_name` varchar(50) DEFAULT NULL,
  `namespace` varchar(50) DEFAULT NULL,
  `type` varchar(10) DEFAULT NULL,
  `rule` varchar(30) DEFAULT NULL,
  `status` varchar(10) DEFAULT NULL,
  `outdated` varchar(50) DEFAULT NULL,
  `spec` JSON DEFAULT NULL,
  `generatedTime` int DEFAULT NULL,
  PRIMARY KEY (`id`)
);