CREATE DATABASE IF NOT EXISTS `flow_management`;
USE `flow_management`;

CREATE TABLE IF NOT EXISTS `network_flow` (
  `id` int NOT NULL AUTO_INCREMENT,
  `time` int DEFAULT NULL,
  `verdict` varchar(50) DEFAULT NULL,
  `drop_reason` INT DEFAULT NULL,
  `ethernet` JSON DEFAULT NULL,
  `ip` JSON DEFAULT NULL,
  `l4` JSON DEFAULT NULL,
  `l7` JSON DEFAULT NULL,
  `reply` BOOLEAN,
  `source` JSON DEFAULT NULL,
  `destination` JSON DEFAULT NULL,
  `type` int DEFAULT NULL,
  `src_cluster_name` varchar(100) DEFAULT NULL,
  `dest_cluster_name` varchar(100) DEFAULT NULL,
  `src_pod_name` varchar(100) DEFAULT NULL,
  `dest_pod_name` varchar(100) DEFAULT NULL,
  `node_name` varchar(100) DEFAULT NULL,
  `event_type` JSON DEFAULT NULL,
  `source_service` JSON DEFAULT NULL,
  `destination_service` JSON DEFAULT NULL,
  `traffic_direction` int DEFAULT NULL,
  `policy_match_type` int DEFAULT NULL,
  `trace_observation_point` int DEFAULT NULL,
  `summary` varchar(1000) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

CREATE TABLE IF NOT EXISTS `discovered_policy` (
  `id` int NOT NULL AUTO_INCREMENT,

  `apiVersion` varchar(20) DEFAULT NULL,
  `kind` varchar(20) DEFAULT NULL,
  `name` varchar(50) DEFAULT NULL,
  `namespace` varchar(50) DEFAULT NULL,
  `type` varchar(10) DEFAULT NULL,
  `rule` varchar(30) DEFAULT NULL,
  `status` varchar(10) DEFAULT NULL,
  `outdated` varchar(50) DEFAULT NULL,
  `spec` JSON DEFAULT NULL,

  `generatedTime` int DEFAULT NULL,
  PRIMARY KEY (`id`)
);

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
  `discovered_policy_to` varchar(50) DEFAULT NULL,
  `policy_dir` varchar(50) DEFAULT NULL,

  `discovery_policy_types` int DEFAULT NULL,
  `discovery_rule_types` int DEFAULT NULL,

  `cidr_bits` int DEFAULT NULL,
  `ignoring_flows` JSON DEFAULT NULL,

  `l3_aggregation_level` int DEFAULT NULL,
  `l4_aggregation_level` int DEFAULT NULL,
  `l7_aggregation_level` int DEFAULT NULL,
  `http_url_threshold` int DEFAULT NULL,

  PRIMARY KEY (`id`)
);
