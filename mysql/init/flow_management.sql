CREATE DATABASE IF NOT EXISTS `flow_management`;
USE `flow_management`;

CREATE TABLE IF NOT EXISTS `network_flow` (
  `id` int NOT NULL AUTO_INCREMENT,
  `time` varchar(20) NOT NULL,
  `verdict` varchar(20) DEFAULT NULL,
  `drop_reason` INT DEFAULT NULL,
  `ethernet` JSON DEFAULT NULL,
  `ip` JSON DEFAULT NULL,
  `l4` JSON DEFAULT NULL,
  `l7` JSON DEFAULT NULL,
  `reply` BOOLEAN,
  `source` JSON DEFAULT NULL,
  `destination` JSON DEFAULT NULL,
  `type` int DEFAULT NULL,
  `src_cluster_name` varchar(50) DEFAULT NULL,
  `dest_cluster_name` varchar(50) DEFAULT NULL,
  `src_pod_name` varchar(50) DEFAULT NULL,
  `dest_pod_name` varchar(50) DEFAULT NULL,
  `node_name` varchar(20) DEFAULT NULL,
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
  `apiVersion` varchar(20) NOT NULL,
  `kind` varchar(50) DEFAULT NULL,
  `metadata` JSON DEFAULT NULL,
  `spec` JSON DEFAULT NULL,
  `generated_time` int DEFAULT NULL,
  PRIMARY KEY (`id`)
);
