CREATE TABLE IF NOT EXISTS `applications` (
  `id` int NOT NULL AUTO_INCREMENT,
  `system_id` int DEFAULT NULL,
  `name` text,
  `version` text,
  `publisher` text,
  PRIMARY KEY (`id`),
  KEY `system_id` (`system_id`),
  CONSTRAINT `applications_ibfk_1` FOREIGN KEY (`system_id`) REFERENCES `systems` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=216 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `devices` (
  `id` int NOT NULL AUTO_INCREMENT,
  `network_id` int DEFAULT NULL,
  `ip` varchar(45) DEFAULT NULL,
  `hostname` varchar(255) DEFAULT NULL,
  `os` varchar(255) DEFAULT NULL,
  `ports` text,
  `mac` varchar(50) DEFAULT NULL,
  `vendor` varchar(255) DEFAULT NULL,
  `manufacturer` varchar(255) DEFAULT NULL,
  `snmp_name` varchar(255) DEFAULT NULL,
  `snmp_desc` text,
  `device_type` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `network_id` (`network_id`),
  CONSTRAINT `devices_ibfk_1` FOREIGN KEY (`network_id`) REFERENCES `networks` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=395 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `networks` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ip_range` varchar(50) DEFAULT NULL,
  `interface` varchar(100) DEFAULT NULL,
  `mac` varchar(50) DEFAULT NULL,
  `scan_time` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ip_range` (`ip_range`,`interface`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `systems` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ip` varchar(45) DEFAULT NULL,
  `os_type` varchar(50) DEFAULT NULL,
  `details` text,
  `last_scanned` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ip` (`ip`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `vulnerabilities` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_id` int NOT NULL,
  `ip` varchar(15) NOT NULL,
  `port` int DEFAULT NULL,
  `vulnerability_id` varchar(100) NOT NULL,
  `vulnerability_description` text NOT NULL,
  `severity` enum('low','medium','high') NOT NULL,
  PRIMARY KEY (`id`),
  KEY `device_id` (`device_id`),
  CONSTRAINT `fk_device` FOREIGN KEY (`device_id`) REFERENCES `devices` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=592 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
