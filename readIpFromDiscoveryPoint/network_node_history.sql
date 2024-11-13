/*
 Navicat Premium Data Transfer

 Source Server         : CoreInspect-Inventory
 Source Server Type    : PostgreSQL
 Source Server Version : 140000
 Source Host           : localhost:5432
 Source Catalog        : CoreInspect
 Source Schema         : network_node_history

 Target Server Type    : PostgreSQL
 Target Server Version : 140000
 File Encoding         : 65001

 Date: 21/06/2022 17:07:57
*/


-- ----------------------------
-- Sequence structure for ip_mac_history_id_seq
-- ----------------------------
DROP SEQUENCE IF EXISTS "network_node_history"."ip_mac_history_id_seq";
CREATE SEQUENCE "network_node_history"."ip_mac_history_id_seq" 
INCREMENT 1
MINVALUE  1
MAXVALUE 9223372036854775807
START 1
CACHE 1;

-- ----------------------------
-- Table structure for ip_mac_history
-- ----------------------------
DROP TABLE IF EXISTS "network_node_history"."ip_mac_history";
CREATE TABLE "network_node_history"."ip_mac_history" (
  "id" int8 NOT NULL DEFAULT nextval('"network_node_history".ip_mac_history_id_seq'::regclass),
  "scannedip" int8,
  "ipaddress" int8,
  "macaddress" int8,
  "scanid" int4 DEFAULT 1,
  "createdtime" varchar(50) COLLATE "pg_catalog"."default" DEFAULT '1999-01-01 00:00:00'::character varying
)
;

-- ----------------------------
-- Records of ip_mac_history
-- ----------------------------

-- ----------------------------
-- Alter sequences owned by
-- ----------------------------
ALTER SEQUENCE "network_node_history"."ip_mac_history_id_seq"
OWNED BY "network_node_history"."ip_mac_history"."id";
SELECT setval('"network_node_history"."ip_mac_history_id_seq"', 2, false);

-- ----------------------------
-- Primary Key structure for table ip_mac_history
-- ----------------------------
ALTER TABLE "network_node_history"."ip_mac_history" ADD CONSTRAINT "ip_mac_history_pkey" PRIMARY KEY ("id");
