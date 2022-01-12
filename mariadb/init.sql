DROP DATABASE IF EXISTS pm_db;
CREATE DATABASE pm_db;
use pm_db;

SET GLOBAL explicit_defaults_for_timestamp = 1;

CREATE TABLE IF NOT EXISTS users (
  ID int(10) NOT NULL AUTO_INCREMENT,
  username varchar(30) NOT NULL,
  passwd BINARY(60) NOT NULL,
  salt BINARY(60) NOT NULL,
  PRIMARY KEY (ID)
);

CREATE TABLE IF NOT EXISTS failed_log_attempts (
  u_id int(10) NOT NULL,
  n_attempts int(1) NOT NULL,
  last_attempt DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (u_id) REFERENCES users(ID)
);

CREATE TABLE IF NOT EXISTS passwords (
  ID int(10) NOT NULL AUTO_INCREMENT,
  u_id   int(10) NOT NULL,
  website   varchar(50) NOT NULL ,
  passwd VARBINARY(256) NOT NULL,
  PRIMARY KEY (ID), 
  FOREIGN KEY (u_id) REFERENCES users(ID)
);

CREATE TABLE IF NOT EXISTS tokens (
  s_id varchar(24) NOT NULL,
  u_id int(10) NOT NULL,
  created DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY  (s_id),
  FOREIGN KEY (u_id) REFERENCES users(ID)
) 


  