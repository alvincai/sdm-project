-- run in mysql as source /pathtofile/filename

-- create database and local user with rights
-- CREATE USER 'sdm'@'localhost' IDENTIFIED BY 'password';
-- create database if not exists sdmAssn1;
-- grant ALL on sdmAssn1.* TO 'sdm'@'localhost';


-- create tables
create table IF NOT EXISTS Proxy(
    keystring VARCHAR(256),
    reEncryptionKey VARCHAR(2048));

create table IF NOT EXISTS HealthRecords(
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    PatientID VARCHAR(20),
    SignerID VARCHAR(20),
    EncryptedDataI VARCHAR(1000),
    EncryptedDataPG VARCHAR(1000),
    Signature VARCHAR(1000),
    SignatureDate DATETIME);

create table IF NOT EXISTS AuthorisedInsert(
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    PatientID VARCHAR(20),
    EntityID VARCHAR(20),
    HealthRecordType VARCHAR(64),
    DateStart DATETIME,
    DateEnd DATETIME,
    Signature VARCHAR(1000)
);

create table IF NOT EXISTS SignKeys (
    id VARCHAR(20),
    pubKey VARCHAR(1000)
);
