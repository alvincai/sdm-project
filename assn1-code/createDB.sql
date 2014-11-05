-- run in mysql as source /pathtofile/filename

-- create database and local user with rights
-- CREATE USER 'sdm'@'localhost' IDENTIFIED BY 'password';
-- create database if not exists sdmAssn1;
-- grant ALL on sdmAssn1.* TO 'sdm'@'localhost';


-- create tables
create table IF NOT EXISTS Patient(
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(20),
    DoctorID VARCHAR(20),
    HospitalID VARCHAR(20),
    HealthClubID VARCHAR(20),
    InsuranceID VARCHAR(20),
    EmployerID VARCHAR(20),
    Signature VARCHAR(1000));


create table IF NOT EXISTS HealthRecords(
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    PatientID VARCHAR(20),
    EncryptedData VARCHAR(1000),
    Signature VARCHAR(1000));

