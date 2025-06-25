# Phase 3

## Comandos para la bd
Instalar sql server
sudo apt update
sudo apt install mysql-server

Ver que este corriendo
sudo systemctl status mysql
para iniciarlo
sudo systemctl start mysql
inicie con el sistema
sudo systemctl enable mysql

Entrar a SQL
sudo mysql

Una vez dentro
CREATE DATABASE signatures;

USE signatures;

CREATE TABLE firmas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    hash VARCHAR(64) NOT NULL UNIQUE,
    nombre_malware VARCHAR(100) NOT NULL,
    severidad ENUM('baja', 'media', 'alta') NOT NULL,
    descripcion TEXT
);

Insertar 
INSERT INTO firmas (hash, nombre_malware, severidad, descripcion)
VALUES 
('5d41402abc4b2a76b9719d911017c592', 'Trojan.Simple', 'alta', 'Troyano detectado.'),
('098f6bcd4621d373cade4e832627b4f6', 'Worm.Basic', 'media', 'Gusano básico.'),
('e99a18c428cb38d5f260853678922e03', 'Keylogger.Minimal', 'alta', 'Keylogger simple.');

mysql> CREATE USER 'usac'@'localhost' IDENTIFIED BY 'seguro123';

## No olvidar
nano arch/x86/entry/syscalls/syscall_64.tbl
xxx     common   scan_file     sys_scan_file

## Compilar kernel
cp -v /boot/config-$(uname -r) .config

make localmodconfig

scripts/config --disable SYSTEM_TRUSTED_KEYS
scripts/config --disable SYSTEM_REVOCATION_KEYS
scripts/config --set-str CONFIG_SYSTEM_TRUSTED_KEYS ""
scripts/config --set-str CONFIG_SYSTEM_REVOCATION_KEYS ""

make -j$(nproc)
sudo make modules_install
sudo make install
sudo reboot


## instalar para las pruebas
sudo apt update
sudo apt install libssl-dev libmysqlclient-dev