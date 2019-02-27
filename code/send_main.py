# -*- coding: utf-8 -*-
"""
REVPI-ATECC PHOTO SIGNER - SENDER

Created on Tue Dec 18 12:01:21 2018
@author:     Peter Lang, Harald Bogesch, Christian Remmele, Felix Meißner
projekt:     python wrapper atecc508a security chip
costumer:    Mr. Prof. Dr. Dominik Merli
institution: HS-Augsburg

"""
# load necessary GUI libraries
from PyQt5.QtWidgets import QApplication, QWidget, QLabel
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5 import QtWidgets
from PyQt5 import QtCore
from PyQt5.QtGui import *
from send_design import Ui_MainWindow  # importing the QT File

#load necessary standard libraries
import datetime
import sys
import numpy as np
import random
import socket
import time

# load necessary atecc libraries
from cryptoauthlib import *
from common import *


# load necessary crypto libarys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature
from cryptography.utils import int_from_bytes, int_to_bytes

# set atecc success code
ATCA_SUCCESS = 0x00
 
# configuration for ATECC508A out of the configuration file, minus the first 16 bytes which are fixed by the factory
atecc508_config = bytearray.fromhex(
    'C0 00 55 00 8F 20 C4 44 87 20 87 20 8F 0F C4 36'
    '9F 0F 82 20 0F 0F C4 44 0F 0F 0F 0F 0F 0F 0F 0F'
    '0F 0F 0F 0F FF FF FF FF 00 00 00 00 FF FF FF FF'
    '00 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF'
    'FF FF FF FF 00 00 55 55 FF FF 00 00 00 00 00 00'
    '33 00 1C 00 13 00 13 00 7C 00 1C 00 3C 00 33 00'
    '3C 00 3C 00 3C 00 30 00 3C 00 3C 00 3C 00 30 00')

class mywindow(QtWidgets.QMainWindow): 
    def __init__(self):
        super(mywindow, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        
        
        ###Variables###
        self.auto = False
        self.freq = 0
        self.pic_count = 0
        self.pic_path = "pics/"
        self.pic_list = ["01.jpg", "02.jpg", "03.jpg", "04.jpg", "05.jpg", "06.jpg", "07.jpg", "08.jpg", "09.jpg", "10.jpg",
            "11.jpg", "12.jpg", "13.jpg", "14.jpg", "15.jpg", "16.jpg", "17.jpg", "18.jpg", "19.jpg", "20.jpg",]
        self.current_pic = self.pic_path + self.pic_list[0]
        self.meta_pic = self.pic_path + "temp.jpg"
        self.hash = bytearray(32)
        self.pub_key = bytearray(64)
        self.signature = bytearray(64)
        self.counter = 0
        self.sensor_1 = 0
        self.sensor_2 = 0
        self.sensor_3 = 0
        self.sensor_4 = 0
        self.serialnum = "unknown"
        self.conf_zone = "unknown"
        self.data_zone = "unknown"
        self.key_slot = 0
        self.dest_ip = "141.082.006.027"
        self.dest_port_pic = "2020"
        self.dest_port_pubkey = "2021"
        self.current_date_time = datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')
        self.use_current_time = True
        self.man_date_time = ("09.09.1999_09:09:09")
        self.metadict = {"device" : "None", "date_time" : "None", "counter" : 0, "sensor_1" : 0, "sensor_2" : 0, "sensor_3" : 0, "sensor_4" : 0,}
        
        ###Timer###
        self._status_update_timer = QtCore.QTimer(self)
        self._status_update_timer.setSingleShot(False)
        self._status_update_timer.timeout.connect(self.timer_update)
        self._status_update_timer.start(1000)
        
        
        
        ###Picture Init###
        logo = QPixmap('logo.jpg')
        self.ui.logo.setPixmap(logo)
        display = QPixmap(self.current_pic)
        self.ui.display.setPixmap(display)
        
        ###Textbox Init###
        self.ui.out_file_name.setText(self.current_pic)
        self.ui.out_serial_number.setText(self.serialnum)
        self.ui.out_conf_zone.setText(self.conf_zone)
        self.ui.out_data_zone.setText(self.data_zone)
        self.ui.out_key_slot.setText(str(self.key_slot))
        self.ui.out_current_date_time.setText(str(self.current_date_time))
        self.ui.out_hash_value.setText("no hash value avilable")
        self.ui.out_public_key.setText("no public key avilable")
        self.ui.out_signature.setText("no signature avilable")
        
        ###Widget Init###
        self.ui.in_dest_ip.setInputMask("000.000.000.000")
        self.ui.in_dest_ip.setText(self.dest_ip)
        self.ui.in_dest_ip.textChanged.connect(self.setip)
        self.ui.in_dest_port_pic.setInputMask("0000")
        self.ui.in_dest_port_pic.setText(self.dest_port_pic)
        self.ui.in_dest_port_pubkey.setInputMask("0000")
        self.ui.in_dest_port_pubkey.setText(self.dest_port_pubkey)
        self.ui.in_dest_port_pic.textChanged.connect(self.setport_pic)
        self.ui.in_dest_port_pubkey.textChanged.connect(self.setport_pubkey)
        
        self.ui.in_man_date.setInputMask("00.00.0000")
        self.ui.in_man_date.setText("09.09.1999")
        self.ui.in_man_date.textChanged.connect(self.setmandatetime)
        self.ui.in_man_time.setInputMask("00:00:00")
        self.ui.in_man_time.setText("09:09:09")
        self.ui.in_man_time.textChanged.connect(self.setmandatetime)
        self.ui.in_counter.setInputMask("00000000")
        self.ui.in_counter.setText(str(self.counter))
        
        
        self.ui.in_sensor_1.setInputMask("0000000")
        self.ui.in_sensor_1.setText("0000000")
        self.ui.in_sensor_1.textChanged.connect(self.setsen1)
        self.ui.in_sensor_2.setInputMask("0000000")
        self.ui.in_sensor_2.setText("0000000")
        self.ui.in_sensor_2.textChanged.connect(self.setsen2)
        self.ui.in_sensor_3.setInputMask("0000000")
        self.ui.in_sensor_3.setText("0000000")
        self.ui.in_sensor_3.textChanged.connect(self.setsen3)
        self.ui.in_sensor_4.setInputMask("0000000")
        self.ui.in_sensor_4.setText("0000000")
        self.ui.in_sensor_4.textChanged.connect(self.setsen4)
        
       
        ###Button Init###
        self.ui.pB_load_new_pic.clicked.connect(self.click_new_pic)
        self.ui.pB_send_valid.clicked.connect(self.click_send_valid)
        self.ui.pB_send_valid_2.clicked.connect(self.click_send_valid_auto)
        self.ui.pB_send_invalid.clicked.connect(self.click_send_invalid)
        self.ui.pB_send_invalid_2.clicked.connect(self.click_send_invalid_prev)
        self.ui.pB_gen_new_key.clicked.connect(self.click_gen_new_key)
        self.ui.pB_send_pub_key.clicked.connect(self.click_send_pub_key)
        
        
        ###CheckBox Init###
        self.ui.cB_use_current_time.toggle()
        #self.ui.cB_use_current_time.setText("True")
        self.ui.cB_use_current_time.stateChanged.connect(self.chgtime)
        
        
    ###Button Functions###
    def click_new_pic(self):
        #load new pic from pool
        if self.pic_count >= 19:
            self.pic_count = 0
        else:
            self.pic_count += 1
        self.current_pic = self.pic_path + self.pic_list[self.pic_count]
        display = QPixmap(self.current_pic)
        self.ui.display.setPixmap(display)
        self.ui.out_file_name.setText(self.current_pic)
        print(self.current_pic)
        self.ui.out_hash_value.setText("no hash value avilable")
        self.ui.out_signature.setText("no signature avilable")
        self.ui.out_signature.setStyleSheet("background-color: rgb(233, 233, 233);")
        

    
    def click_send_valid(self):
        print("Send Valid Data to:  " + self.dest_ip + "  Port: " + self.dest_port_pic)
        #del self.signature[:]
        #self.signature = bytearray(64)
        
        #counting up
        self.counter += 1
        self.ui.in_counter.setText(str(self.counter))
        
        #set metadata
        self.set_metadata()
        #generate hash value out of current picture
        print('opening picture')
        picture = open(self.meta_pic, "rb")
        file = picture.read()
        picture_bytes = bytes(file)
        print("hashing picture")
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(picture_bytes)
        self.hash = digest.finalize()
        self.ui.out_hash_value.setText(pretty_print_hex(self.hash, indent='    '))
        picture.close()
        print("hashing done")
        
        #signing
        print("creating signature")
        buffer = bytearray(64)
        start_time = time.time()
        assert atcab_sign(self.key_slot, self.hash, buffer) == ATCA_SUCCESS
        stop_time = time.time()
        print("time for signing: " + str(stop_time-start_time))
        self.signature = buffer
        print("creating signature done")
        self.ui.out_signature.setText(pretty_print_hex(self.signature, indent='    '))
        
        #check signature
        is_valid = AtcaReference(False)
        assert atcab_verify_extern(self.hash, self.signature, self.pub_key, is_valid) == ATCA_SUCCESS
        if is_valid == 1:
            print("is valid")
            self.ui.out_signature.setStyleSheet("background-color: rgb(170, 255, 127);")
        else:
            print("is invalid")
            self.ui.out_signature.setStyleSheet("background-color: rgb(255, 0, 0);")
            
        
        #sending picture and signature to receiver
        self.TCP_send_pic()
        
        
    def click_send_valid_auto(self):
        if self.auto == False:
            self.auto = True
            self.ui.pB_send_valid_2.setText("Stop Automatic Programm")
            
            self.ui.pB_load_new_pic.setEnabled(False)
            self.ui.pB_send_valid.setEnabled(False)
            self.ui.pB_send_invalid.setEnabled(False)
            self.ui.pB_send_invalid_2.setEnabled(False)
            self.ui.pB_gen_new_key.setEnabled(False)
            self.ui.pB_send_pub_key.setEnabled(False)

        else:
            self.auto = False
            self.ui.pB_send_valid_2.setText("Start Automatic Programm")
            
            self.ui.pB_load_new_pic.setEnabled(True)
            self.ui.pB_send_valid.setEnabled(True)
            self.ui.pB_send_invalid.setEnabled(True)
            self.ui.pB_send_invalid_2.setEnabled(True)
            self.ui.pB_gen_new_key.setEnabled(True)
            self.ui.pB_send_pub_key.setEnabled(True)
        

        
    def click_send_invalid(self):
        print("Send Invalid Data to:  " + self.dest_ip + "  Port: " + self.dest_port_pic)
        #counting up
        self.counter += 1
        self.ui.in_counter.setText(str(self.counter))
        #set metadata
        self.set_metadata()
        #generate hash value out of current picture
        print('opening picture')
        picture = open(self.meta_pic, "rb")
        file = picture.read()
        picture_bytes = bytes(file)
        print("hashing picture")
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(picture_bytes)
        self.hash = digest.finalize()
        self.ui.out_hash_value.setText(pretty_print_hex(self.hash, indent='    '))
        picture.close()
        print("hashing done")
        
        #using an invalid random signature
        print("creating a random invalid signature")
        self.signature = np.random.bytes(len(self.signature))
        print("creating signature done")
        self.ui.out_signature.setText(pretty_print_hex(self.signature, indent='    '))
        
        #check signature
        is_valid = AtcaReference(False)
        assert atcab_verify_extern(self.hash, self.signature, self.pub_key, is_valid) == ATCA_SUCCESS
        if is_valid == 1:
            print("is valid")
            self.ui.out_signature.setStyleSheet("background-color: rgb(170, 255, 127);")
        else:
            print("is invalid")
            self.ui.out_signature.setStyleSheet("background-color: rgb(255, 0, 0);")
        
        #sending picture and signature to receiver
        self.TCP_send_pic()

    
    def click_send_invalid_prev(self):
        print("Send Invalid with prev Signature Data to:  " + self.dest_ip + "  Port: " + self.dest_port_pic)
        #counting up    
        self.counter += 1
        self.ui.in_counter.setText(str(self.counter))
        #set metadata
        self.set_metadata()
        #generate hash value out of current picture
        print('opening picture')
        picture = open(self.meta_pic, "rb")
        file = picture.read()
        picture_bytes = bytes(file)
        print("hashing picture")
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(picture_bytes)
        self.hash = digest.finalize()
        self.ui.out_hash_value.setText(pretty_print_hex(self.hash, indent='    '))
        picture.close()
        print("hashing done")
        
        #using the old signature
        print(self.counter)
        if self.counter > 0:
            self.ui.out_signature.setText(pretty_print_hex(self.signature, indent='    '))
            is_valid = AtcaReference(False)
            assert atcab_verify_extern(self.hash, self.signature, self.pub_key, is_valid) == ATCA_SUCCESS
            if is_valid == 1:
                print("is valid")
                self.ui.out_signature.setStyleSheet("background-color: rgb(170, 255, 127);")
            else:
                print("is invalid")
                self.ui.out_signature.setStyleSheet("background-color: rgb(255, 0, 0);")
                
        
            #sending picture and signature to receiver
            self.TCP_send_pic()
        
        
        
        else:
            self.ui.out_signature.setText("no signature avilable\nplease generate valid signature first")
        
        
        
    def click_gen_new_key(self):
        print("check validation of key slot {}".format(self.key_slot))
        if self.key_slot in [0,2,3,7]:
            print("genrate key for slot {}".format(self.key_slot))
            self.pub_key = bytearray(64)
            assert ATCA_SUCCESS == atcab_genkey(self.key_slot, self.pub_key)
            self.ui.out_public_key.setText(pretty_print_hex(self.pub_key, indent='    '))
        else:
            print("invalid slot number, use slot 0, 2, 3 or 7\n")
            self.pub_key = "invalid slot number, use slot 0, 2, 3 or 7\n"
            
    
    def click_send_pub_key(self):
        self.TCP_send_key()
        return True

    
    ###CheckBox Functions###
    def chgtime(self):
        if self.use_current_time:
            self.use_current_time = False
            print("Auto Datum An")
        else:
            self.use_current_time = True
            print("Auto Datum Aus")
    
    ###Input Functions###
    def setip(self):
        self.dest_ip = str(self.ui.in_dest_ip.text())
        
    def setport_pic(self):
        self.dest_port_pic = str(self.ui.in_dest_port_pic.text())
        
    def setport_pubkey(self):
        self.dest_port_pubkey = str(self.ui.in_dest_port_pubkey.text())
        
    def setsen1(self):
        self.sensor_1 = int(self.ui.in_sensor_1.text())
    def setsen2(self):
        self.sensor_2 = int(self.ui.in_sensor_2.text())
    def setsen3(self):
        self.sensor_3 = int(self.ui.in_sensor_3.text())
    def setsen4(self):
        self.sensor_4 = int(self.ui.in_sensor_4.text())
    def setmandatetime(self):
        self.man_date_time = str(self.ui.in_man_date.text()) + "_" + str(self.ui.in_man_time.text())
        print(self.man_date_time)
    
    ###Timer Function###
    def timer_update(self):
        self.current_date_time = datetime.datetime.now().strftime('%d.%m.%Y_%H:%M:%S')
        self.ui.out_current_date_time.setText(str(self.current_date_time))
        if self.auto:
            self.freq += 1
            if self.freq >= 10:
                self.freq = 0
                self.click_new_pic()
                a=["0","0","0","0"]
                for i in range(4):
                    a[i] = str(random.randrange(0,999999))   
                self.ui.in_sensor_1.setText(a[0])
                self.ui.in_sensor_2.setText(a[1])
                self.ui.in_sensor_3.setText(a[2])
                self.ui.in_sensor_4.setText(a[3])
                
                self.click_send_valid()
            
            
    ###set metadata###
    def set_metadata(self):
        
        # setting metadict
        self.metadict["device"] = self.serialnum
        if self.use_current_time:
            self.metadict["date_time"] = self.current_date_time
        else:
            self.metadict["date_time"] = self.man_date_time    
        self.metadict["counter"] = self.counter
        self.metadict["sensor_1"] = self.sensor_1
        self.metadict["sensor_2"] = self.sensor_2
        self.metadict["sensor_3"] = self.sensor_3
        self.metadict["sensor_4"] = self.sensor_4
        

        # reading picture
        file = open(self.current_pic, 'rb')
        data = file.read()
        file.close()

        # handle dictionary
        metadata = str(self.metadict)
        metadata = metadata.replace("'", '')
        metadata = metadata.replace('{', '')
        metadata = metadata.replace('}', '')
        metadata = metadata.replace(': ', '*')
        metadata = metadata.replace(' ', '')
        metadata = metadata.replace(',', ';')

        # check current metadata
        start = data.find(b'\xff\xfe')
        if start == -1:

            # no metadata
            datanew = data
        else:

            # metadata already used
            # delete old metadata
            datanew = data[:start]
        print("set metadata done")

        # create new metadata
        metadata = b'\xff\xfe\x00' + metadata.encode() + b'\x00'

        # save picture with metadata
        file2 = open(self.meta_pic, 'wb')
        file2.write((datanew+metadata))
        file2.close()
        
        

    ###send picture###
    def TCP_send_pic(self):      
        # define socket
        print("opening socket")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            #formatting ip address
            ip_list = self.dest_ip.split(".")
            for i in ip_list:
                ip_list[ip_list.index(i)] = str(int(i))
            ip = ip_list[0] + "." + ip_list[1] + "." + ip_list[2] + "." + ip_list[3]
            
            # start TCP-connection
            print("opening connection")
            s.connect((ip, int(self.dest_port_pic)))
            #s.settimeout(10)

            # reading picture
            print("opening picture")
            f = open(self.meta_pic, 'rb')
            message = f.read()

            # analyse length
            length = len(message)
            length = 'length ' + str(length)
            length = length.encode()

            # handle signature
            signature = b'SIGNATURE:' + self.signature

            # den length, picture and signature
            print("sending data")
            s.sendall(length)
            time.sleep(0.5)
            s.sendall(message)
            time.sleep(0.5)
            s.sendall(signature)
            
            # close TCP-connection
            s.close()
            print("send success")

        except:

            # close TCP-connection
            s.close()
            print("send error")
        
        
    ###send public key###
    def TCP_send_key(self):
        # define socket
        print("opening socket")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        time.sleep(0.5)

        try:
            #formatting ip address
            ip_list = self.dest_ip.split(".")
            for i in ip_list:
                ip_list[ip_list.index(i)] = str(int(i))
            ip = ip_list[0] + "." + ip_list[1] + "." + ip_list[2] + "." + ip_list[3]
            
            # start TCP-connection
            print("opening connection")
            s.connect((ip, int(self.dest_port_pubkey)))
            # handle public-key
            print("generating message")
            pub_key = b'PUB_KEY' + self.pub_key

            # send public-key
            print("sending key")
            s.sendall(pub_key)
            # close TCP-connection
            s.close()
            print("send pub_key success")


        except:

            # close TCP-connection
            s.close()
            print("send pub_key error")

    
    ###device initialisation###
    # including:
    # - reading serial-number and chip name
    # - checks if config and data zone are locked
    # - returning the public key of the aktivatet key slot
    def init_device(self, slot= 0, device='ecc', iface = 'i2c'):
        slot = self.key_slot
        # loading cryptoauthlib (python specific)
        load_cryptoauthlib()

        # get the target default config
        cfg = eval('cfg_ateccx08a_{}_default()'.format(atca_names_map.get(iface)))

        # basic Raspberry Pi I2C check
        if 'i2c' == iface and check_if_rpi():
            cfg.cfg.atcai2c.bus = 1

        # initialize the stack
        assert atcab_init(cfg) == ATCA_SUCCESS
        
        # request the Revision Number
        info = bytearray(4)
        assert atcab_info(info) == ATCA_SUCCESS
        dev_type = get_device_type_id(get_device_name(info))
        print('\nDevice Part:')
        print('    ' + get_device_name(info))

        # request the Serial Number
        serial_number = bytearray(9)
        assert atcab_read_serial_number(serial_number) == ATCA_SUCCESS
        self.serialnum = pretty_print_hex(serial_number, indent='    ')
        self.serialnum = self.serialnum[:-1]
        self.ui.out_serial_number.setText(self.serialnum)
        print('\nSerial number: ')
        print(pretty_print_hex(serial_number, indent='    '))
        
        # read the configuration zone
        config_zone = bytearray(128)
        assert atcab_read_config_zone(config_zone) == ATCA_SUCCESS
        print('\nConfiguration Zone:')
        print(pretty_print_hex(config_zone, indent='    '))

        # check the device locks
        print('\nCheck Device Locks')
        is_locked = AtcaReference(False)
        assert atcab_is_locked(0, is_locked) == ATCA_SUCCESS
        config_zone_locked = bool(is_locked.value)
        print('    Config Zone is %s' % ('locked' if config_zone_locked else 'unlocked'))
        if config_zone_locked:
            self.conf_zone = "locked"
        else:
            self.conf_zone = "unlocked"
        self.ui.out_conf_zone.setText(self.conf_zone)
            
            
        assert atcab_is_locked(1, is_locked) == ATCA_SUCCESS
        data_zone_locked = bool(is_locked.value)
        print('    Data Zone is %s' % ('locked' if data_zone_locked else 'unlocked'))
        if data_zone_locked:
            self.data_zone = "locked"
        else:
            self.data_zone = "unlocked"
        self.ui.out_data_zone.setText(self.data_zone)

        # get the device's public key from the activated key slot
        assert atcab_get_pubkey(slot, self.pub_key) == ATCA_SUCCESS
        print('    Public Key in Slot ',self.key_slot, ":\n")
        print(pretty_print_hex(self.pub_key, indent='    '))
        self.ui.out_public_key.setText(pretty_print_hex(self.pub_key, indent='    '))
            
        if dev_type in [0, 0x20]:
            raise ValueError('Device does not support Sign/Verify operations')
        elif dev_type != cfg.devtype:
            cfg.dev_type = dev_type
            assert atcab_release() == ATCA_SUCCESS
            time.sleep(1)
            assert atcab_init(cfg) == ATCA_SUCCESS

        
    
    
    
    ###Close Event###
    def closeEvent(self, event):
        print("Goodbye")
        event.accept()
        
        




    
    
if __name__ == "__main__":
      
    #init GUI
    app = QtWidgets.QApplication([])
    sender = mywindow()
    sender.setWindowTitle('ATECC_Send')
    
    #init atecc chip
    print('##### PROJEKT 5 - SENDER - GET DEVICE INFO #####')
    sender.init_device()
    print('')
    
    #start GUI
    print("starting GUI")
    sender.show()
    sys.exit(app.exec())
