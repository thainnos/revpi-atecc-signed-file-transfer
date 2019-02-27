# -*- coding: utf-8 -*-
"""
REVPI-ATECC PHOTO SIGNER - RECEIVER

Created on Wedn Jan 02 13:19:18 2019
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
from receive_design import Ui_MainWindow  # importing the QT File

# load necessary standard libraries
import datetime
import sys
import numpy as np
import random
import socket
import os
import shutil
import threading
import queue
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
        print("starting gui")
        super(mywindow, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        
        
        ##Variables##
        self.toggle = False
        self.new_key = False
        self.auto = False
        self.pic_count = 0
        self.pic_count_prev = 0
        self.current_pic = "pics/temp.jpg"
        self.pic_path_savings = "pics/savings/"
        self.pic_savename = self.pic_path_savings + "serialnumber" + "_" + "date_time"
        self.hash = bytearray(32)
        self.pub_key = bytearray(64)
        self.pub_key_buffer = bytearray(64)
        self.signature = bytearray(64)
        self.status_signature = False
        self.serialnum = "unknown"
        self.conf_zone = "unknown"
        self.data_zone = "unknown"
        self.device_ip = "000.000.000.000"
        self.device_port_pic = "2020"
        self.device_port_pubkey = "2021"
        self.current_date_time = datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')
        self.metadict = {"device" : "None", "date_time" : "None", "counter" : 0, "sensor_1":0, "sensor_2":0, "sensor_3":0, "sensor_4":0}
        
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
        self.ui.out_serial_number.setText(self.serialnum)
        self.ui.out_conf_zone.setText(self.conf_zone)
        self.ui.out_data_zone.setText(self.data_zone)
        self.ui.out_current_date_time.setText(str(self.current_date_time))
        self.ui.out_sender_name.setText("no data")
        self.ui.out_pic_date.setText("no data")
        self.ui.out_pic_time.setText("no data")
        self.ui.out_current_counter.setText("no data")
        self.ui.out_prev_counter.setText("no data")
        self.ui.out_sensor_1.setText("no data")                                                  
        self.ui.out_sensor_2.setText("no data")                                                 
        self.ui.out_sensor_3.setText("no data")                                                  
        self.ui.out_sensor_4.setText("no data")                                                  
        self.ui.out_hash_value.setText("no hash value avilable")
        self.ui.out_public_key.setText("no public key avilable")
        self.ui.out_signature.setText("no signature avilable")
        self.ui.out_save_name.setText("")
        self.ui.out_sign_status.setText("no data")
        self.ui.out_count_status.setText("no data")
        self.ui.out_date_time_status.setText("no data")
        self.ui.out_device_ip.setText(self.device_ip)

                                                          
                                                          
        
        ###Widget Init###
        self.ui.in_device_port_pic.setInputMask("0000")
        self.ui.in_device_port_pic.setText(self.device_port_pic)
        self.ui.in_device_port_pic.setReadOnly(True)
        self.ui.in_device_port_pic.textChanged.connect(self.setport_pic)
        self.ui.in_device_port_pubkey.setInputMask("0000")
        self.ui.in_device_port_pubkey.setText(self.device_port_pubkey)
        self.ui.in_device_port_pubkey.setReadOnly(True)
        self.ui.in_device_port_pubkey.textChanged.connect(self.setport_pubkey)
        
       
        ###Button Init###
        self.ui.pB_start_auto.clicked.connect(self.click_start_auto)
        self.ui.pB_start_auto.setEnabled(False)
        self.ui.pB_save_current_pic.clicked.connect(self.click_save_pic)
        self.ui.pB_save_pub_key.clicked.connect(self.click_save_pub_key)
        
        ###Thread Init###
        self.tcp_pic = threading.Thread(target = self.TCP_receive_pic)
        self.tcp_key = threading.Thread(target = self.TCP_receive_key)
    
        
        
    ###Button Functions###
    def click_save_pic(self):
        #save the current picture with the actual date-time as its name
        self.pic_savename = self.pic_path_savings + self.metadict["device"] + "_" + self.metadict["date_time"] + ".jpg"
        shutil.copyfile(self.current_pic, self.pic_savename)
        self.ui.out_save_name.setText(self.pic_savename)
        
        
    def click_start_auto(self):
        if self.auto == False:
            self.auto = True
            self.ui.pB_start_auto.setText("Stop Automatic Programm")
            self.ui.pB_save_pub_key.setEnabled(False)

        else:
            self.auto = False
            self.ui.pB_start_auto.setText("Start Automatic Programm")
            self.ui.pB_save_pub_key.setEnabled(True)

            
    def click_save_pub_key(self):
        self.pub_key = self.pub_key_buffer
        self.ui.out_public_key.setText(pretty_print_hex(self.pub_key, indent='    '))
        self.ui.out_public_key.setStyleSheet("background-color: rgb(233, 233, 233);")
        self.ui.pB_start_auto.setEnabled(True)
        

    
    ###Input Functions###    
    def setport_pic(self):
        self.device_port_pic = str(self.ui.in_dest_port_pic.text())
        
    def setport_pubkey(self):
        self.device_port_pubkey = str(self.ui.in_dest_port_pubkey.text())
    
    ###Timer Function###
    def timer_update(self):
        self.current_date_time = datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')
        self.ui.out_current_date_time.setText(str(self.current_date_time))
        
        if self.new_key:
            self.ui.out_public_key.setText(pretty_print_hex(self.pub_key_buffer, indent='    '))
            self.ui.out_public_key.setStyleSheet("background-color: rgb(255, 165, 0);")
            self.new_key = False
        
        if self.auto:
            print("New pic: " + str(self.toggle))
            if self.toggle:
                display = QPixmap(self.current_pic)
                self.ui.display.setPixmap(display)
                self.ui.out_signature.setText(pretty_print_hex(self.signature, indent='    '))
                self.verify()
                self.ui.out_hash_value.setText(pretty_print_hex(self.hash, indent='    '))
                self.get_metadata()             
                
                #update outputwidgets
                self.pic_count_prev = self.pic_count
                self.pic_count = int(self.metadict["counter"])
                
                self.ui.out_sender_name.setText(self.metadict["device"])            
                date = str(self.metadict["date_time"]).split("_")[0]
                print(date)
                print("time next")
                time = str(self.metadict["date_time"]).split("_")[1]
                print(time)
                self.ui.out_pic_date.setText(str(date))
                self.ui.out_pic_time.setText((time))
                self.ui.out_current_counter.setText(self.metadict["counter"])
                self.ui.out_prev_counter.setText(str(self.pic_count_prev))
                self.ui.out_sensor_1.setText(self.metadict["sensor_1"])                                                  
                self.ui.out_sensor_2.setText(self.metadict["sensor_2"])                                                
                self.ui.out_sensor_3.setText(self.metadict["sensor_3"])                                                
                self.ui.out_sensor_4.setText(self.metadict["sensor_4"])
                print("new pic done")
                if self.pic_count == (self.pic_count_prev+1):
                    self.ui.out_count_status.setText("valid")
                    self.ui.out_count_status.setStyleSheet("background-color: rgb(0,255,0);")
                else:
                    self.ui.out_count_status.setText("invalid")
                    self.ui.out_count_status.setStyleSheet("background-color: rgb(255,0,0);")
                
                
                try:
                    date_list = date.split(".")
                    for i in date_list:
                        date_list[date_list.index(i)] = int(i)
                    time_list = time.split(":")
                    for i in time_list:
                        time_list[time_list.index(i)] = int(i)
                    pic_time = datetime.datetime(year=date_list[2],month=date_list[1],day=date_list[0],hour=time_list[0],minute=time_list[1],second=time_list[2])
                    print(pic_time)
                    time_div = (pic_time-datetime.datetime.now()).total_seconds()
                    
                    print(time_div)
                    if abs(time_div) <= 60:
                        self.ui.out_date_time_status.setText("valid, time delta: %.2f sec."% (time_div))
                        self.ui.out_date_time_status.setStyleSheet("background-color: rgb(0,255,0);")
                    else:
                        self.ui.out_date_time_status.setText("invalid, time delta: %.2f sec."% (time_div))
                        self.ui.out_date_time_status.setStyleSheet("background-color: rgb(255,0,0);")
                        
                except:
                    self.ui.out_date_time_status.setText("invalid, wrong date_time format")
                    self.ui.out_date_time_status.setStyleSheet("background-color: rgb(255,0,0);")
                    
                    
                    
                if self.status_signature:
                    self.ui.out_sign_status.setText("valid")
                    self.ui.out_sign_status.setStyleSheet("background-color: rgb(0,255,0);")
                else:
                    self.ui.out_sign_status.setText("invalid")
                    self.ui.out_sign_status.setStyleSheet("background-color: rgb(255,0,0);")
                    
                    
                    
                
                self.toggle = False
                
            
           
            
            
            
    ###get metadata###
    def get_metadata(self):
        print("getting metadata")
        # reading picture
        file = open(self.current_pic, 'rb')
        data = file.read()
        file.close()

        # search metadata
        start = data.find(b'\xff\xfe')
        start = start + 3
        data = data[start:-1]
        print(data)
        data = data.decode()
        print(data)

        # convert metadata into dictionary
        data = data.split(';')
        for i in range(len(data)):
            data[i] = data[i].split('*')
        keys = []
        values = []
        for i in range(len(data)):
            keys.append(data[i][0])
            values.append(data[i][1])
        dictionary = dict(zip(keys, values))
        print("setting temp dict")
        print(dictionary)
        self.metadict.clear()
        self.metadict = dictionary
        print("formatting dict")
        print(self.metadict)
        

    
    ###device initialisation###
    # including:
    # - reading serial-number and chip name
    # - checks if config and data zone are locked
    # - returning the public key of the aktivatet key slot
    def init_device(self, device='ecc', iface = 'i2c'):
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
        
            
        if dev_type in [0, 0x20]:
            raise ValueError('Device does not support Sign/Verify operations')
        elif dev_type != cfg.devtype:
            cfg.dev_type = dev_type
            assert atcab_release() == ATCA_SUCCESS
            time.sleep(1)
            assert atcab_init(cfg) == ATCA_SUCCESS
            
            
    ###get the device ip###        
    def get_ip(self):        
        self.device_ip = os.popen('ip addr show eth0').read().split("inet ")[1].split("/")[0]
        print(self.device_ip)
        self.ui.out_device_ip.setText(self.device_ip)
        return(self.device_ip) 
            

    ###Close Event###
    def closeEvent(self, event):
        print("Goodbye")
        event.accept()
        
        
    ###receive function for the pictures###
    def TCP_receive_pic(self):
        print("start pic receive function")
        # define and start TCP-connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", int(self.device_port_pic)))
        s.listen(1)
        print("opening socket receive pic")
        # initialize variable
        picture = b''
        signature = b''

        try:
            while True:

                # receive length
                print("opening connection picture")
                komm, addr = s.accept()
                print("connection established picture")
                while True:
                    print("waiting for data")
                    data = komm.recv(1024)
                    print("receiving data picture")
                    if data.startswith(b'length'):

                        # handle length
                        length = data.split(b" ")[1]
                        length = int(length.decode())
                        print("pic length: "+str(length))
                        
                        # receive picture
                        while len(picture) < length:
                            print("buffering data pic")
                            data = komm.recv(1024)
                            picture = picture + data

                        # receive signature
                        print("getting pic signature")
                        data = komm.recv(1024)
                        print("pic signature received")
                        signature = data[10:]
                        self.signature = signature

                        # save received picture
                        print("saving picture")
                        file = open(self.current_pic, 'wb')
                        file.write(picture)
                        file.close()

                        # reset variable
                        picture = b''
                        signature = b''
                        
                        print("receiving done")
                        
                        #public picture
                        self.toggle = True
                        #data = komm.recv(1024)
                        

                    if not data:

                        # close TCP-connection
                        komm.close()
                        print("closing connection picture")
                        break
                        

        except:
            # close TCP-connection
            print("error receive connection picture")
            s.close()
        
        finally:
            print("closing socket picture")
            s.close()
            
        
    
    ###receive function for the public key###
    def TCP_receive_key(self):
        print("start key receive function")
        # define and start TCP-connection
        print("opening socket receive key")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", int(self.device_port_pubkey)))
        s.listen(1)

        try:
            while True:

                # receive data
                print("opening connection receive key")
                komm, addr = s.accept()
                while True:
                    print("receiving data key")
                    data = komm.recv(4096)
                    print(data)
                    if data.startswith(b'PUB_KEY'):
                        # handle public-key
                        pub_key = data[7:]
                        print(pub_key)
                        print(pretty_print_hex(pub_key, indent='    '))
                        self.pub_key_buffer = pub_key
                        
                        self.new_key = True
                        
                        

                    if not data:

                        # close TCP-connection
                        komm.close()
                        break
                        

        except:
            # close TCP-connection
            print("error receiving key")
            s.close()
        
        finally:
            # close TCP-connection
            print("closing socket key")
            s.close()
        
    
    
    ###verify###
    def verify(self):
        #opening current picture
        print('opening picture')
        picture = open(self.current_pic, "rb")
        file = picture.read()
        picture_bytes = bytes(file)
        #creating hash
        print("hashing picture")
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(picture_bytes)
        self.hash = digest.finalize()
        self.ui.out_hash_value.setText(pretty_print_hex(self.hash, indent='    '))
        picture.close()
        print("hashing done")
        #check signature
        is_valid = AtcaReference(False)
        print("verify picture")
        start_time = time.time()
        assert atcab_verify_extern(self.hash, self.signature, self.pub_key, is_valid) == ATCA_SUCCESS
        stop_time = time.time()
        print("time for verification: " + str(stop_time-start_time))
        print("verifcation done")
        if is_valid == AtcaReference(True):
            print("is valid")
            self.ui.out_signature.setStyleSheet("background-color: rgb(170, 255, 127);")
            self.status_signature = True
        else:
            print("is invalid")
            self.ui.out_signature.setStyleSheet("background-color: rgb(255, 0, 0);")
            self.status_signature = False
        
        
    



    
    
if __name__ == "__main__":
      
    #init GUI
    app = QtWidgets.QApplication([])
    receiver = mywindow()
    receiver.setWindowTitle('ATECC_Receive')
    
    #init atecc chip
    print('##### PROJEKT 5 - RECEIVER - GET DEVICE INFO #####')
    receiver.init_device()
    print('')
    
    #get device ip address
    receiver.get_ip()
    
    #starting threads
    receiver.tcp_pic.start()
    receiver.tcp_key.start()    
    
    #start GUI
    receiver.show()
    sys.exit(app.exec())
