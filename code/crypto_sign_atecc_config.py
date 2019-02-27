# -*- coding: utf-8 -*-
"""
REVPI-ATECC PHOTO SIGNER - CONFIGURATION

Created on Tue Dec 18 12:01:21 2018
@author:     Peter Lang, Harald Bogesch, Christian Remmele, Felix Meißner
projekt:     python wrapper atecc508a security chip
costumer:    Mr. Prof. Dr. Dominik Merli
institution: HS-Augsburg

"""


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


# device initialisation
# including:
# - reading serial-number and chip name
# - checks if config and data zone are locked
# - returning the public key of the aktivatet key slot

def init_device(slot=0, device='ecc', iface = 'i2c'):
  
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

    assert atcab_is_locked(1, is_locked) == ATCA_SUCCESS
    data_zone_locked = bool(is_locked.value)
    print('    Data Zone is %s' % ('locked' if data_zone_locked else 'unlocked'))

    # get the device's public key from the activated key slot
    public_key = bytearray(64)
    assert atcab_get_pubkey(slot, public_key) == ATCA_SUCCESS  
        
    if dev_type in [0, 0x20]:
        raise ValueError('Device does not support Sign/Verify operations')
    elif dev_type != cfg.devtype:
        cfg.dev_type = dev_type
        assert atcab_release() == ATCA_SUCCESS
        time.sleep(1)
        assert atcab_init(cfg) == ATCA_SUCCESS

    
    return public_key



def device_config(atecc508_config, device='ecc', iface = 'i2c'):
    """
    burn the configuration to the chip
    
    !!!!!!!!!!!!!!!!!!!!!!!!!!!ATTENTION!!!!!!!!!!!!!!!!!!!!!!!!!!!
    !!!                                                         !!!
    !!!        after locking the configuration zone             !!!
    !!! it is no longer possible, to modify the configuration   !!!
    !!!     it is also not possible to undo the locking         !!!
    !!!                                                         !!!
    !!!!!!!!!!!!!!!!!!!!!!!!!!!ATTENTION!!!!!!!!!!!!!!!!!!!!!!!!!!!
    
    """
    
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
    print('\nSerial number: ')
    print(pretty_print_hex(serial_number, indent='    '))
    
    # check the device locks
    print('\nCheck Device Locks')
    is_locked = AtcaReference(False)
    assert atcab_is_locked(0, is_locked) == ATCA_SUCCESS
    config_zone_locked = bool(is_locked.value)
    print('    Config Zone is %s' % ('locked' if config_zone_locked else 'unlocked'))
    
    # load configuration
    print('\nProgram Configuration')
    config = atecc508_config
    if not config_zone_locked:
        if dev_type is not None:
            print('    Programming {} Configuration'.format(get_device_name(info)))
        else:
            print('    Unknown Device')
            raise ValueError('Unknown Device Type: {:02X}'.format(dev_type))

        # writing configuration
        assert ATCA_SUCCESS == atcab_write_bytes_zone(0, 0, 16, config, len(config))
        print('        Success')

        #verify the written data and locking the configuration zone
        print('    Verifying Configuration')
        config_qa = bytearray(len(config))
        atcab_read_bytes_zone(0, 0, 16, config_qa, len(config_qa))

        if config_qa != config:
            raise ValueError('Configuration read from the device does not match')
        else:
            print('        Success')
            print('    Locking Configuration')
            assert ATCA_SUCCESS == atcab_lock_config_zone()
            print('        Locked')
    else:
        print('    Locked, skipping - config-zone already locked')
    
    # check the device locks
    print('\nCheck Device Locks')
    is_locked = AtcaReference(False)
    assert atcab_is_locked(0, is_locked) == ATCA_SUCCESS
    config_zone_locked = bool(is_locked.value)
    print('    Config Zone is %s' % ('locked' if config_zone_locked else 'unlocked'))
    
    # genrating new key at slot 0
    pubkey = bytearray(64)
    assert ATCA_SUCCESS == atcab_genkey(0, pubkey)


def generate_key(slot = 0):
    """
    generater an new key in the given slot
    """
    if slot in [0,2,3,7]:
        print("genrate key for slot {}\n".format(slot))
        pubkey = bytearray(64)
        assert ATCA_SUCCESS == atcab_genkey(slot, pubkey)
        print('    Key {} Success:'.foramt(slot))
        print(pretty_print_hex(pubkey, indent='    '))
        return pubkey
    else:
        print("invalid slot number, use slot 0, 2, 3 or 7\n")
        
    


def sign_device(digest, slot):
    """
    sign message using an ATECC508A
    """
    signature = bytearray(64)
    assert atcab_sign(slot, digest, signature) == ATCA_SUCCESS

    return signature


def verify_device(message, signature, public_key):
    """
    verify a signature using a device
    """
    is_verified = AtcaReference(False)
    assert atcab_verify_extern(message, signature, public_key, is_verified) == ATCA_SUCCESS

    return bool(is_verified.value)

def sign_host(digest, key):
    signature = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    (r,s) = utils.decode_dss_signature(signature)
    signature = int_to_bytes(r, 32) + int_to_bytes(s, 32)
    return signature


def verify_host(digest, signature, public_key_data):
    """
    verify a signature using the host software
    """
    try:
        public_key_data = b'\x04' + public_key_data

        r = int_from_bytes(signature[0:32], byteorder='big', signed=False)
        s = int_from_bytes(signature[32:64], byteorder='big', signed=False)
        sig = utils.encode_dss_signature(r, s)
    
        public_key = ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP256R1(), public_key_data).public_key(default_backend())
        public_key.verify(sig, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False
    



if __name__ == '__main__':  
    
    print('##### PROJEKT 5 - DEVICE CONFIG #####')
    device_config(atecc508_config)
    generate_key()
    
    
    print('##### PROJEKT 5 - DEVICE INIT #####')
    public_key = init_device()
    print('PubKey:')
    print(pretty_print_hex(public_key, indent='    '))
    private_key = 0
    print('')
    print('')

    print('##### PROJEKT 5 - Bild Umwandeln #####')
    picture = open("pics/01.jpg", "rb")
    file = picture.read()
    picture_bytes = bytes(file)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(picture_bytes)
    hash_value = digest.finalize()
    picture.close()
    

    
    print('Picture Digest:')
    print(pretty_print_hex(hash_value, indent='    '))
    print('')
    print('')
   
    print('##### PROJEKT 5 - PERFORM SIGNATURE #####')
    print('    Signing')
    signature = sign_device(hash_value, private_key)
    print('\nSignature:')
    print(pretty_print_hex(signature, indent='    '))
    print('')
    print('')
    
    ###Bild erneut Hashen für die verifikation
    picture = open("pics/01.jpg", "rb")
    file = picture.read()
    picture_bytes = bytes(file)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(picture_bytes)
    hash_value = digest.finalize()
    picture.close()
    
    print('##### PROJEKT 5 - PERFORM VERIFICATION #####')
    print('    Verifying')
    verified = verify_device(hash_value, signature, public_key)
    print('    Signature is %s!' % ('valid' if verified else 'invalid'))
    print('')
    print('')
    
    print('##### PROJEKT 5 - ATCAB RELEASE #####')
    atcab_release()
    picture.close()
    print('')
    print('')
    
    print('##### PROJEKT 5 - DONE #####')
    print('')
    print('')