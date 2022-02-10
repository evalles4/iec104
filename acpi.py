# -*- coding: utf-8 -*-
import struct


TESTFR_CON = '\x83\x00\x00\x00'
TESTFR_ACT = [0x68,0x04,0x43,0x00]#'\x43\x00\x00\x00'

STOPDT_CON = '\x23\x00\x00\x00'
STOPDT_ACT = '\x13\x00\x00\x00'

STARTDT_CON = [0x68,0x04,0x0b,0x00]#'\x0b\x00\x00\x00'
STARTDT_ACT = '\x07\x00\x00\x00'

def start_act_frame():

    frame = [None]*6
    frame[0] = 0x68
    frame[1] = 0x04
    frame[2] = 0x07
    frame[3] = 0x00
    frame[4] = 0x00  
    frame[5] = 0x00

    return frame

def testfr_con_frame():

    frame = [None]*6
    frame[0] = 0x68
    frame[1] = 0x04
    frame[2] = 0x83
    frame[3] = 0x00
    frame[4] = 0x00  
    frame[5] = 0x00

    return frame

def i_frame(ssn, rsn):
    return struct.pack('<1BHH', 0x64, ssn << 1, rsn << 1)


def s_frame(rsn):
    return struct.pack('<3BH', 0x64, 0x01, 0x00, rsn << 1)


def parse_i_frame(data):
    ssn, rsn = struct.unpack('<2H', data)
    return ssn >> 1, rsn >> 1


def parse_s_frame(data):
    rsn = struct.unpack_from('<2H', data)[1]
    return rsn >> 1
