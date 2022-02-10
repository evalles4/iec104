# -*- coding: utf-8 -*-
import logging
import sys
import struct
import binascii
from datetime import datetime

tx_count = 0
rx_count = 0


def cp56time2a_to_time(buf):
    logger = logging.getLogger(__name__)
    microsecond = (buf[1] & 0xFF) << 8 | (buf[0] & 0xFF)
    microsecond %= 1000
    second = int(microsecond)
    minute = buf[2] & 0x3F
    hour = buf[3] & 0x1F
    day = buf[4] & 0x1F
    month = (buf[5] & 0x0F) - 1
    year = (buf[6] & 0x7F) + 2000
    logger.debug("{}.{}.{}.{}.{}.{}".format(
        year, month, day, hour, minute, second))

    return datetime(year, month, day, minute, hour, second, microsecond)


class ASDU(object):
    def __init__(self, data):
        logger = logging.getLogger(__name__)
        self.type_id = data.read('uint:8')
        logger.debug(self.type_id)
        self.sq = data.read('bool')  # Single or Sequence
        self.sq_count = data.read('uint:7')
        self.t = data.read('bool')  # Single or Sequence
        self.pn = data.read('bool')  # Single or Sequence
        self.cot = data.read('uint:6')
        self.org = data.read('uint:8')  # new
        self.asdu = data.read('uintle:16')
        logger.debug("ASDU received")
        logger.debug("Number of objects: %s", str(self.sq_count))
        if self.sq_count != 0:
            logger.debug("Length per object: %s", str(
                (len(data)-48)/self.sq_count))
        logger.debug("Type id: {}, SQ: {}, Num obj: {}, T: {}, PN: {}, COT: {}, ORG: {}, ASDU: {}".format(self.type_id, self.sq, self.sq_count, self.t, self.pn, self.cot, self.org, self.asdu))

        self.objs = []
        if not self.sq:
            try:
                for i in range(self.sq_count):
                    ioa = data.read("intle:24")
                    obj = InfoObjMeta.types[self.type_id](data)
                    obj.__dict__['ioa'] = ioa
                    self.objs.append(obj)

            except:
                logger.debug("Error during parsing ASDU object with sq = False: %s",
                             str(sys.exc_info()[0]))
            # LEER SECUENCIA SELF.SQ_READ(...)
        else:
            try:
                for i in range(self.sq_count):
                    if i == 0:
                        logger.debug("First Object.")
                        ioa = data.read("intle:24")
                        obj = InfoObjMeta.types[self.type_id](data)
                        obj.__dict__['ioa'] = ioa
                    else:
                        logger.debug("Last obj: %s", str(obj.__dict__))
                        ioa = int(obj.__dict__['ioa'])+1
                        obj = InfoObjMeta.types[self.type_id](data)
                        obj.__dict__['ioa'] = ioa
                    self.objs.append(obj)

            except Exception as except_data:
                logger.error("Error during parsing ASDU object with sq = True: %s. Error: %s",
                             str(sys.exc_info()[0]), except_data)


class QDS(object):
    def __init__(self, data):

        overflow = bool(data & 0x01)
        blocked = bool(data & 0x10)
        substituted = bool(data & 0x20)
        not_topical = bool(data & 0x40)
        invalid = bool(data & 0x80)


class InfoObjMeta(type):
    types = {}

    def __new__(mcs, name, bases, dct):
        re = type.__new__(mcs, name, bases, dct)
        if 'type_id' in dct:
            InfoObjMeta.types[dct['type_id']] = re
        return re


class InfoObj(metaclass=InfoObjMeta):

    def __init__(self, data):
        logger = logging.getLogger(__name__)

        try:
            self.value = None
            self.ioa = None
            #self.ioa = ioa if ioa else data.read("intle:24")
            logger.debug("IOA: %s", self.ioa)

        except Exception as except_data:
            logger.error("Error during creation InfoObj: %s", except_data)


class SIQ(InfoObj):
    def __init__(self, data):
        super(SIQ, self).__init__(data)
        self.iv = data.read('bool')
        self.nt = data.read('bool')
        self.sb = data.read('bool')
        self.bl = data.read('bool')
        data.read('int:3')  # reserve
        self.spi = data.read('bool')


class DIQ(InfoObj):
    def __init__(self, data):
        super(DIQ, self).__init__(data)
        self.iv = data.read('bool')
        self.nt = data.read('bool')
        self.sb = data.read('bool')
        self.bl = data.read('bool')
        data.read('int:2')  # reserve
        self.dpi = data.read('uint:2')


class MSpNa1(SIQ):
    type_id = 1
    name = 'M_SP_NA_1'
    description = 'Single-point information without time tag'

    def __init__(self, data):
        logger = logging.getLogger(__name__)
        super(MSpNa1, self).__init__(data)
        self.value = self.spi
        logger.debug('Obj: M_SP_NA_1, Value: {}'.format(self.spi))


class MSpTa1(InfoObj):
    type_id = 2
    name = 'M_SP_TA_1'
    description = 'Single-point information with time tag'

    def __init__(self, data):
        super(MSpTa1, self).__init__(data)


class MDpNa1(DIQ):
    type_id = 3
    name = 'M_DP_NA_1'
    description = 'Double-point information without time tag'

    def __init__(self, data):
        logger = logging.getLogger(__name__)
        super(MDpNa1, self).__init__(data)
        logger.debug('Obj: M_DP_NA_1, Value: {}'.format(self.dpi))


class MDpTa1(InfoObj):
    type_id = 4
    name = 'M_DP_TA_1'
    description = 'Double-point information with time tag'


class MStNa1(InfoObj):
    type_id = 5
    name = 'M_ST_NA_1'
    description = 'Step position information'


class MStTa1(InfoObj):
    type_id = 6
    name = 'M_ST_TA_1'
    description = 'Step position information with time tag'


class MBoNa1(InfoObj):
    type_id = 7
    name = 'M_BO_NA_1'
    description = 'Bitstring of 32 bit'


class MBoTa1(InfoObj):
    type_id = 8
    name = 'M_BO_TA_1'
    description = 'Bitstring of 32 bit with time tag'


class MMeNa1(InfoObj):
    type_id = 9
    name = 'M_ME_NA_1'
    description = 'Measured value, normalized value'

    def __init__(self, data):
        logger = logging.getLogger(__name__)
        try:
            logger.debug("Parsing M_ME_NA_1")
            super(MMeNa1, self).__init__(data)
            nva = data.read("intle:16")
            self.value = nva
            logger.debug('Obj: M_ME_NA_1, Value: {}'.format(nva))
            self.iv = data.read('bool')
            self.nt = data.read('bool')
            self.sb = data.read('bool')
            self.bl = data.read('bool')
            data.read('bool')
            data.read('bool')
            data.read('bool')
            self.ov = data.read('bool')
            logger.debug('Obj: M_ME_NA_1, Qua: Invalid {} Not topical {} Sustituted {} Blocked {} Overflow {} '.format(
                self.iv, self.nt, self.sb, self.bl, self.ov))
        except Exception as exception_information:
            logger.error("Error during parsing M_ME_NA_1: %s",
                         exception_information)
            raise Exception(exception_information)


class MMeTa1(InfoObj):
    type_id = 10
    name = 'M_ME_TA_1'
    description = 'Measured value, normalized value with time tag'


class MMeNb1(InfoObj):
    type_id = 11
    name = 'M_ME_NB_1'
    description = 'Measured value, scaled value'

    def __init__(self, data):
        logger = logging.getLogger(__name__)
        super(MMeNb1, self).__init__(data)
        logger.debug('Obj: M_ME_NB_1')
        try:
            sva = data.read("intle:16")
            self.value = sva
            self.iv = data.read('bool')
            self.nt = data.read('bool')
            self.sb = data.read('bool')
            self.bl = data.read('bool')
            self.ov = data.read('bool')
            self.ov = data.read('bool')
            self.ov = data.read('bool')
            self.ov = data.read('bool')
            logger.debug('Obj: M_ME_NB_1, Qua: Invalid {} Not topical {} Sustituted {} Blocked {} Overflow {} value {}'.format(
                self.iv, self.nt, self.sb, self.bl, self.ov, self.value))
        except Exception as exception_data:
            logger.error("Exception during parsing M_ME_NB_1: %s",
                         exception_data)


class MMeTb1(InfoObj):
    type_id = 12
    name = 'M_ME_TB_1'
    description = 'Measured value, scaled value with time tag'


class MMeNc1(InfoObj):
    type_id = 13
    name = 'M_ME_NC_1'
    description = 'Measured value, short floating point number'
    length = 5

    def __init__(self, data):
        logger = logging.getLogger(__name__)
        super(MMeNc1, self).__init__(data)
        # print(data)
        logger.debug('Obj: M_ME_NC_1')

        try:
            self.value = data.read("floatle:32")

            self.iv = data.read('bool')
            self.nt = data.read('bool')
            self.sb = data.read('bool')
            self.bl = data.read('bool')
            self.ov = data.read('bool')
            self.ov = data.read('bool')
            self.ov = data.read('bool')
            self.ov = data.read('bool')
            logger.debug('Obj: M_ME_NC_1, Qua: Invalid {} Not topical {} Sustituted {} Blocked {} Overflow {} '.format(
                self.iv, self.nt, self.sb, self.bl, self.ov))
        except Exception as exception_data:
            logger.error("Exception during parsing M_ME_NC_1: %s",
                         exception_data)


class MMeTc1(InfoObj):
    type_id = 14
    name = 'M_ME_TC_1'
    description = 'Measured value, short floating point number with time tag'


class MItNa1(InfoObj):
    type_id = 15
    name = 'M_IT_NA_1'
    description = 'Integrated totals'
    length = 5

    def __init__(self, data):
        logger = logging.getLogger(__name__)
        super(MItNa1, self).__init__(data)
        # print(data)
        logger.debug('Obj: M_IT_NA_1')

        try:
            self.value = data.read("uintle:24")

            self.iv = data.read('bool')
            self.ca = data.read('bool')
            self.cy = data.read('bool')
            self.sequence = data.read("unitle:5")

            logger.debug('Obj: M_IT_NA_1, Invalid {} Adjust flag {} Carry flag {} Sequence {} '.format(
                self.iv, self.ca, self.cy, self.sequence))
        except Exception as exception_data:
            logger.error("Exception during parsing M_IT_NA_1: %s",
                         exception_data)


class MItTa1(InfoObj):
    type_id = 16
    name = 'M_IT_TA_1'
    description = 'Integrated totals with time tag'


class MEpTa1(InfoObj):
    type_id = 17
    name = 'M_EP_TA_1'
    description = 'Event of protection equipment with time tag'


class MEpTb1(InfoObj):
    type_id = 18
    name = 'M_EP_TB_1'
    description = 'Packed start events of protection equipment with time tag'


class MEpTc1(InfoObj):
    type_id = 19
    name = 'M_EP_TC_1'
    description = 'Packed output circuit information of protection equipment with time tag'


class MPsNa1(InfoObj):
    type_id = 20
    name = 'M_PS_NA_1'
    description = 'Packed single-point information with status change detection'


class MMeNd1(InfoObj):
    type_id = 21
    name = 'M_ME_ND_1'
    description = 'Measured value, normalized value without quality descriptor'


class MSpTb1(InfoObj):
    type_id = 30
    name = 'M_SP_TB_1'
    description = 'Single-point information with time tag CP56Time2a'

    def __init__(self, data):
        logger = logging.getLogger(__name__)
        super(MSpTb1, self).__init__(data)
        logger.debug('Obj: M_SP_TB_1')

        self.iv = data.read('bool')

        self.nt = data.read('bool')
        self.sb = data.read('bool')
        self.bl = data.read('bool')
        data.read('bool')
        data.read('bool')
        data.read('bool')
        self.spi = data.read('bool')
        ts = data.read(56)
        self.value = self.spi
        logger.debug('Obj: M_SP_TB_1, Qua: Invalid {} Not topical {} Sustituted {} Blocked {} value {} Date {}'.format(
            self.iv, self.nt, self.sb, self.bl, self.spi, ts))


class MDpTb1(InfoObj):
    type_id = 31
    name = 'M_DP_TB_1'
    description = 'Double-point information with time tag CP56Time2a'


class MStTb1(InfoObj):
    type_id = 32
    name = 'M_ST_TB_1'
    description = 'Step position information with time tag CP56Time2a'


class MBoTb1(InfoObj):
    type_id = 33
    name = 'M_BO_TB_1'
    description = 'Bitstring of 32 bits with time tag CP56Time2a'


class MMeTd1(InfoObj):
    type_id = 34
    name = 'M_ME_TD_1'
    description = 'Measured value, normalized value with time tag CP56Time2a'

    def __init__(self, data):
        logger = logging.getLogger(__name__)
        super(MMeTd1, self).__init__(data)
        val = data.read("intle:16")
        logger.debug('Obj: M_ME_TD_1, Value: {}'.format(val))
        self.iv = data.read('bool')
        self.nt = data.read('bool')
        self.sb = data.read('bool')
        self.bl = data.read('bool')
        self.ov = data.read('bool')
        self.ov = data.read('bool')
        self.ov = data.read('bool')
        self.ov = data.read('bool')

        ts = data.read(56)

        self.value = val
        logger.debug('Obj: M_ME_TD_1, Qua: Invalid {} Not topical {} Sustituted {} Blocked {} Overflow {} Date {}'.format(
            self.iv, self.nt, self.sb, self.bl, self.ov, ts))


class MMeTe1(InfoObj):
    type_id = 35
    name = 'M_ME_TE_1'
    description = 'Measured value, scaled value with time tag CP56Time2a'

    def __init__(self, data):
        logger = logging.getLogger(__name__)
        super(MMeTe1, self).__init__(data)
        val = data.read("intle:16")
        logger.debug('Obj: M_ME_TE_1, Value: {}'.format(val))
        self.iv = data.read('bool')
        self.nt = data.read('bool')
        self.sb = data.read('bool')
        self.bl = data.read('bool')
        self.ov = data.read('bool')
        self.ov = data.read('bool')
        self.ov = data.read('bool')
        self.ov = data.read('bool')

        ts = data.read(56)

        self.value = val
        logger.debug('Obj: M_ME_TE_1, Qua: Invalid {} Not topical {} Sustituted {} Blocked {} Overflow {} Date {}'.format(
            self.iv, self.nt, self.sb, self.bl, self.ov, ts))


class MMeTf1(InfoObj):
    type_id = 36
    name = 'M_ME_TF_1'
    description = 'Measured value, short floating point number with time tag CP56Time2a'

    def __init__(self, data):
        logger = logging.getLogger(__name__)
        super(MMeTf1, self).__init__(data)
        try:
            self.value = data.read("floatle:32")
        except Exception as except_data:
            logger.error(except_data)
        logger.debug('Obj: M_ME_TF_1, Value: {}'.format(self.value))
        self.iv = data.read('bool')
        self.nt = data.read('bool')
        self.sb = data.read('bool')
        self.bl = data.read('bool')
        self.ov = data.read('bool')
        self.ov = data.read('bool')
        self.ov = data.read('bool')
        self.ov = data.read('bool')
        logger.debug('Obj: M_ME_TF_1, Qua: Invalid {} Not topical {} Sustituted {} Blocked {} Overflow {}'.format(
            self.iv, self.nt, self.sb, self.bl, self.ov))
        ts = data.read(56)


class MItTb1(InfoObj):
    type_id = 37
    name = 'M_IT_TB_1'
    description = 'Integrated totals with time tag CP56Time2a'


class MEpTd1(InfoObj):
    type_id = 38
    name = 'M_EP_TD_1'
    description = 'Event of protection equipment with time tag CP56Time2a'


class MEpTe1(InfoObj):
    type_id = 39
    name = 'M_EP_TE_1'
    description = 'Packed start events of protection equipment with time tag CP56Time2a'


class MEpTf1(InfoObj):
    type_id = 40
    name = 'M_EP_TF_1'
    description = 'Packed output circuit information of protection equipment with time tag CP56Time2a'


class CScNa1(InfoObj):
    type_id = 45
    name = 'C_SC_NA_1'
    description = 'Single command'


class CDcNa1(InfoObj):
    type_id = 46
    name = 'C_DC_NA_1'
    description = 'Double command'


class CRcNa1(InfoObj):
    type_id = 47
    name = 'C_RC_NA_1'
    description = 'Regulating step command'


class CSeNa1(InfoObj):
    type_id = 48
    name = 'C_SE_NA_1'
    description = 'Set-point command, normalized value'


class CSeNb1(InfoObj):
    type_id = 49
    name = 'C_SE_NB_1'
    description = 'Set-point command, scaled value'


class CSeNc1(InfoObj):
    type_id = 50
    name = 'C_SE_NC_1'
    description = 'Set-point command, short floating point number'


class CBoNa1(InfoObj):
    type_id = 51
    name = 'C_BO_NA_1'
    description = 'Bitstring of 32 bit'


class MEiNa1(InfoObj):
    type_id = 70
    name = 'M_EI_NA_1'
    description = 'End of initialization'


class CIcNa1(InfoObj):
    type_id = 100
    name = 'C_IC_NA_1'
    description = 'Interrogation command'


class CCiNa1(InfoObj):
    type_id = 101
    name = 'C_CI_NA_1'
    description = 'Counter interrogation command'


class CRdNa1(InfoObj):
    type_id = 102
    name = 'C_RD_NA_1'
    description = 'Read command'


class CCsNa1(InfoObj):
    type_id = 103
    name = 'C_CS_NA_1'
    description = 'Clock synchronization command'


class CTsNa1(InfoObj):
    type_id = 104
    name = 'C_TS_NA_1'
    description = 'Test command'


class CRpNa1(InfoObj):
    type_id = 105
    name = 'C_RP_NA_1'
    description = 'Reset process command'


class CCdNa1(InfoObj):
    type_id = 106
    name = 'C_CD_NA_1'
    descripiton = 'Delay acquisition command'


class PMeNa1(InfoObj):
    type_id = 110
    name = 'P_ME_NA_1'
    description = 'Parameter of measured values, normalized value'

    def __init__(self, data):
        logger = logging.getLogger(__name__)
        super(PMeNa1, self).__init__(data)
        self.nva = data.read('int:8')
        logger.debug('Obj: P_ME_NA_1, Value: {}'.format(self.nva))


class PMeNb1(InfoObj):
    type_id = 111
    name = 'P_ME_NB_1'
    description = 'Parameter of measured values, scaled value'

    def __init__(self, data):
        logger = logging.getLogger(__name__)
        super(PMeNb1, self).__init__(data)
        self.sva = data.read('int:8')
        self.lpc = data.read('bool')
        self.pop = data.read('bool')
        self.kpa = data.read('int:6')
        logger.debug('Obj: P_ME_NB_1, Value: {}'.format(self.sva))


class PMeNc1(InfoObj):
    type_id = 112
    name = 'P_ME_NC_1'
    description = 'Parameter of measured values, short floating point number'

    def __init__(self, data):
        logger = logging.getLogger(__name__)
        super(PMeNc1, self).__init__(data)
        self.nva = data.read('float:8')
        logger.debug('Obj: P_ME_NC_1, Value: {}'.format(self.nva))


class PAcNa1(InfoObj):
    type_id = 113
    name = 'P_AC_NA_1'
    description = 'Parameter activation'


class FFrNa1(InfoObj):
    type_id = 120
    name = 'F_FR_NA_1'
    description = 'File ready'


class FSrNa1(InfoObj):
    type_id = 121
    name = 'F_SR_NA_1'
    description = 'Section ready'


class FScNa1(InfoObj):
    type_id = 122
    name = 'F_SC_NA_1'
    description = 'Call directory, select file, call file, call section'


class FLsNa1(InfoObj):
    type_id = 123
    name = 'F_LS_NA_1'
    description = 'Last section, last segment'


class FAdNa1(InfoObj):
    type_id = 124
    name = 'F_AF_NA_1'
    description = 'ACK file, ACK section'


class FSgNa1(InfoObj):
    type_id = 125
    name = 'F_SG_NA_1'
    description = 'Segment'


class FDrTa1(InfoObj):
    type_id = 126
    name = 'F_DR_TA_1'
    description = 'Directory'


def get_C_RD_NA_1_ASDU(ASDU, IOA):
    """
    Obtiene un mensaje de petición de lectura.
    """
    frame = [None] * 15
    frame[0] = 0x68
    frame[1] = 0x0d  # LENGTH
    tx_count_frame, rx_count_frame = get_TX_RX_frame()
    """ print(tx_count_frame)
    print(rx_count_frame) """
    frame[2] = int(tx_count_frame[0], 16)  # TX[1]<<7 + 0 (MULTIPLICAR * 2)

    frame[3] = int(tx_count_frame[1], 16)  # TX[2]

    frame[4] = int(rx_count_frame[0], 16)  # RX[1]<<7 + 0 (MULTIPLICAR * 2)

    frame[5] = int(rx_count_frame[1], 16)

    frame[6] = 0x66
    frame[7] = 0x01
    frame[8] = 0x05  # COT
    frame[9] = 0x00
    frame_10, frame_11 = ASDU_to_frame(ASDU)
    frame[10] = int(frame_10, 16)
    frame[11] = int(frame_11, 16)
    """ frame[10] = hex_line_list[0]#0x29#asdu.hex()
    frame[11] = hex_line_list[1] """
    """ hex_line = int(IOA).to_bytes(3,'little').hex()
    hex_line_list = [hex_line[i:i+2] for i in range(0,len(hex_line),2)] """
    frame_12, frame_13, frame_14 = IOA_to_frame(IOA)
    frame[12] = int(frame_12, 16)
    frame[13] = int(frame_13, 16)
    frame[14] = int(frame_14, 16)
    """ frame[13] = hex(int(hex_line_list[1],16)) #IOA B
    frame[14] = hex(int(hex_line_list[2],16)) # IOA BB """
    return frame


def get_C_IC_NA_1_ASDU(ASDU, IOA):
    """
    Obtiene un mensaje de petición de lectura general.
    """
    frame = [None] * 16
    frame[0] = 0x68
    frame[1] = 0x0e  # LENGTH
    tx_count_frame, rx_count_frame = get_TX_RX_frame()
    """ print(tx_count_frame)
    print(rx_count_frame) """
    frame[2] = int(tx_count_frame[0], 16)  # TX[1]<<7 + 0 (MULTIPLICAR * 2)

    frame[3] = int(tx_count_frame[1], 16)  # TX[2]

    frame[4] = int(rx_count_frame[0], 16)  # RX[1]<<7 + 0 (MULTIPLICAR * 2)

    frame[5] = int(rx_count_frame[1], 16)

    frame[6] = 0x64
    frame[7] = 0x01
    frame[8] = 0x06  # COT
    frame[9] = 0x00
    frame_10, frame_11 = ASDU_to_frame(ASDU)
    frame[10] = int(frame_10, 16)
    frame[11] = int(frame_11, 16)
    """ frame[10] = hex_line_list[0]#0x29#asdu.hex()
    frame[11] = hex_line_list[1] """
    """ hex_line = int(IOA).to_bytes(3,'little').hex()
    hex_line_list = [hex_line[i:i+2] for i in range(0,len(hex_line),2)] """

    frame[12] = 0x00
    frame[13] = 0x00
    frame[14] = 0x00
    # Group to be request
    frame[15] = 0x14
    """ frame[13] = hex(int(hex_line_list[1],16)) #IOA B
    frame[14] = hex(int(hex_line_list[2],16)) # IOA BB """
    return frame


def get_C_SE_NC_1_ASDU(ASDU, IOA, data):
    """
    Set-point command, short floating point value without time tag.
    """
    frame = [None] * 15
    frame[0] = 0x68
    frame[1] = 0x0d 
    tx_count_frame, rx_count_frame = get_TX_RX_frame()

    frame[2] = int(tx_count_frame[0], 16)

    frame[3] = int(tx_count_frame[1], 16)

    frame[4] = int(rx_count_frame[0], 16) 

    frame[5] = int(rx_count_frame[1], 16)

    frame[6] = 0x32
    frame[7] = 0x01
    frame[8] = 0x06  # COT
    frame[9] = 0x00
    frame_10, frame_11 = ASDU_to_frame(ASDU)
    frame[10] = int(frame_10, 16)
    frame[11] = int(frame_11, 16)

    frame_12, frame_13, frame_14 = IOA_to_frame(IOA)
    frame[12] = int(frame_12, 16)
    frame[13] = int(frame_13, 16)
    frame[14] = int(frame_14, 16)

    frame_15, frame_16, frame_17, frame_18 = parse_data_to_float32le(data)
    frame[15] = int(frame_15, 16)
    frame[16] = int(frame_16, 16)
    frame[17] = int(frame_17, 16)
    frame[18] = int(frame_18, 16)
    frame[19] = 0

    return frame


def parse_data_to_float32le(data):
    hex_line = struct.pack('<f', data).hex()
    hex_line_list = [hex_line[i:i+2] for i in range(0, len(hex_line), 2)]
    return hex_line_list


def IOA_to_frame(IOA):
    hex_line = int(IOA).to_bytes(3, 'little').hex()
    hex_line_list = [hex_line[i:i+2] for i in range(0, len(hex_line), 2)]
    return [hex(int(hex_line_list[0], 16)), hex(int(hex_line_list[1], 16)), hex(int(hex_line_list[2], 16))]


def ASDU_to_frame(ASDU):
    hex_line = int(ASDU).to_bytes(2, 'little').hex()
    hex_line_list = [hex_line[i:i+2] for i in range(0, len(hex_line), 2)]
    return [hex(int(hex_line_list[0], 16)), hex(int(hex_line_list[1], 16))]


def get_TX_RX_frame():

    hex_line = int(tx_count).to_bytes(2, 'little').hex()
    hex_line_list_tx_count = [hex_line[i:i+2]
                              for i in range(0, len(hex_line), 2)]
    tx_count_result = [hex(int(hex_line_list_tx_count[0], 16)*2),
                       hex(int(hex_line_list_tx_count[1], 16))]

    hex_line = int(rx_count).to_bytes(2, 'little').hex()
    hex_line_list_rx_count = [hex_line[i:i+2]
                              for i in range(0, len(hex_line), 2)]
    rx_count_result = [hex(int(hex_line_list_rx_count[0], 16)*2),
                       hex(int(hex_line_list_rx_count[1], 16))]
    print([tx_count_result, rx_count_result])
    return [tx_count_result, rx_count_result]


def increment_rx():
    global rx_count
    rx_count += 1


def increment_tx():
    global tx_count
    tx_count += 1


def default_rx_tx_values():
    global tx_count
    global rx_count
    tx_count = 0
    rx_count = 0


def get_C_CI_NA_1_ASDU(ASDU, IOA):
    """
    Obtiene un mensaje de petición de lectura general.
    """
    frame = [None] * 16
    frame[0] = 0x68
    frame[1] = 0x0e  # LENGTH
    tx_count_frame, rx_count_frame = get_TX_RX_frame()
    """ print(tx_count_frame)
    print(rx_count_frame) """
    frame[2] = int(tx_count_frame[0], 16)

    frame[3] = int(tx_count_frame[1], 16)

    frame[4] = int(rx_count_frame[0], 16)

    frame[5] = int(rx_count_frame[1], 16)

    frame[6] = 0x65
    frame[7] = 0x01
    frame[8] = 0x06  # COT
    frame[9] = 0x00
    frame_10, frame_11 = ASDU_to_frame(ASDU)
    frame[10] = int(frame_10, 16)
    frame[11] = int(frame_11, 16)
    """ frame[10] = hex_line_list[0]#0x29#asdu.hex()
    frame[11] = hex_line_list[1] """
    """ hex_line = int(IOA).to_bytes(3,'little').hex()
    hex_line_list = [hex_line[i:i+2] for i in range(0,len(hex_line),2)] """

    frame[12] = 0x00
    frame[13] = 0x00
    frame[14] = 0x00
    frame[15] = 0x05
    """ frame[13] = hex(int(hex_line_list[1],16)) #IOA B
    frame[14] = hex(int(hex_line_list[2],16)) # IOA BB """
    return frame
