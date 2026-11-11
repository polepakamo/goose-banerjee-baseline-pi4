/*
 *  goose_receiver.c - DROP-IN REPLACEMENT for libIEC61850 v1.5.3 src/goose/goose_receiver.c
 *
 *  Identical to the stock receiver (all BER parsing is the stock code) except:
 *    - parseGooseMessage() applies the scheme selected by GOOSE_SCHEME
 *      (none | banerjee), see goose_sec.h
 *    - every received frame produces one record in the gs_log ring:
 *        T_proc, stNum, sqNum, frame length, verdict
 *
 *  T_proc boundary - the SAME for all three schemes:
 *    start : immediately AFTER select() returns (EthernetHandleSet_waitReady),
 *            before recv()                              [gooseReceiverLoop]
 *    end   : immediately after the subscriber callback has returned (delivered),
 *            or at the point the frame is rejected (rejected frames)
 *    so it contains recv(), header parse, subscriber lookup, extension parse,
 *    AEAD, BER decode of the PDU, and the callback - and no idle waiting.
 */

#include "libiec61850_platform_includes.h"
#include "stack_config.h"
#include "goose_subscriber.h"
#include "hal_ethernet.h"
#include "hal_thread.h"
#include "ber_decode.h"
#include "mms_value.h"
#include "mms_value_internal.h"
#include "linked_list.h"
#include "goose_receiver.h"
#include "goose_receiver_internal.h"
#include <time.h>

#include "goose_sec.h"

/* Ascon-AEAD128, NIST LWC API (ascon-c, crypto_aead/asconaead128/ref) */
extern int crypto_aead_decrypt(
    unsigned char *m,        unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c,  unsigned long long  clen,
    const unsigned char *ad, unsigned long long  adlen,
    const unsigned char *npub,
    const unsigned char *k);

#ifndef DEBUG_GOOSE_SUBSCRIBER
#define DEBUG_GOOSE_SUBSCRIBER 0
#endif

#define ETH_BUFFER_LENGTH 1518
#define ETH_P_GOOSE       0x88b8

/* ---- per-frame timing / logging state (receiver thread only) ------------- */
static struct timespec s_t_start;
static uint32_t        s_frame_len = 0;

static inline uint64_t ts_ns(const struct timespec* t)
{
    return (uint64_t) t->tv_sec * 1000000000ULL + (uint64_t) t->tv_nsec;
}

/* close the measurement for the current frame and publish one log record */
static void
gsFinish(uint32_t verdict, uint32_t st, uint32_t sq)
{
    struct timespec te;
    gs_rec_t r;
    clock_gettime(CLOCK_MONOTONIC, &te);
    r.t_proc_ns = ts_ns(&te) - ts_ns(&s_t_start);
    r.st = st; r.sq = sq;
    r.frame_len = s_frame_len;
    r.verdict = verdict;
    gs_log_push(&r);
}


/* ---- VLAN-aware kernel filter ---------------------------------------------------------------
 * Stock libIEC61850 v1.5.3 Ethernet_setProtocolFilter(0x88b8) attaches a filter that tests the
 * EtherType at byte 12 only. A VLAN-tagged GOOSE frame (the normal case, and the paper's 202/261
 * byte frames) has 0x8100 there, so on a NIC that does not strip the tag the stock filter drops
 * every frame. This filter accepts EtherType 0x88b8 at byte 12 (untagged / tag stripped) or
 * 0x8100 at byte 12 followed by 0x88b8 at byte 16 (tag still in the packet).
 * EthernetSocket is opaque; in v1.5.3 (hal/ethernet/linux/ethernet_linux.c) its first member is
 * the raw socket file descriptor. */
#include <sys/socket.h>
#include <linux/filter.h>

static void
gsAttachGooseFilter(EthernetSocket sock)
{
    struct sock_filter code[] = {
        { 0x28, 0, 0, 0x0000000c },   /* ldh [12]                      */
        { 0x15, 3, 0, 0x000088b8 },   /* jeq 0x88b8 -> accept          */
        { 0x15, 0, 3, 0x00008100 },   /* jeq 0x8100 ? next : reject    */
        { 0x28, 0, 0, 0x00000010 },   /* ldh [16]                      */
        { 0x15, 0, 1, 0x000088b8 },   /* jeq 0x88b8 ? accept : reject  */
        { 0x06, 0, 0, 0x00040000 },   /* accept                        */
        { 0x06, 0, 0, 0x00000000 },   /* reject                        */
    };
    struct sock_fprog fprog;
    int fd = *(int*) sock;

    fprog.len = (unsigned short)(sizeof(code) / sizeof(code[0]));
    fprog.filter = code;
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) == -1)
        perror("gs: attaching the GOOSE filter failed");
}

/* set by the strict baseline filter to drop the frame instead of delivering it */
static bool s_strict_active = false;

struct sGooseReceiver
{
    bool running;
    bool stop;
    char* interfaceId;
    uint8_t* buffer;
    EthernetSocket ethSocket;
    LinkedList subscriberList;
#if (CONFIG_MMS_THREADLESS_STACK == 0)
    Thread thread;
#endif
};

GooseReceiver GooseReceiver_createEx(uint8_t* buffer)
{
    GooseReceiver self = (GooseReceiver) GLOBAL_MALLOC(sizeof(struct sGooseReceiver));
    if (self != NULL) {
        self->running = false; self->stop = false;
        self->interfaceId = NULL; self->buffer = buffer;
        self->ethSocket = NULL;
        self->subscriberList = LinkedList_create();
#if (CONFIG_MMS_THREADLESS_STACK == 0)
        self->thread = NULL;
#endif
    }
    return self;
}

GooseReceiver GooseReceiver_create()
{
    GooseReceiver self = GooseReceiver_createEx(NULL);
    if (self) self->buffer = (uint8_t*) GLOBAL_MALLOC(ETH_BUFFER_LENGTH);
    return self;
}

void GooseReceiver_addSubscriber(GooseReceiver self, GooseSubscriber subscriber)
    { LinkedList_add(self->subscriberList, (void*) subscriber); }
void GooseReceiver_removeSubscriber(GooseReceiver self, GooseSubscriber subscriber)
    { LinkedList_remove(self->subscriberList, (void*) subscriber); }
void GooseReceiver_setInterfaceId(GooseReceiver self, const char* interfaceId)
{
    if (self->interfaceId != NULL) GLOBAL_FREEMEM(self->interfaceId);
    self->interfaceId = StringUtils_copyString(interfaceId);
}
const char* GooseReceiver_getInterfaceId(GooseReceiver self)
{
    if (self->interfaceId) return self->interfaceId;
    return CONFIG_ETHERNET_INTERFACE_ID;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * FULL ORIGINAL parseAllData — no simplifications, all tag types handled.
 * This ensures the same BER-parsing overhead as the unmodified libiec61850.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void
createNewStringFromBufferElement(MmsValue* value, uint8_t* bufferSrc, int elementLength)
{
    value->value.visibleString.buf = (char*) GLOBAL_MALLOC(elementLength + 1);
    memcpy(value->value.visibleString.buf, bufferSrc, elementLength);
    value->value.visibleString.buf[elementLength] = 0;
    value->value.visibleString.size = elementLength;
}

static GooseParseError
parseAllData(uint8_t* buffer, int allDataLength, MmsValue* dataSetValues)
{
    int bufPos = 0;
    int elementLength = 0;
    int elementIndex = 0;
    int maxIndex = MmsValue_getArraySize(dataSetValues) - 1;
    GooseParseError pe = GOOSE_PARSE_ERROR_NO_ERROR;
    uint8_t tag;

    while (bufPos < allDataLength) {
        tag = buffer[bufPos++];
        if (elementIndex > maxIndex) { pe = GOOSE_PARSE_ERROR_OVERFLOW; break; }
        MmsValue* value = MmsValue_getElement(dataSetValues, elementIndex);
        if (value == NULL) return GOOSE_PARSE_ERROR_TYPE_MISMATCH;
        bufPos = BerDecoder_decodeLength(buffer, &elementLength, bufPos, allDataLength);
        if (bufPos < 0) { pe = GOOSE_PARSE_ERROR_TAGDECODE; break; }
        switch (tag) {
        case 0x80: break;
        case 0xa1:
            if (MmsValue_getType(value)==MMS_ARRAY) {
                if (parseAllData(buffer+bufPos, elementLength, value)!=GOOSE_PARSE_ERROR_NO_ERROR) pe=GOOSE_PARSE_ERROR_SUBLEVEL;
            } else pe=GOOSE_PARSE_ERROR_TYPE_MISMATCH; break;
        case 0xa2:
            if (MmsValue_getType(value)==MMS_STRUCTURE) {
                if (parseAllData(buffer+bufPos, elementLength, value)!=GOOSE_PARSE_ERROR_NO_ERROR) pe=GOOSE_PARSE_ERROR_SUBLEVEL;
            } else pe=GOOSE_PARSE_ERROR_TYPE_MISMATCH; break;
        case 0x83:
            if (MmsValue_getType(value)==MMS_BOOLEAN) MmsValue_setBoolean(value, BerDecoder_decodeBoolean(buffer, bufPos));
            else pe=GOOSE_PARSE_ERROR_TYPE_MISMATCH; break;
        case 0x84:
            if (MmsValue_getType(value)==MMS_BIT_STRING) {
                int padding=buffer[bufPos];
                if (padding>7) { pe=GOOSE_PARSE_ERROR_INVALID_PADDING; break; }
                int bitStringLength=(8*(elementLength-1))-padding;
                if (bitStringLength==value->value.bitString.size)
                    memcpy(value->value.bitString.buf, buffer+bufPos+1, elementLength-1);
                else pe=GOOSE_PARSE_ERROR_LENGTH_MISMATCH;
            } else pe=GOOSE_PARSE_ERROR_TYPE_MISMATCH; break;
        case 0x85:
            if (MmsValue_getType(value)==MMS_INTEGER) {
                if (elementLength<=value->value.integer->maxSize) {
                    value->value.integer->size=elementLength;
                    memcpy(value->value.integer->octets, buffer+bufPos, elementLength);
                } else pe=GOOSE_PARSE_ERROR_LENGTH_MISMATCH;
            } else pe=GOOSE_PARSE_ERROR_TYPE_MISMATCH; break;
        case 0x86:
            if (MmsValue_getType(value)==MMS_UNSIGNED) {
                if (elementLength<=value->value.integer->maxSize) {
                    value->value.integer->size=elementLength;
                    memcpy(value->value.integer->octets, buffer+bufPos, elementLength);
                } else pe=GOOSE_PARSE_ERROR_LENGTH_MISMATCH;
            } else pe=GOOSE_PARSE_ERROR_TYPE_MISMATCH; break;
        case 0x87:
            if (MmsValue_getType(value)==MMS_FLOAT) {
                if (elementLength==9) MmsValue_setDouble(value, BerDecoder_decodeDouble(buffer,bufPos));
                else if (elementLength==5) MmsValue_setFloat(value, BerDecoder_decodeFloat(buffer,bufPos));
                else pe=GOOSE_PARSE_ERROR_LENGTH_MISMATCH;
            } else pe=GOOSE_PARSE_ERROR_TYPE_MISMATCH; break;
        case 0x89:
            if (MmsValue_getType(value)==MMS_OCTET_STRING) {
                if (elementLength<=abs(value->value.octetString.maxSize)) {
                    value->value.octetString.size=elementLength;
                    memcpy(value->value.octetString.buf, buffer+bufPos, elementLength);
                } else {
                    uint8_t* newBuf=(uint8_t*)GLOBAL_MALLOC(elementLength);
                    if (newBuf) {
                        memcpy(newBuf, buffer+bufPos, elementLength);
                        uint8_t* oldBuf=value->value.octetString.buf;
                        value->value.octetString.buf=newBuf;
                        value->value.octetString.maxSize=-elementLength;
                        value->value.octetString.size=elementLength;
                        GLOBAL_FREEMEM(oldBuf);
                    }
                }
            } else pe=GOOSE_PARSE_ERROR_TYPE_MISMATCH; break;
        case 0x8a:
            if (MmsValue_getType(value)==MMS_VISIBLE_STRING) {
                if (value->value.visibleString.buf!=NULL) {
                    if ((int32_t)value->value.visibleString.size>=elementLength) {
                        memcpy(value->value.visibleString.buf, buffer+bufPos, elementLength);
                        value->value.visibleString.buf[elementLength]=0;
                    } else {
                        GLOBAL_FREEMEM(value->value.visibleString.buf);
                        createNewStringFromBufferElement(value, buffer+bufPos, elementLength);
                    }
                } else createNewStringFromBufferElement(value, buffer+bufPos, elementLength);
            } else pe=GOOSE_PARSE_ERROR_TYPE_MISMATCH; break;
        case 0x8c:
            if (MmsValue_getType(value)==MMS_BINARY_TIME) {
                if ((elementLength==4)||(elementLength==6))
                    memcpy(value->value.binaryTime.buf, buffer+bufPos, elementLength);
            } else pe=GOOSE_PARSE_ERROR_TYPE_MISMATCH; break;
        case 0x91:
            if (elementLength==8) {
                if (MmsValue_getType(value)==MMS_UTC_TIME) MmsValue_setUtcTimeByBuffer(value, buffer+bufPos);
                else pe=GOOSE_PARSE_ERROR_TYPE_MISMATCH;
            } else pe=GOOSE_PARSE_ERROR_LENGTH_MISMATCH; break;
        default: pe=GOOSE_PARSE_ERROR_UNKNOWN_TAG; break;
        }
        if (pe!=GOOSE_PARSE_ERROR_NO_ERROR) break;
        bufPos+=elementLength; elementIndex++;
    }
    if (elementIndex<=maxIndex && pe==GOOSE_PARSE_ERROR_NO_ERROR) pe=GOOSE_PARSE_ERROR_UNDERFLOW;
    return pe;
}

/* FULL ORIGINAL parseAllDataUnknownValue — two passes, complete tag validation */
static MmsValue*
parseAllDataUnknownValue(GooseSubscriber self, uint8_t* buffer, int allDataLength, bool isStructure)
{
    int bufPos=0, elementLength=0, elementIndex=0;
    MmsValue* dataSetValues=NULL;

    /* Pass 1: validate all tags, count elements */
    while (bufPos < allDataLength) {
        uint8_t tag=buffer[bufPos++];
        bufPos=BerDecoder_decodeLength(buffer, &elementLength, bufPos, allDataLength);
        if (bufPos<0) { if(DEBUG_GOOSE_SUBSCRIBER) printf("GOOSE_SUBSCRIBER: bad BER length\n"); return 0; }
        switch (tag) {
        case 0x80: case 0xa1: case 0xa2: case 0x83: case 0x84: case 0x85:
        case 0x86: case 0x87: case 0x89: case 0x8a: case 0x8c: case 0x91: break;
        default:
            if (DEBUG_GOOSE_SUBSCRIBER) printf("GOOSE_SUBSCRIBER: unknown tag %02x in pass1\n", tag);
            goto exit_with_error;
        }
        bufPos+=elementLength; elementIndex++;
    }

    if (isStructure) dataSetValues=MmsValue_createEmptyStructure(elementIndex);
    else             dataSetValues=MmsValue_createEmptyArray(elementIndex);

    elementIndex=0; bufPos=0;

    /* Pass 2: decode all elements */
    while (bufPos < allDataLength) {
        uint8_t tag=buffer[bufPos++];
        bufPos=BerDecoder_decodeLength(buffer, &elementLength, bufPos, allDataLength);
        if (bufPos<0) goto exit_with_error;
        MmsValue* value=NULL;
        switch (tag) {
        case 0xa1:
            value=parseAllDataUnknownValue(self, buffer+bufPos, elementLength, false);
            if (!value) goto exit_with_error; break;
        case 0xa2:
            value=parseAllDataUnknownValue(self, buffer+bufPos, elementLength, true);
            if (!value) goto exit_with_error; break;
        case 0x83:
            if (elementLength>0) value=MmsValue_newBoolean(BerDecoder_decodeBoolean(buffer, bufPos));
            else goto exit_with_error; break;
        case 0x84:
            if (elementLength>1) {
                int pad=buffer[bufPos]; if (pad>7) goto exit_with_error;
                value=MmsValue_newBitString((elementLength-1)*8-pad);
                memcpy(value->value.bitString.buf, buffer+bufPos+1, elementLength-1);
            } else goto exit_with_error; break;
        case 0x85:
            if (elementLength>8) goto exit_with_error;
            value=MmsValue_newInteger(elementLength*8);
            memcpy(value->value.integer->octets, buffer+bufPos, elementLength);
            value->value.integer->size=elementLength; break;
        case 0x86:
            if (elementLength>8) goto exit_with_error;
            value=MmsValue_newUnsigned(elementLength*8);
            memcpy(value->value.integer->octets, buffer+bufPos, elementLength);
            value->value.integer->size=elementLength; break;
        case 0x87:
            if (elementLength==9) value=MmsValue_newDouble(BerDecoder_decodeDouble(buffer, bufPos));
            else if (elementLength==5) value=MmsValue_newFloat(BerDecoder_decodeFloat(buffer, bufPos));
            break;
        case 0x89:
            value=MmsValue_newOctetString(elementLength, elementLength);
            memcpy(value->value.octetString.buf, buffer+bufPos, elementLength); break;
        case 0x8a:
            value=MmsValue_newVisibleStringFromByteArray(buffer+bufPos, elementLength); break;
        case 0x8c:
            if (elementLength==4) value=MmsValue_newBinaryTime(true);
            else if (elementLength==6) value=MmsValue_newBinaryTime(false);
            if ((elementLength==4)||(elementLength==6))
                memcpy(value->value.binaryTime.buf, buffer+bufPos, elementLength); break;
        case 0x91:
            if (elementLength==8) {
                value=MmsValue_newUtcTime(0);
                MmsValue_setUtcTimeByBuffer(value, buffer+bufPos);
            } break;
        default:
            if (DEBUG_GOOSE_SUBSCRIBER) printf("GOOSE_SUBSCRIBER: unknown tag %02x in pass2\n", tag);
            goto exit_with_error;
        }
        bufPos+=elementLength;
        if (value) { MmsValue_setElement(dataSetValues, elementIndex, value); elementIndex++; }
    }
    self->dataSetValuesSelfAllocated=true;
    return dataSetValues;

exit_with_error:
    if (dataSetValues) MmsValue_delete(dataSetValues);
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * FULL ORIGINAL parseGoosePayload — complete state machine, all fields
 * ═══════════════════════════════════════════════════════════════════════════ */
static int

parseGoosePayload(GooseReceiver self, uint8_t* buffer, int apduLength)
{
    int bufPos=0;
    uint32_t timeAllowedToLive=0, stNum=0, sqNum=0, confRev=0;
    bool simulation=false, ndsCom=false;
    GooseSubscriber matchingSubscriber=NULL;
    uint8_t* timestampBufPos=NULL;
    uint8_t* dataSetBufferAddress=NULL;
    int dataSetBufferLength=0;
    uint32_t numberOfDatSetEntries=0;

    if (buffer[bufPos++]==0x61) {
        int gooseLength;
        bufPos=BerDecoder_decodeLength(buffer, &gooseLength, bufPos, apduLength);
        if (bufPos<0) return 0;
        int gooseEnd=bufPos+gooseLength;

        while (bufPos<gooseEnd) {
            int elementLength;
            uint8_t tag=buffer[bufPos++];
            bufPos=BerDecoder_decodeLength(buffer, &elementLength, bufPos, apduLength);
            if (bufPos<0) goto exit_with_fault;

            switch (tag) {
            case 0x80: {
                LinkedList element=LinkedList_getNext(self->subscriberList);
                while (element!=NULL) {
                    GooseSubscriber subscriber=(GooseSubscriber)LinkedList_getData(element);
                    if (subscriber->isObserver) {
                        if (elementLength<=129) { memcpy(subscriber->goCBRef, buffer+bufPos, elementLength); subscriber->goCBRef[elementLength]=0; }
                        matchingSubscriber=subscriber; break;
                    } else if (subscriber->goCBRefLen==elementLength && memcmp(subscriber->goCBRef, buffer+bufPos, elementLength)==0) {
                        matchingSubscriber=subscriber; break;
                    }
                    element=LinkedList_getNext(element);
                }
                if (matchingSubscriber==NULL) return 0;
                break;
            }
            case 0x81: timeAllowedToLive=BerDecoder_decodeUint32(buffer, elementLength, bufPos); break;
            case 0x82:
                if (matchingSubscriber && elementLength<=129) {
                    memcpy(matchingSubscriber->datSet, buffer+bufPos, elementLength);
                    matchingSubscriber->datSet[elementLength]=0;
                } break;
            case 0x83:
                if (matchingSubscriber && elementLength<=129) {
                    memcpy(matchingSubscriber->goId, buffer+bufPos, elementLength);
                    matchingSubscriber->goId[elementLength]=0;
                } break;
            case 0x84: timestampBufPos=buffer+bufPos; break;
            case 0x85: stNum=BerDecoder_decodeUint32(buffer, elementLength, bufPos); break;
            case 0x86: sqNum=BerDecoder_decodeUint32(buffer, elementLength, bufPos); break;
            case 0x87: simulation=BerDecoder_decodeBoolean(buffer, bufPos); break;
            case 0x88: confRev=BerDecoder_decodeUint32(buffer, elementLength, bufPos); break;
            case 0x89: ndsCom=BerDecoder_decodeBoolean(buffer, bufPos); break;
            case 0x8a: numberOfDatSetEntries=BerDecoder_decodeUint32(buffer, elementLength, bufPos); break;
            case 0xab: dataSetBufferAddress=buffer+bufPos; dataSetBufferLength=elementLength; break;
            default: break;
            }
            bufPos+=elementLength;
        }

        if (matchingSubscriber!=NULL) {
            matchingSubscriber->timeAllowedToLive=timeAllowedToLive;
            matchingSubscriber->ndsCom=ndsCom;
            matchingSubscriber->simulation=simulation;

            if (matchingSubscriber->dataSetValuesSelfAllocated &&
                matchingSubscriber->dataSetValues!=NULL &&
                matchingSubscriber->confRev!=confRev) {
                MmsValue_delete(matchingSubscriber->dataSetValues);
                matchingSubscriber->dataSetValues=NULL;
            }
            matchingSubscriber->confRev=confRev;

            if (timestampBufPos) MmsValue_setUtcTimeByBuffer(matchingSubscriber->timestamp, timestampBufPos);
            else MmsValue_setUtcTime(matchingSubscriber->timestamp, 0);

            if (matchingSubscriber->isObserver && matchingSubscriber->dataSetValues!=NULL) {
                MmsValue_delete(matchingSubscriber->dataSetValues);
                matchingSubscriber->dataSetValues=NULL;
            }

            bool isValid=true;
            if (matchingSubscriber->dataSetValues==NULL)
                matchingSubscriber->dataSetValues=parseAllDataUnknownValue(matchingSubscriber, dataSetBufferAddress, dataSetBufferLength, false);
            else {
                GooseParseError parseError=parseAllData(dataSetBufferAddress, dataSetBufferLength, matchingSubscriber->dataSetValues);
                if (parseError!=GOOSE_PARSE_ERROR_NO_ERROR) isValid=false;
                matchingSubscriber->parseError=parseError;
            }

            /* stock libIEC61850 v1.5.3 behaviour, unchanged: a non-increasing sqNum only marks the
             * subscriber state invalid (isValid = false); the frame is still delivered to the callback */
            if (matchingSubscriber->stNum == stNum) {
                if (matchingSubscriber->sqNum >= sqNum) {
                    isValid = false;
                }
            }

            /* optional strict sqNum == last+1 DROP filter (baseline security tests only) */
            if (s_strict_active &&
                matchingSubscriber->stNum == stNum &&
                sqNum != matchingSubscriber->sqNum + 1) {
                gsFinish(GS_V_REJ_REPLAY, stNum, sqNum);
                return 1;
            }
            matchingSubscriber->stateValid=isValid;
            matchingSubscriber->stNum=stNum;
            matchingSubscriber->sqNum=sqNum;
            matchingSubscriber->invalidityTime=Hal_getTimeInMs()+timeAllowedToLive;

            if (matchingSubscriber->listener!=NULL)
                matchingSubscriber->listener(matchingSubscriber, matchingSubscriber->listenerParameter);

            gsFinish(GS_V_DELIVERED, stNum, sqNum);   /* T_proc END: after the callback */
            return 1;
        }
        return 0;
    }
exit_with_fault:
    gsFinish(GS_V_REJ_PARSE, 0, 0);
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * parseGooseMessage - scheme dispatch
 * ═══════════════════════════════════════════════════════════════════════════ */
static void
parseGooseMessage(GooseReceiver self, uint8_t* buffer, int numbytes)
{
    int bufPos;
    bool subscriberFound=false;
    gs_dbg[2]++;
    if (numbytes<22) { gs_dbg[3]++; return; }

    bufPos=12;
    int headerLength=14;
    uint8_t priority=0; uint16_t vlanId=0; bool vlanSet=false;

    if (buffer[bufPos]==0x81 && buffer[bufPos+1]==0x00) {
        priority=buffer[bufPos+2]&0xF8>>5;
        vlanId=((buffer[bufPos+2]&0x07)<<8)+buffer[bufPos+3];
        vlanSet=true; bufPos+=4; headerLength+=4;
    }
    if (buffer[bufPos++]!=0x88) { gs_dbg[4]++; return; }
    if (buffer[bufPos++]!=0xb8) { gs_dbg[4]++; return; }

    uint8_t srcMac[6]; memcpy(srcMac, &buffer[6], 6);
    uint8_t dstMac[6]; memcpy(dstMac, buffer, 6);

    uint16_t appId;
    appId = (uint16_t)(buffer[bufPos++] * 0x100);
    appId = (uint16_t)(appId + buffer[bufPos++]);
    uint16_t length;
    length = (uint16_t)(buffer[bufPos++] * 0x100);
    length = (uint16_t)(length + buffer[bufPos++]);
    bufPos+=4; /* skip Reserved1 + Reserved2 */

    int apduLength=length-8;
    if (numbytes<length+headerLength) {
        gs_dbg[5]++; gs_dbg[11]=(uint64_t)numbytes; gs_dbg[12]=length; gs_dbg[13]=(uint64_t)headerLength;
        return;
    }

    LinkedList element=LinkedList_getNext(self->subscriberList);
    while (element!=NULL) {
        GooseSubscriber subscriber=(GooseSubscriber)LinkedList_getData(element);
        if (subscriber->isObserver) {
            subscriber->appId=appId;
            memcpy(subscriber->srcMac, srcMac, 6);
            memcpy(subscriber->dstMac, dstMac, 6);
            subscriberFound=true;
            subscriber->vlanSet=vlanSet;
            subscriber->vlanId=vlanId;
            subscriber->vlanPrio=priority;
            break;
        }
        if (((subscriber->appId==-1)||(subscriber->appId==appId)) &&
            (!subscriber->dstMacSet||(memcmp(subscriber->dstMac,dstMac,6)==0))) {
            subscriberFound=true; break;
        }
        element=LinkedList_getNext(element);
    }

    if (!subscriberFound) { gs_dbg[6]++; gs_dbg[14]=appId; return; }
    gs_dbg[7]++;

    s_frame_len = (uint32_t) numbytes;
    gs_scheme_t scheme = gs_scheme();

    if (scheme == GS_NONE) {
        s_strict_active = false;
        parseGoosePayload(self, buffer+bufPos, apduLength);
        return;
    }

    /* ---------------- banerjee: extension handling ------------------------ */
    uint8_t* apdu = buffer + bufPos;
    const uint8_t* hdr10 = buffer + bufPos - 10;        /* EtherType AppID Length Res1 Res2 */
    int hl = 0, vl = 0;
    const uint8_t *av_tlv = NULL, *iv = NULL, *mac = NULL;
    int av_tlv_len = 0, iv_len = 0;

    if (apduLength < 2 || apdu[0] != 0x61 || gs_ber_tl(apdu, apduLength, &hl, &vl) != 0 ||
        gs_parse_ext(apdu + hl + vl, apduLength - hl - vl, &av_tlv, &av_tlv_len, &iv, &iv_len, &mac) != 0) {
        gsFinish(GS_V_REJ_PARSE, 0, 0);
        return;
    }

    uint8_t aad[GS_AAD_MAX]; int alen = 0;
    memcpy(aad, hdr10, 10); alen = 10;

    if (scheme == GS_BANERJEE) {
        /* decrypt the WHOLE PDU value first, then parse it */
        uint8_t ct[ETH_BUFFER_LENGTH + 16];
        uint8_t plain[ETH_BUFFER_LENGTH];
        uint8_t wrapped[ETH_BUFFER_LENGTH + 4];
        unsigned long long plen = 0;
        int wp;

        memcpy(aad + alen, av_tlv, (size_t) av_tlv_len); alen += av_tlv_len;
        memcpy(ct, apdu + hl, (size_t) vl);
        memcpy(ct + vl, mac, 16);

        if (crypto_aead_decrypt(plain, &plen, NULL, ct, (unsigned long long)(vl + 16),
                                aad, (unsigned long long) alen, iv, GS_KEY) != 0) {
            gsFinish(GS_V_REJ_AUTH, 0, 0);
            return;
        }
        wrapped[0] = 0x61;
        wp = 1 + gs_ber_put_len(wrapped + 1, (int) plen);
        memcpy(wrapped + wp, plain, (size_t) plen);
        wp += (int) plen;

        s_strict_active = (gs_banerjee_replay() == GS_REPLAY_STRICT);
        parseGoosePayload(self, wrapped, wp);
        return;
    }
}

/* ─── GooseReceiver lifecycle (stock, except the timing marks) ───────────── */

#if (CONFIG_MMS_THREADLESS_STACK == 0)
static void* gooseReceiverLoop(void *threadParameter)
{
    GooseReceiver self=(GooseReceiver)threadParameter;
    EthernetHandleSet handleSet=EthernetHandleSet_new();
    EthernetHandleSet_addSocket(handleSet, self->ethSocket);
    if (self->running) {
        while (self->running) {
            int rdy = EthernetHandleSet_waitReady(handleSet, 100);
            if (rdy > 0) gs_dbg[8]++; else if (rdy == 0) gs_dbg[9]++; else gs_dbg[10]++;
            if (rdy > 0) {
                /* T_proc START: after select() returns, before recv() */
                clock_gettime(CLOCK_MONOTONIC, &s_t_start);
                GooseReceiver_tick(self);
            }
            if (self->stop) break;
        }
        GooseReceiver_stopThreadless(self);
    }
    EthernetHandleSet_destroy(handleSet);
    return NULL;
}
#endif


void GooseReceiver_start(GooseReceiver self)
{
#if (CONFIG_MMS_THREADLESS_STACK == 0)
    if (GooseReceiver_startThreadless(self)) {
        self->thread=Thread_create((ThreadExecutionFunction)gooseReceiverLoop, (void*)self, false);
        if (self->thread) Thread_start(self->thread);
    }
#endif
}
bool GooseReceiver_isRunning(GooseReceiver self) { return self->running; }
void GooseReceiver_stop(GooseReceiver self)
{
#if (CONFIG_MMS_THREADLESS_STACK == 0)
    self->stop=true; self->running=false;
    if (self->thread) Thread_destroy(self->thread);
    self->stop=false;
#endif
}
void GooseReceiver_destroy(GooseReceiver self)
{
    if (self) {
#if (CONFIG_MMS_THREADLESS_STACK == 0)
        if (self->thread && GooseReceiver_isRunning(self)) GooseReceiver_stop(self);
#endif
        if (self->interfaceId) GLOBAL_FREEMEM(self->interfaceId);
        LinkedList_destroyDeep(self->subscriberList, (LinkedListValueDeleteFunction)GooseSubscriber_destroy);
        GLOBAL_FREEMEM(self->buffer);
        GLOBAL_FREEMEM(self);
    }
}
EthernetSocket GooseReceiver_startThreadless(GooseReceiver self)
{
    if (self->interfaceId==NULL) self->ethSocket=Ethernet_createSocket(CONFIG_ETHERNET_INTERFACE_ID, NULL);
    else                         self->ethSocket=Ethernet_createSocket(self->interfaceId, NULL);
    if (self->ethSocket!=NULL) {
        gsAttachGooseFilter(self->ethSocket);   /* instead of the VLAN-blind stock Ethernet_setProtocolFilter */
        Ethernet_setMode(self->ethSocket, ETHERNET_SOCKET_MODE_MULTICAST);
        LinkedList el=LinkedList_getNext(self->subscriberList);
        while (el) {
            GooseSubscriber sub=(GooseSubscriber)LinkedList_getData(el);
            if (!sub->dstMacSet) Ethernet_setMode(self->ethSocket, ETHERNET_SOCKET_MODE_ALL_MULTICAST);
            else Ethernet_addMulticastAddress(self->ethSocket, sub->dstMac);
            el=LinkedList_getNext(el);
        }
        self->running=true;
    } else self->running=false;
    return self->ethSocket;
}
void GooseReceiver_stopThreadless(GooseReceiver self)
{
    if (self->ethSocket) Ethernet_destroySocket(self->ethSocket);
    self->running=false;
}
bool GooseReceiver_tick(GooseReceiver self)
{
    /* T_proc start is set by gooseReceiverLoop() right after select() returns. */
    gs_dbg[0]++;
    int packetSize=Ethernet_receivePacket(self->ethSocket, self->buffer, ETH_BUFFER_LENGTH);
    if (packetSize>0) gs_dbg[1]++;
    if (packetSize>0) { parseGooseMessage(self, self->buffer, packetSize); return true; }
    return false;
}
void GooseReceiver_handleMessage(GooseReceiver self, uint8_t* buffer, int size)
    { parseGooseMessage(self, buffer, size); }
