/*
 *  goose_publisher.c - DROP-IN REPLACEMENT for libIEC61850 v1.5.3 src/goose/goose_publisher.c
 *
 *  Identical to the stock publisher except GoosePublisher_publish(), which
 *  applies the scheme selected by GOOSE_SCHEME (none | banerjee).
 *  See goose_sec.h for exactly what the Banerjee baseline does and which parts
 *  of it are assumptions.
 *
 *  Frame layout produced by the banerjee scheme:
 *    Ethernet | EtherType AppID Length Res1 Res2 | 0x61 PDU (value encrypted) | security extension
 *    Res1 = extension length (IEC 62351-6), Length covers PDU + extension.
 *
 *  Nothing in here is timed: the application times the GoosePublisher_publish()
 *  call from outside.
 */

#include "libiec61850_platform_includes.h"
#include "stack_config.h"
#include "goose_publisher.h"
#include "hal_ethernet.h"
#include "ber_encoder.h"
#include "mms_server_internal.h"
#include "mms_value_internal.h"

#include "goose_sec.h"

/* Ascon-AEAD128, NIST LWC API (ascon-c, crypto_aead/asconaead128/ref) */
extern int crypto_aead_encrypt(
    unsigned char *c,        unsigned long long *clen,
    const unsigned char *m,  unsigned long long  mlen,
    const unsigned char *ad, unsigned long long  adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k);

#ifndef DEBUG_GOOSE_PUBLISHER
#define DEBUG_GOOSE_PUBLISHER 0
#endif

#define GOOSE_MAX_MESSAGE_SIZE 1518

static bool
prepareGooseBuffer(GoosePublisher self, CommParameters* parameters, const char* interfaceID, bool useVlanTags);

struct sGoosePublisher {
    uint8_t* buffer;
    EthernetSocket ethernetSocket;
    int lengthField;
    int payloadStart;
    int payloadLength;
    char* goID;
    char* goCBRef;
    char* dataSetRef;
    uint32_t confRev;
    uint32_t stNum;
    uint32_t sqNum;
    uint32_t timeAllowedToLive;
    bool needsCommission;
    bool simulation;
    MmsValue* timestamp;
};

GoosePublisher
GoosePublisher_createEx(CommParameters* parameters, const char* interfaceID, bool useVlanTag)
{
    GoosePublisher self = (GoosePublisher) GLOBAL_CALLOC(1, sizeof(struct sGoosePublisher));
    if (self) {
        if (prepareGooseBuffer(self, parameters, interfaceID, useVlanTag)) {
            self->timestamp = MmsValue_newUtcTimeByMsTime(Hal_getTimeInMs());
            GoosePublisher_reset(self);
        } else {
            GoosePublisher_destroy(self);
            self = NULL;
        }
    }
    return self;
}

GoosePublisher
GoosePublisher_create(CommParameters* parameters, const char* interfaceID)
{
    return GoosePublisher_createEx(parameters, interfaceID, true);
}

void
GoosePublisher_destroy(GoosePublisher self)
{
    if (self) {
        if (self->ethernetSocket) Ethernet_destroySocket(self->ethernetSocket);
        MmsValue_delete(self->timestamp);
        if (self->goID)      GLOBAL_FREEMEM(self->goID);
        if (self->goCBRef)   GLOBAL_FREEMEM(self->goCBRef);
        if (self->dataSetRef) GLOBAL_FREEMEM(self->dataSetRef);
        if (self->buffer)    GLOBAL_FREEMEM(self->buffer);
        GLOBAL_FREEMEM(self);
    }
}

void GoosePublisher_setGoID(GoosePublisher self, char* goID)
{
    if (self->goID) GLOBAL_FREEMEM(self->goID);
    self->goID = StringUtils_copyString(goID);
}
void GoosePublisher_setGoCbRef(GoosePublisher self, char* goCbRef)
{
    if (self->goCBRef) GLOBAL_FREEMEM(self->goCBRef);
    self->goCBRef = StringUtils_copyString(goCbRef);
}
void GoosePublisher_setDataSetRef(GoosePublisher self, char* dataSetRef)
{
    if (self->dataSetRef) GLOBAL_FREEMEM(self->dataSetRef);
    self->dataSetRef = StringUtils_copyString(dataSetRef);
}
void GoosePublisher_setConfRev(GoosePublisher self, uint32_t confRev)   { self->confRev = confRev; }
void GoosePublisher_setSimulation(GoosePublisher self, bool simulation) { self->simulation = simulation; }
void GoosePublisher_setStNum(GoosePublisher self, uint32_t stNum)       { self->stNum = stNum; }
void GoosePublisher_setSqNum(GoosePublisher self, uint32_t sqNum)       { self->sqNum = sqNum; }
void GoosePublisher_setNeedsCommission(GoosePublisher self, bool ndsCom){ self->needsCommission = ndsCom; }

uint64_t
GoosePublisher_increaseStNum(GoosePublisher self)
{
    uint64_t currentTime = Hal_getTimeInMs();
    MmsValue_setUtcTimeMs(self->timestamp, currentTime);
    self->stNum++;
    if (self->stNum == 0) self->stNum = 1;
    self->sqNum = 0;
    return currentTime;
}

void GoosePublisher_reset(GoosePublisher self) { self->sqNum = 0; self->stNum = 1; }

void GoosePublisher_setTimeAllowedToLive(GoosePublisher self, uint32_t timeAllowedToLive)
{
    self->timeAllowedToLive = timeAllowedToLive;
}

static bool
prepareGooseBuffer(GoosePublisher self, CommParameters* parameters, const char* interfaceID, bool useVlanTags)
{
    uint8_t srcAddr[6];
    if (interfaceID) Ethernet_getInterfaceMACAddress(interfaceID, srcAddr);
    else             Ethernet_getInterfaceMACAddress(CONFIG_ETHERNET_INTERFACE_ID, srcAddr);

    uint8_t defaultDstAddr[] = CONFIG_GOOSE_DEFAULT_DST_ADDRESS;
    uint8_t* dstAddr;
    uint8_t  priority;
    uint16_t vlanId;
    uint16_t appId;

    if (parameters) {
        dstAddr  = parameters->dstAddress;
        priority = parameters->vlanPriority;
        vlanId   = parameters->vlanId;
        appId    = parameters->appId;
    } else {
        dstAddr  = defaultDstAddr;
        priority = CONFIG_GOOSE_DEFAULT_PRIORITY;
        vlanId   = CONFIG_GOOSE_DEFAULT_VLAN_ID;
        appId    = CONFIG_GOOSE_DEFAULT_APPID;
    }

    if (interfaceID) self->ethernetSocket = Ethernet_createSocket(interfaceID, dstAddr);
    else             self->ethernetSocket = Ethernet_createSocket(CONFIG_ETHERNET_INTERFACE_ID, dstAddr);

    if (self->ethernetSocket) {
        self->buffer = (uint8_t*) GLOBAL_MALLOC(GOOSE_MAX_MESSAGE_SIZE + 128);  /* room for the security extension */
        if (self->buffer == NULL) {
            Ethernet_destroySocket(self->ethernetSocket);
            self->ethernetSocket = NULL;
            return false;
        }
        memcpy(self->buffer, dstAddr, 6);
        memcpy(self->buffer + 6, srcAddr, 6);
        int bufPos = 12;

        if (useVlanTags) {
            self->buffer[bufPos++] = 0x81; self->buffer[bufPos++] = 0x00;
            uint8_t tci1 = priority << 5; tci1 += vlanId / 256;
            uint8_t tci2 = vlanId % 256;
            self->buffer[bufPos++] = tci1;
            self->buffer[bufPos++] = tci2;
        }

        self->buffer[bufPos++] = 0x88; self->buffer[bufPos++] = 0xB8;  /* EtherType GOOSE */
        self->buffer[bufPos++] = appId / 256;
        self->buffer[bufPos++] = appId % 256;
        self->lengthField = bufPos;
        self->buffer[bufPos++] = 0x00; self->buffer[bufPos++] = 0x08;  /* Length placeholder */
        self->buffer[bufPos++] = 0x00; self->buffer[bufPos++] = 0x00;  /* Reserved1 */
        self->buffer[bufPos++] = 0x00; self->buffer[bufPos++] = 0x00;  /* Reserved2 */
        self->payloadStart = bufPos;
        return true;
    }
    return false;
}


static int32_t
createGoosePayload(GoosePublisher self, LinkedList dataSetValues, uint8_t* buffer, size_t maxPayloadSize)
{
    uint32_t goosePduLength = 0;
    goosePduLength += BerEncoder_determineEncodedStringSize(self->goCBRef);
    uint32_t timeAllowedToLive = self->timeAllowedToLive;
    goosePduLength += 2 + BerEncoder_UInt32determineEncodedSize(timeAllowedToLive);
    goosePduLength += BerEncoder_determineEncodedStringSize(self->dataSetRef);
    if (self->goID) goosePduLength += BerEncoder_determineEncodedStringSize(self->goID);
    else            goosePduLength += BerEncoder_determineEncodedStringSize(self->goCBRef);
    goosePduLength += 2 + 8;
    goosePduLength += 2 + BerEncoder_UInt32determineEncodedSize(self->sqNum);
    goosePduLength += 2 + BerEncoder_UInt32determineEncodedSize(self->stNum);
    goosePduLength += 2 + BerEncoder_UInt32determineEncodedSize(self->confRev);
    goosePduLength += 6;

    uint32_t numberOfDataSetEntries = LinkedList_size(dataSetValues);
    goosePduLength += 2 + BerEncoder_UInt32determineEncodedSize(numberOfDataSetEntries);

    uint32_t dataSetSize = 0;
    LinkedList element = LinkedList_getNext(dataSetValues);
    while (element) {
        MmsValue* dataSetEntry = (MmsValue*) element->data;
        if (dataSetEntry) dataSetSize += MmsValue_encodeMmsData(dataSetEntry, NULL, 0, false);
        element = LinkedList_getNext(element);
    }
    uint32_t allDataSize = dataSetSize + BerEncoder_determineLengthSize(dataSetSize) + 1;
    goosePduLength += allDataSize;

    uint32_t payloadSize = 1 + BerEncoder_determineLengthSize(goosePduLength) + goosePduLength;
    if (payloadSize > maxPayloadSize) return -1;

    int32_t bufPos = 0;
    bufPos = BerEncoder_encodeTL(0x61, goosePduLength, buffer, bufPos);
    bufPos = BerEncoder_encodeStringWithTag(0x80, self->goCBRef, buffer, bufPos);
    bufPos = BerEncoder_encodeUInt32WithTL(0x81, timeAllowedToLive, buffer, bufPos);
    bufPos = BerEncoder_encodeStringWithTag(0x82, self->dataSetRef, buffer, bufPos);
    if (self->goID) bufPos = BerEncoder_encodeStringWithTag(0x83, self->goID, buffer, bufPos);
    else            bufPos = BerEncoder_encodeStringWithTag(0x83, self->goCBRef, buffer, bufPos);
    bufPos = BerEncoder_encodeOctetString(0x84, self->timestamp->value.utcTime, 8, buffer, bufPos);
    bufPos = BerEncoder_encodeUInt32WithTL(0x85, self->stNum, buffer, bufPos);
    bufPos = BerEncoder_encodeUInt32WithTL(0x86, self->sqNum, buffer, bufPos);
    bufPos = BerEncoder_encodeBoolean(0x87, self->simulation, buffer, bufPos);
    bufPos = BerEncoder_encodeUInt32WithTL(0x88, self->confRev, buffer, bufPos);
    bufPos = BerEncoder_encodeBoolean(0x89, self->needsCommission, buffer, bufPos);
    bufPos = BerEncoder_encodeUInt32WithTL(0x8a, numberOfDataSetEntries, buffer, bufPos);
    bufPos = BerEncoder_encodeTL(0xab, dataSetSize, buffer, bufPos);

    element = LinkedList_getNext(dataSetValues);
    while (element) {
        MmsValue* dataSetEntry = (MmsValue*) element->data;
        if (dataSetEntry) bufPos = MmsValue_encodeMmsData(dataSetEntry, buffer, bufPos, true);
        element = LinkedList_getNext(element);
    }
    return bufPos;
}

/* length of the 0x61 tag + length bytes at the start of the PDU */
static int
pduHeaderLength(const uint8_t* p)
{
    if (p[1] < 0x80)  return 2;
    if (p[1] == 0x81) return 3;
    return 4;
}

int
GoosePublisher_publish(GoosePublisher self, LinkedList dataSet)
{
    gs_scheme_t scheme = gs_scheme();
    uint8_t* buffer = self->buffer + self->payloadStart;
    size_t maxPayloadSize = GOOSE_MAX_MESSAGE_SIZE - self->payloadStart;
    int lengthIndex = self->lengthField;

    self->payloadLength = createGoosePayload(self, dataSet, buffer, maxPayloadSize);
    if (self->payloadLength == -1) return -1;

    if (scheme == GS_NONE) {
        size_t gooseLength = (size_t) self->payloadLength + 8;
        self->buffer[lengthIndex]     = (uint8_t)(gooseLength / 256);
        self->buffer[lengthIndex + 1] = (uint8_t)(gooseLength & 0xff);
        self->buffer[lengthIndex + 2] = 0;       /* Reserved1: no security extension */
        self->buffer[lengthIndex + 3] = 0;
    }
    else {
        int iv_len  = gs_iv_len();
        int ext_len = gs_ext_len(iv_len);
        uint8_t* ext;
        uint8_t nonce[16];
        uint8_t zero_tag[16];
        uint8_t aad[GS_AAD_MAX];
        uint8_t ct[GOOSE_MAX_MESSAGE_SIZE + 16];
        unsigned long long clen = 0;
        const uint8_t* enc_ptr;
        int enc_len, alen, av_tlv_len;
        size_t gooseLength;
        const uint8_t* t = self->timestamp->value.utcTime;

        if ((size_t)(self->payloadLength + ext_len) > maxPayloadSize) return -1;
        ext = buffer + self->payloadLength;

        gs_nonce_ber(nonce, self->stNum, self->sqNum, t);     /* ASSUMED nonce, see goose_sec.h */

        /* Length and Reserved1 are part of the AAD, so set them before encrypting */
        gooseLength = (size_t)(self->payloadLength + ext_len) + 8;
        self->buffer[lengthIndex]     = (uint8_t)(gooseLength / 256);
        self->buffer[lengthIndex + 1] = (uint8_t)(gooseLength & 0xff);
        self->buffer[lengthIndex + 2] = (uint8_t)(ext_len >> 8);
        self->buffer[lengthIndex + 3] = (uint8_t)(ext_len);

        memset(zero_tag, 0, sizeof(zero_tag));
        gs_build_ext(ext, iv_len, nonce, zero_tag);
        av_tlv_len = 2 + ext[1];

        /* AAD always starts with EtherType | AppID | Length | Res1 | Res2 (10 bytes) */
        memcpy(aad, self->buffer + lengthIndex - 4, 10);
        alen = 10;

        {
            /* the whole PDU value is encrypted; the 0x61 tag+length stay in the clear */
            int hl = pduHeaderLength(buffer);
            enc_ptr = buffer + hl;
            enc_len = self->payloadLength - hl;
        }
        memcpy(aad + alen, ext, (size_t) av_tlv_len);
        alen += av_tlv_len;

        crypto_aead_encrypt(ct, &clen,
                            enc_ptr, (unsigned long long) enc_len,
                            aad,     (unsigned long long) alen,
                            NULL, nonce, GS_KEY);

        memcpy((uint8_t*) enc_ptr, ct, (size_t) enc_len);   /* ciphertext replaces plaintext  */
        memcpy(ext + ext_len - 16, ct + enc_len, 16);        /* tag goes into the MAC TLV      */

        self->payloadLength += ext_len;
    }

    self->sqNum++;
    if (self->sqNum == 0) self->sqNum = 1;

    {
        int total_frame_size = self->payloadStart + self->payloadLength;
        gs_last_frame_size = total_frame_size;
        Ethernet_sendPacket(self->ethernetSocket, self->buffer, total_frame_size);
    }
    return 0;
}

int
GoosePublisher_publishAndDump(GoosePublisher self, LinkedList dataSet, char *msgBuf, int32_t *msgLen, int32_t bufSize)
{
    int rc = GoosePublisher_publish(self, dataSet);
    if (rc == 0) {
        int copied = self->payloadStart + self->payloadLength;
        if (bufSize < copied) copied = bufSize;
        memcpy(msgBuf, self->buffer, (size_t) copied);
        *msgLen = copied;
    }
    return rc;
}
