/**
 * @file pdulib.cpp
 * @brief Pure ESP-IDF Standard C++ Version
 */

#include <string.h>
#include <math.h>
#include <ctype.h>
#include <stdlib.h>
#include "pdulib.h"

PDU::PDU(int worksize ) {
  generalWorkBuffLength = worksize;
  generalWorkBuff = new char[generalWorkBuffLength+2]; // dynamically allocate buffer
}
PDU::~PDU() {
  delete[] generalWorkBuff;
}

const struct sRange gsm7_legal[] = {
        {10, 10}, {13, 13}, {32, 95}, {97, 126}, {161, 161}, {163, 167}, {191, 191}, {196, 201}, {209, 209}, {214, 214}, {216, 216}, {220, 220}, {223, 224}, {228, 230}, {232, 233}, {236, 236}, {241, 242}, {246, 246}, {248, 249}, {252, 252}, {915, 916}, {920, 920}, {923, 923}, {926, 926}, {928, 928}, {931, 931}, {934, 934}, {936, 937}, // greek
        {8364, 8364}                                                                                                                                                                                                                                                                                                                             // euro
};

bool PDU::phoneNumberLegal(const char *number) {
  bool rc = true;
  int j = strlen(number);
  int i =0;
  while (i++ < j) {
    char c = *number++;
    if (!(isdigit(c) || c == '+')) {
      rc = false;
      break;
    }
  }
  return rc;
}

bool PDU::setAddress(const char *address, eLengthType lt, char *buffer)
{
  bool rc = phoneNumberLegal(address);
  if (rc) {
    eAddressType at = NATIONAL_NUMERIC;
    if (*address == '+') {
      address++; 
      at = INTERNATIONAL_NUMERIC;
    }
    addressLength = strlen(address);
    if (addressLength < MAX_NUMBER_LENGTH)
    {
      if (lt == NIBBLES)  
        buffer[smsOffset++] = addressLength;
      else { 
        if (addressLength == 0) {
          buffer[smsOffset++] = 0; 
          return true;
        }
        else
          buffer[smsOffset++] = ((addressLength + 1) / 2) + 1; 
      }
      switch (at)
      {
        case INTERNATIONAL_NUMERIC:
          buffer[smsOffset++] = INTERNATIONAL_NUMBER;
          stringToBCD(address, &buffer[smsOffset]);
          smsOffset += (strlen(address) + 1) / 2;
          rc = true;
          break;
        case NATIONAL_NUMERIC:
          buffer[smsOffset++] = NATIONAL_NUMBER;
          stringToBCD(address, &buffer[smsOffset]);
          smsOffset += (strlen(address) + 1) / 2;
          rc = true;
          break;
        default:
          ;
      }
    }
    else
      rc = false;
  }
  return rc;
}

void PDU::stringToBCD(const char *number, char *pdu)
{
  int j, targetindex = 0;
  if (*number == '+') number++;
  for (j = 0; j < addressLength; j++)
  {
    if ((j & 1) == 1) 
    {
      pdu[targetindex] &= 0x0f;
      pdu[targetindex] += (*number++ - '0') << 4;
      targetindex++;
    }
    else
    {
      pdu[targetindex] = 0xf0;
      pdu[targetindex] += *number++ - '0';
    }
  }
}

void PDU::digitSwap(const char *number, char *pdu)
{
  int j, targetindex = 0;
  if (*number == '+') number++;
  for (j = 0; j < addressLength; j++)
  {
    if ((j & 1) == 1) 
    {
      pdu[targetindex] = *number++;
      targetindex += 2;
    }
    else
    { 
      pdu[targetindex + 1] = *number++;
    }
  }
  if ((addressLength & 1) == 1)
  {
    pdu[targetindex] = 'F';
    targetindex += 2;
  }
  pdu[targetindex++] = 0;
}

int PDU::convert_utf8_to_gsm7bit(const char *message, char *gsm7bit, int udhsize, int bufferSize)
{
  int w = 0;
  while (*message)
  {
    int length = utf8Length(message);
    unsigned short ucs2[2], target; 
    utf8_to_ucs2_single(message, ucs2);
    target = (ucs2[0] << 8) | ((ucs2[0] & 0xff00) >> 8); 
    
    if (target == 0x20AC)
    { 
      *gsm7bit++ = 27;
      *gsm7bit++ = 0x65;
      w += 2;
    }
    else if (target >= GREEK_UCS_MINIMUM)
    {
      *gsm7bit++ = lookup_UnicodeToGreek7[target - GREEK_UCS_MINIMUM];
      w++;
    }
    else
    {
      short x = lookup_ascii8to7[target];
      if (x > 256)
      { 
        *gsm7bit++ = 27;
        *gsm7bit++ = x - 256;
        w += 2;
      }
      else
      {
        *gsm7bit++ = x;
        w++;
      }
    }
    message += length; 
    if (w > MAX_SMS_LENGTH_7BIT)
      break;
  }
  return w > MAX_SMS_LENGTH_7BIT ? GSM7_TOO_LONG : w;
}

int PDU::utf8_to_packed7bit(const char *utf8, char *pdu, int *septets, int udhsize, int bufferSize)
{
  int r, w, len7bit;
  char gsm7bit[MAX_SMS_LENGTH_7BIT + 2]; 

  len7bit = convert_utf8_to_gsm7bit(utf8, gsm7bit, udhsize, bufferSize);
  if (len7bit < 0) return len7bit;

  r = 0; w = 0;
  while (r < len7bit)
  {
    pdu[w] = ((gsm7bit[r] >> (w % 7)) & 0x7F) | ((gsm7bit[r + 1] << (7 - (w % 7))) & 0xFF);
    if ((w % 7) == 6) r++;
    r++; w++;
  }
  *septets = len7bit;
  return w;
}

int PDU::buildUDH(unsigned short csms, unsigned numparts, unsigned partnumber)
{
  int offset = 0;
  udhbuffer[offset++] = 6;           
  udhbuffer[offset++] = 8;           
  udhbuffer[offset++] = 4;           
  udhbuffer[offset++] = csms >> 8;   
  udhbuffer[offset++] = csms & 0xff; 
  udhbuffer[offset++] = numparts;
  udhbuffer[offset++] = partnumber;
  return offset;
}

int PDU::encodePDU(const char *recipient, const char *message, unsigned short csms, unsigned char numparts, unsigned char partnumber)
{
  int length = -1;
  int delta = -1;
  char tempbuf[PDU_BINARY_MAX_LENGTH];
  smsOffset = 0;
  int beginning = 0;
  enum eDCS dcs = ALPHABET_7BIT;
  overFlow = false;
  if ((csms + numparts + partnumber) == 0)
    ; 
  else
  {
    if (csms == 0 || numparts == 0 || partnumber == 0) return (int)MULTIPART_NUMBERS;
    else if (partnumber > numparts) return (int)MULTIPART_NUMBERS;
  }
  bool gsm7bit = true;
  const char *savem = message;
  while (*message && gsm7bit)
  {
    unsigned short ucs2[2], target; 
    int length = utf8Length(message);
    utf8_to_ucs2_single(message, ucs2); 
    target = (ucs2[0] << 8) | ((ucs2[0] & 0xff00) >> 8);
    gsm7bit = isGSM7(&target);
    message += length; 
  }
  if (!gsm7bit) dcs = ALPHABET_16BIT;
  if (!setAddress(scabuffout, OCTETS, tempbuf)) return ADDRESS_FORMAT; 
  else beginning = smsOffset;
  
  int pdutype = PDU_SMS_SUBMIT;                                                                
  if (csms != 0) pdutype |= (1 << PDU_UDHI); 
  tempbuf[smsOffset++] = pdutype;
  tempbuf[smsOffset++] = 0; 
  if (!setAddress(recipient, NIBBLES, tempbuf)) return ADDRESS_FORMAT;
  
  tempbuf[smsOffset++] = 0; 
  int udhsize;
  if (csms == 0) udhsize = 0;
  else udhsize = buildUDH(csms, numparts, partnumber);
  
  int pduLengthPlaceHolder = 0;
  int septetcount = 0;
  switch (dcs)
  {
  case ALPHABET_8BIT:
    delta = ALPHABET_8BIT_NOT_SUPPORTED; 
    break;
  case ALPHABET_7BIT:
    tempbuf[smsOffset++] = DCS_7BIT_ALPHABET_MASK;
    pduLengthPlaceHolder = smsOffset;
    tempbuf[smsOffset++] = 1; 
    if (udhsize != 0)
    {
      memcpy(&tempbuf[smsOffset], udhbuffer, udhsize);
      smsOffset += udhsize;
    }
    delta = utf8_to_packed7bit(savem, &tempbuf[smsOffset], &septetcount, udhsize == 0 ? 0 : 8, MAX_NUMBER_OCTETS);
    if (delta < 0) {
      overFlow = delta == WORK_BUFFER_TOO_SMALL;
    }
    else {
      tempbuf[pduLengthPlaceHolder] = septetcount;
      if (udhsize != 0) tempbuf[pduLengthPlaceHolder] += 8; 
      length = smsOffset + delta;             
    }
    break;
  case ALPHABET_16BIT:
    tempbuf[smsOffset++] = DCS_16BIT_ALPHABET_MASK;
    pduLengthPlaceHolder = smsOffset;
    tempbuf[smsOffset++] = 1; 
    if (udhsize != 0)
    {
      memcpy(&tempbuf[smsOffset], udhbuffer, udhsize);
      smsOffset += udhsize;
    }
    delta = utf8_to_ucs2(savem, (char *)&tempbuf[smsOffset]);
    if (delta > 0) {
      tempbuf[pduLengthPlaceHolder] = delta + udhsize; 
      length = smsOffset + delta;                        
    }
    break;
  default:
    break;
  }
  if (delta < 0) return delta;

  if (generalWorkBuffLength < (length*2)) {
    overFlow = true;
    return WORK_BUFFER_TOO_SMALL;
  }
  int newoffset = 0;
  for (int i = 0; i < length; i++)
  {
    putHex(tempbuf[i], &generalWorkBuff[newoffset]);
    newoffset += 2;
  }
  generalWorkBuff[length * 2] = 0x1a;    
  generalWorkBuff[(length * 2) + 1] = 0; 

  return length - beginning;
}

unsigned char PDU::gethex(const char *pc)
{
  int i;
  char PC = toupper(*pc);
  if (isdigit(PC)) i = ((unsigned char)(PC) - '0') * 16;
  else i = ((unsigned char)(PC) - 'A' + 10) * 16;
  PC = toupper(*++pc);
  if (isdigit(PC)) i += (unsigned char)(PC) - '0';
  else i += (unsigned char)(PC) - 'A' + 10;
  return i;
}

void PDU::putHex(unsigned char b, char *target)
{
  if ((b >> 4) <= 9) *target++ = (b >> 4) + '0';
  else *target++ = (b >> 4) + 'A' - 10;
  if ((b & 0xf) <= 9) *target++ = (b & 0xf) + '0';
  else *target++ = (b & 0xf) + 'A' - 10;
}

int PDU::pdu_to_ucs2(const char *pdu, int length, unsigned short *ucs2)
{
  unsigned short temp;
  int indexOut = 0;
  int octet = 0;
  unsigned char X;
  while (octet < length)
  {
    temp = 0;
    X = gethex(pdu);
    pdu += 2; 
    octet++;
    temp = X << 8; 
    X = gethex(pdu);
    pdu += 2;
    octet++;
    temp |= X; 
    ucs2[indexOut++] = temp;
  }
  return indexOut;
}

int PDU::convert_7bit_to_unicode(unsigned char *gsm7bit, int length, char *unicode)
{
  int r;
  int w;
  w = 0;
  for (r = 0; r < length; r++)
  {
    if (w >= generalWorkBuffLength) {
      overFlow = true;
      unicode[w] = 0;  
      return w;
    }
    if ((lookup_gsm7toUnicode[(unsigned char)gsm7bit[r]]) != 27)
    {
      const unsigned char C = lookup_gsm7toUnicode[(unsigned char)gsm7bit[r]];
      if (gsm7bit[r] == '?' || C != NPC8)
        w += buildUtf(C, &unicode[w]);
      else
      {
        unsigned short S = lookup_Greek7ToUnicode[gsm7bit[r] - 16];
        w += buildUtf(S, &unicode[w]);
      }
    }
    else
    {
      r++;
      switch (gsm7bit[r])
      {
      case 10: unicode[w++] = 12; break;
      case 20: unicode[w++] = '^'; break;
      case 40: unicode[w++] = '{'; break;
      case 41: unicode[w++] = '}'; break;
      case 47: unicode[w++] = '\\'; break;
      case 60: unicode[w++] = '['; break;
      case 61: unicode[w++] = '~'; break;
      case 62: unicode[w++] = ']'; break;
      case 64: unicode[w++] = '|'; break;
      case 0x65: w += buildUtf(0x20AC, &unicode[w]); break;
      default: unicode[w++] = NPC8; break;
      }
    }
  }
  unicode[w] = 0;
  return w;
}

int PDU::pduGsm7_to_unicode(const char *pdu, int numSeptets, char *unicode, char firstchar)
{
  int r, w, length;
  unsigned char gsm7bit[(numSeptets * 8) / 7];
  w = 0;
  int index = 0; 
  if (firstchar != 0) gsm7bit[w++] = firstchar;

  for (r = 0; w < numSeptets; r++)
  {
    index = r * 2;
    if (r % 7 == 0)
    {
      gsm7bit[w++] = (gethex(&pdu[index]) << 0) & 0x7F;
    }
    else if (r % 7 == 6)
    {
      gsm7bit[w++] = ((gethex(&pdu[index]) << 6) | (gethex(&pdu[index - 2]) >> 2)) & 0x7F;
      if (w < numSeptets) 
        gsm7bit[w++] = (gethex(&pdu[index]) >> 1) & 0x7F;
      if (w >= numSeptets) break;
    }
    else
    {
      gsm7bit[w++] = ((gethex(&pdu[index]) << (r % 7)) | (gethex(&pdu[index - 2]) >> (7 + 1 - (r % 7)))) & 0x7F;
    }
  }
  length = convert_7bit_to_unicode(gsm7bit, w, unicode);
  return length;
}

bool PDU::decodePDU(const char *pdu)
{
  bool rc = true;
  int index = 0, outindex = 0;
  int i, dcs, tpdu;
  bool udhPresent;
  char udhfollower = 0;
  unsigned char X;
  overFlow = false;
  i = decodeAddress(pdu, scabuffin, OCTETS);
  if (i < 0) return false;
  
  index = i + 4; 
  tpdu = gethex(&pdu[index]);
  index += 2; 
  udhPresent = tpdu & (1 << PDU_UDHI);
  i = decodeAddress(&pdu[index], addressBuff, NIBBLES);
  if (i < 0) return false;
  
  index += i + 4; 
  index += 2;                
  dcs = gethex(&pdu[index]); 
  index += 2;
  
  outindex = 0;
  for (i = 0; i < 7; i++)
  {
    X = gethex(&pdu[index]);
    index += 2;
    tsbuff[outindex++] = (X & 0xf) + 0x30;
    tsbuff[outindex++] = (X >> 4) + 0x30;
  }
  tsbuff[outindex] = 0;
  
  int dulength = gethex(&pdu[index]);
  index += 2;
  int utflength = 0, utfoffset;
  unsigned short ucs2;
  *generalWorkBuff = 0;
  
  if (udhPresent)
  {
    int udhlength = gethex(&pdu[index]);
    index += 2;
    switch (udhlength)
    {
    default:
      index += (udhlength + 1);
      dulength -= udhlength;
      break; 
    case 5:
    case 6:
      int iei = gethex(&pdu[index]);
      index += 2;
      int ieilength = gethex(&pdu[index]);
      index += 2;
      if ((udhlength == 5 && iei == 0 && ieilength == 3) || (udhlength == 6 && iei == 8 && ieilength == 4))
      {
        concatInfo[0] = gethex(&pdu[index]);
        index += 2; 
        if (udhlength == 6)
        { 
          unsigned char lo = gethex(&pdu[index]);
          concatInfo[0] <<= 8;
          concatInfo[0] += lo;
          index += 2;
        }
        concatInfo[2] = gethex(&pdu[index]); 
        index += 2;
        concatInfo[1] = gethex(&pdu[index]); 
        index += 2;
        if ((dcs & DCS_ALPHABET_MASK) == DCS_7BIT_ALPHABET_MASK)
        {
          dulength -= 7; 
          if (udhlength == 5) {
            udhfollower = gethex(&pdu[index]) >> 1;
            index += 2; 
          }
        }
        else dulength -= (udhlength + 1); 
      }
      else return false;
      break;
    }
  }
  else
  {
    memset(concatInfo, 0, sizeof(concatInfo));
  }
  
  switch (dcs & DCS_ALPHABET_MASK)
  {
  case DCS_7BIT_ALPHABET_MASK:
    outindex = 0;
    i = pduGsm7_to_unicode(&pdu[index], dulength, (char *)generalWorkBuff,udhfollower);
    generalWorkBuff[i] = 0;
    rc = true;
    break;
  case DCS_8BIT_ALPHABET_MASK:
    rc = false;
    break;
  case DCS_16BIT_ALPHABET_MASK:
    utfoffset = 0;
    while (dulength)
    {
      pdu_to_ucs2(&pdu[index], 2, &ucs2); 
      index += 4;
      dulength -= 2;
      utflength = ucs2_to_utf8(ucs2, generalWorkBuff + utfoffset);
      if ((utfoffset + utflength) >= generalWorkBuffLength) {
        overFlow = true;
        break;
      }
      utfoffset += utflength;
    }
    generalWorkBuff[utfoffset] = 0; 
    rc = true;
    break;
  default:
    rc = false;
  }
  return rc;
}

#define BITS7654ON 0B11110000
#define BITS765ON 0B11100000
#define BITS76ON 0B11000000
#define BIT7ON6OFF 0B10000000
#define BITS0TO5ON 0B00111111

bool SPstart = false;
unsigned short spair[2]; 

int PDU::ucs2_to_utf8(unsigned short ucs2, char *outbuf)
{
  if (ucs2 <= 0x7f) 
  {
    outbuf[0] = ucs2;
    return 1;
  }
  else if (ucs2 <= 0x7ff) 
  {
    unsigned char c1 = BITS76ON, c2 = BIT7ON6OFF;
    for (int k = 0; k < 11; ++k)
    {
      if (k < 6) c2 |= (ucs2 % 64) & (1 << k);
      else c1 |= (ucs2 >> 6) & (1 << (k - 6));
    }
    outbuf[0] = c1;
    outbuf[1] = c2;
    return 2;
  }
  else if ((ucs2 & 0xff00) >= 0xD800 && ((ucs2 & 0xff00) <= 0xDB00))
  { 
    SPstart = true;
    spair[0] = ucs2;
  }
  else if (SPstart)
  {
    SPstart = false;
    spair[1] = ucs2;
    unsigned long utf16 = ((spair[0] & ~0xd800) << 10) + (spair[1] & 0x03ff);
    unsigned char c1 = BITS7654ON, c2 = BIT7ON6OFF, c3 = BIT7ON6OFF, c4 = BIT7ON6OFF;
    utf16 += 0x10000;
    for (int k = 0; k < 22; ++k) 
    {
      if (k < 6) c4 |= (utf16 % 64) & (1 << k);
      else if (k < 12) c3 |= (utf16 >> 6) & (1 << (k - 6));
      else if (k < 18) c2 |= (utf16 >> 12) & (1 << (k - 12));
      else c1 |= (utf16 >> 18) & (1 << (k - 18));
    }
    outbuf[0] = c1;
    outbuf[1] = c2;
    outbuf[2] = c3;
    outbuf[3] = c4;
    return 4;
  }
  else 
  {
    unsigned char c1 = BITS765ON, c2 = BIT7ON6OFF, c3 = BIT7ON6OFF;
    for (int k = 0; k < 16; ++k) 
    {
      if (k < 6) c3 |= (ucs2 % 64) & (1 << k);
      else if (k < 12) c2 |= (ucs2 >> 6) & (1 << (k - 6));
      else c1 |= (ucs2 >> 12) & (1 << (k - 12));
    }
    outbuf[0] = c1;
    outbuf[1] = c2;
    outbuf[2] = c3;
    return 3;
  }
  return 0;
}

int PDU::utf8Length(const char *utf8)
{
  int length = 1;
  unsigned char mask = BITS76ON;
  if ((*utf8 & BIT7ON6OFF) == 0) ;
  else
  {
    while ((*utf8 & mask) == mask)
    {
      length++;
      mask = (mask >> 1 | BIT7ON6OFF);
    }
    if (length > 1)
    { 
      int LEN = length - 1;
      utf8++;
      while (LEN)
      {
        if ((*utf8++ & BITS76ON) == BIT7ON6OFF) LEN--;
        else break;
      }
      if (LEN != 0) length = -1;
    }
    else length = -1; 
  }
  return length;
}

int PDU::utf8_to_ucs2_single(const char *utf8, unsigned short *target)
{
  unsigned short ucs2[2];
  int numbytes = 0;
  int cont = utf8Length(utf8) - 1; 
  unsigned long utf16;
  if (cont < 0) return 0;
  if (cont == 0)
  { 
    ucs2[0] = *utf8;
    ucs2[1] = 0; 
    numbytes = 2;
  }
  else
  {
    unsigned char mask = BITS0TO5ON;
    int temp = cont;
    while (temp-- > 0) mask >>= 1;
    utf16 = *utf8++ & mask;
    while (cont-- > 0)
    {
      utf16 = (utf16 << 6) | (*(utf8++) & BITS0TO5ON);
    }
    if (utf16 < 0x10000)
    {
      ucs2[0] = utf16;
      numbytes = 2;
    }
    else
    {
      utf16 -= 0x10000;
      ucs2[0] = 0xD800 | (utf16 >> 10);
      ucs2[1] = 0xDC00 | (utf16 & 0x3ff);
      numbytes = 4;
    }
  }
  *target = (ucs2[0] >> 8) | ((ucs2[0] & 0x0ff) << 8); 
  if (numbytes > 2)
  {
    target++;
    *target = (ucs2[1] >> 8) | ((ucs2[1] & 0x0ff) << 8); 
  }
  return numbytes;
}

const char *PDU::getSender() { return addressBuff; }
const char *PDU::getTimeStamp() { return tsbuff; }
const char *PDU::getText() { return generalWorkBuff; }

void PDU::BCDtoString(char *output, const char *input, int length)
{
  unsigned char X;
  for (int i = 0; i < length; i += 2)
  {
    X = gethex(input);
    input += 2;
    *output++ = (X & 0xf) + 0x30;
    if ((X & 0xf0) == 0xf0) break;
    *output++ = (X >> 4) + 0x30;
  }
  *output = 0; 
}

int PDU::decodeAddress(const char *pdu, char *output, eLengthType et)
{                           
  int length = gethex(pdu); 
  if (et == NIBBLES) addressLength = length;
  else {
    addressLength = --length * 2;
    if (addressLength == 0) {
      *output = 0;
      return 0;    
    }
  }
  pdu += 2; 
  int adt = gethex(pdu);
  pdu += 2;
  if ((adt & EXT_MASK) != 0)
  {
    switch ((adt & TON_MASK) >> TON_OFFSET)
    {
    case 1:            
      *output++ = '+'; 
      [[fallthrough]];  // <--- 加上这一行
    case 0: 
    case 2: 
      BCDtoString(output, pdu, addressLength);
      if ((addressLength & 1) == 1) addressLength++;            
      break;
    case 5: 
      pduGsm7_to_unicode(pdu, (addressLength * 4) / 7, output,0);
      if ((addressLength & 1) == 1) addressLength++;            
      break;
    default:
      addressLength = 0;
      break;
    }
  }
  else
  {
    addressLength = 0; 
  }
  return addressLength;
}

int PDU::utf8_to_ucs2(const char *utf8, char *ucs2)
{ 
  int octets = 0, ucslength;
  unsigned short tempucs2[2]; 
  while (*utf8 && octets <= MAX_NUMBER_OCTETS)
  {
    int inputlen = utf8Length(utf8);
    ucslength = utf8_to_ucs2_single(utf8, tempucs2);
    if (octets + ucslength > MAX_NUMBER_OCTETS) return UCS2_TOO_LONG;
    memcpy(ucs2, tempucs2, ucslength);
    utf8 += inputlen;    
    ucs2 += ucslength;   
    octets += ucslength; 
  }
  return octets;
}

const char *PDU::getSMS() { return generalWorkBuff; }
void PDU::setSCAnumber(const char *n) { strcpy(scabuffout, n); }
void PDU::setSCAnumber() { *scabuffout = 0; }
const char *PDU::getSCAnumber() { return scabuffin; }
void PDU::buildUtf16(unsigned long cp, char *target) { buildUtf(cp, target); }

int PDU::buildUtf(unsigned long cp, char *target)
{
  unsigned char buf[5];
  int length;
  if (cp <= 0x7f) 
  {
    length = 1;
    buf[0] = cp;
    buf[length] = 0;
  }
  else if (cp <= 0x7ff)
  { 
    length = 2;
    buf[0] = BITS76ON;
    buf[1] = BIT7ON6OFF;
    buf[length] = 0;
    for (int k = 0; k < 11; ++k) 
    {
      if (k < 6) buf[1] |= (cp % 64) & (1 << k);
      else buf[0] |= (cp >> 6) & (1 << (k - 6));
    }
  }
  else if (cp <= 0xffff)
  { 
    length = 3;
    buf[0] = BITS765ON;
    buf[1] = BIT7ON6OFF;
    buf[2] = BIT7ON6OFF;
    buf[length] = 0;
    for (int k = 0; k < 16; ++k) 
    {
      if (k < 6) buf[2] |= (cp % 64) & (1 << k);
      else if (k < 12) buf[1] |= (cp >> 6) & (1 << (k - 6));
      else buf[0] |= (cp >> 12) & (1 << (k - 12));
    }
  }
  else if (cp > 0x10000)
  { 
    length = 4;
    buf[0] = BITS7654ON;
    buf[1] = BIT7ON6OFF;
    buf[2] = BIT7ON6OFF;
    buf[3] = BIT7ON6OFF;
    buf[length] = 0;
    for (int k = 0; k < 22; ++k) 
    {
      if (k < 6) buf[3] |= (cp % 64) & (1 << k);
      else if (k < 12) buf[2] |= (cp >> 6) & (1 << (k - 6));
      else if (k < 18) buf[1] |= (cp >> 12) & (1 << (k - 12));
      else buf[0] |= (cp >> 18) & (1 << (k - 18));
    }
  }
  strcpy(target, (char *)buf);
  return strlen(target);
}

bool PDU::isGSM7(unsigned short *pucs)
{
  for (unsigned int i = 0; i < sizeof(gsm7_legal) / sizeof(sRange); i++)
  {
    if (*pucs >= gsm7_legal[i].min && *pucs <= gsm7_legal[i].max) return true;
  }
  return false;
}

int *PDU::getConcatInfo() { return concatInfo; }
bool PDU::getOverflow() { return overFlow; }

// --- 庞大的字符查找表映射区域，无需更改 ---
const short lookup_ascii8to7[] = {
    NPC7, NPC7, NPC7, NPC7, NPC7, NPC7, NPC7, NPC7, NPC7, NPC7, 10, NPC7, 10 + 256, 13, NPC7, NPC7,
    NPC7, NPC7, NPC7, NPC7, NPC7, NPC7, NPC7, NPC7, NPC7, NPC7, NPC7, NPC7, NPC7, NPC7, NPC7, NPC7,
    32, 33, 34, 35, 2, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    0, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 60 + 256, 47 + 256, 62 + 256, 20 + 256, 17,
    -39, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
    112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 40 + 256, 64 + 256, 41 + 256, 61 + 256, NPC7,
    NPC7, NPC7, -39, -102, -34, NPC7, NPC7, NPC7, NPC7, NPC7, -83, -39, -214, NPC7, NPC7, NPC7,
    NPC7, -39, -39, -34, -34, -42, -45, -45, -39, NPC7, -115, -39, -111, NPC7, NPC7, -89,
    -32, 64, -99, 1, 36, 3, -33, 95, -34, NPC7, NPC7, -60, NPC7, -45, NPC7, NPC7,
    NPC7, NPC7, -50, -51, -39, -117, NPC7, NPC7, NPC7, -49, NPC7, -62, NPC7, NPC7, NPC7, 96,
    -65, -65, -65, -65, 91, 14, 28, 9, -31, 31, -31, -31, -73, -73, -73, -73,
    -68, 93, -79, -79, -79, -79, 92, -42, 11, -85, -85, -85, 94, -89, NPC7, 30,
    127, -97, -97, -97, 123, 15, 29, -9, 4, 5, -101, -101, 7, 7, -105, -105,
    NPC7, 125, 8, -111, -111, -111, 124, -47, 12, 6, -117, -117, 126, -121, NPC7, -121
};

const unsigned char lookup_gsm7toUnicode[] = {
    64, 163, 36, 165, 232, 233, 249, 236, 242, 199, 10, 216, 248, 13, 197, 229,
    NPC8, 95, NPC8, NPC8, NPC8, NPC8, NPC8, NPC8, NPC8, NPC8, NPC8, 27, 198, 230, 223, 201,
    32, 33, 34, 35, 164, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    161, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 196, 214, 209, 220, 167,
    191, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
    112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 228, 246, 241, 252, 224
};

const unsigned short lookup_Greek7ToUnicode[] = {
    0x394, 95, 0x3a6, 0x393, 0x39b, 0x3a9, 0x3a0, 0x3a8, 0x3a3, 0x398, 0x39e
};

const unsigned short lookup_UnicodeToGreek7[] = {
    19, 16, 0, 0, 0, 25, 0, 0, 20, 0, 0, 26, 0, 22, 0, 0, 24, 0, 0, 18, 0, 23, 21
};