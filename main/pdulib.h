/**
 * @file pdulib.h
 * @brief Encode/Decode PDU data (Pure ESP-IDF Standard C++ Version)
 */

#ifndef PDU_LIB_INCLUDE
#define PDU_LIB_INCLUDE

#define BITMASK_7BITS 0x7F

#define DCS_COMPRESSED (5<<1)
#define DCS_CLASS_MEANING (4<<1)
#define DCS_ALPHABET_MASK (3<<2)
#define DCS_ALPHABET_OFFSET 2
#define DCS_7BIT_ALPHABET_MASK  0B0000 
#define DCS_8BIT_ALPHABET_MASK  0B0100 
#define DCS_16BIT_ALPHABET_MASK 0B1000 
#define DCS_CLASS_MASK 3
#define DCS_IMMEDIATE_DISPLAY 3
#define DCS_ME_SPECIFIC_MASK 1
#define DCS_SIM_SPECIFIC_MASK 2
#define DCS_TE_SPECIFIC_MASK 3

#define PDU_VALIDITY_MASK_OFFSET 3
#define PDU_VALIDITY_NOT_PRESENT 0
#define PDU_VALIDITY_PRESENT_RELATIVE 2
#define PDU_VALIDITY_PRESENT_ENHANCED 1
#define PDU_VALIDITY_PRESENT_ABSOLUTE 3
#define PDU_UDHI 6

#define PDU_SMS_DELIVER 0
#define PDU_SMS_SUBMIT  1

#define INTERNATIONAL_NUMBER 0x91
#define NATIONAL_NUMBER 0xA1

#define EXT_MASK 0x80
#define TON_MASK 0x70
#define TON_OFFSET 4
#define NPI_MASK 0x0f

#define MAX_SMS_LENGTH_7BIT 160 
#define MAX_NUMBER_OCTETS 140
#define MAX_NUMBER_LENGTH 20    
#define UTF8_BUFFSIZE 100   

#define PDU_BINARY_MAX_LENGTH 170

#define NPC7    63
#define NPC8    '?'

#define EURO_UCS 0x20AC

enum eDCS { ALPHABET_7BIT, ALPHABET_8BIT, ALPHABET_16BIT };
enum eAddressType {INTERNATIONAL_NUMERIC,NATIONAL_NUMERIC,ALPHABETIC};
enum eLengthType {OCTETS,NIBBLES};  

class PDU
{
public:
  PDU(int = UTF8_BUFFSIZE);
  ~PDU();
  
  int encodePDU(const char *recipient,const char *message,unsigned short csms=0, unsigned char numparts=0, unsigned char partnumber=0);
  const char *getSMS();
  void setSCAnumber(const char *number);
  void setSCAnumber();
  bool decodePDU(const char *pdu);
  const char *getSCAnumber();
  const char *getSender();
  const char *getTimeStamp();
  const char *getText();
  
  void buildUtf16(unsigned long codepoint, char *target); 
  int buildUtf(unsigned long codepoint, char *target); 
  int utf8_to_ucs2(const char *utf8, char *ucs2);  
  bool isGSM7(unsigned short *pucs);  
  int utf8Length(const char *);
  int utf8_to_ucs2_single(const char *utf8, unsigned short *pucs2);  
  int * getConcatInfo();
  bool getOverflow();
  
  enum eEncodeError {OBSOLETE_ERROR = -1,UCS2_TOO_LONG = -2, GSM7_TOO_LONG = -3, MULTIPART_NUMBERS = -4,ADDRESS_FORMAT=-5,WORK_BUFFER_TOO_SMALL=-6,ALPHABET_8BIT_NOT_SUPPORTED = -7};
  
private:
  bool overFlow;
  int scalength;
  char scabuffin[MAX_NUMBER_LENGTH+1]; 
  char scabuffout[MAX_NUMBER_LENGTH+1]; 
  int addressLength;  
  char addressBuff[MAX_NUMBER_LENGTH+1];  
  int generalWorkBuffLength;  
  char *generalWorkBuff;  
  int tslength;
  char tsbuff[20];    
  int smsOffset;
  int concatInfo[3];
  unsigned char udhbuffer[8];
  
  bool phoneNumberLegal(const char *);  
  void stringToBCD(const char *number, char *pdu);
  void BCDtoString(char *number, const char *pdu,int length);
  void digitSwap(const char *number, char *pdu);
  int utf8_to_packed7bit(const char *utf8, char *pdu, int *septets, int UDHsize, int availableSpace);
  int pduGsm7_to_unicode(const char *pdu, int pdulength, char *ascii,char firstchar);
  int convert_utf8_to_gsm7bit(const char *ascii, char *a7bit, int udhsize, int availableSpace);
  int convert_7bit_to_unicode(unsigned char *a7bit, int length, char *ascii);
  unsigned char gethex(const char *pc);
  void putHex(unsigned char b, char *target);
  int pdu_to_ucs2(const char *pdu, int length, unsigned short *ucs2);
  int ucs2_to_utf8(unsigned short ucs2, char *utf8);
  int decodeAddress(const char *,char *, eLengthType);  
  bool setAddress(const char *,eLengthType, char *);
  int buildUDH(unsigned short,unsigned,unsigned);
};

extern const short lookup_ascii8to7[];
extern const unsigned char lookup_gsm7toUnicode[];
extern const unsigned short lookup_Greek7ToUnicode[];

#define GREEK_UCS_MINIMUM 0x393
extern const unsigned short lookup_UnicodeToGreek7[];

struct sRange {
  unsigned short min,max;
};
extern const struct sRange gsm7_legal[];

#endif