#pragma once

//ref https://www.ipa.go.jp/security/rfc/RFC3174EN.html and astyle

class SHA1 {
	enum
	{
		shaSuccess = 0,
		shaNull,            /* Null pointer parameter */
		shaInputTooLong,    /* input data too long */
		shaStateError       /* called Input after Result */
	};
	#define HashSize 20
	#define CircularShift(bits,word) \ (((word) << (bits)) | ((word) >> (32-(bits))))
public:
	uint32_t Intermediate_Hash[HashSize/4]; /* Message Digest  */
	uint32_t Length_Low;            /* Message length in bits      */
	uint32_t Length_High;           /* Message length in bits      */
	/* Index into message block array   */
	int_least16_t Message_Block_Index;
	uint8_t Message_Block[64];      /* 512-bit message blocks      */
	int Computed;               /* Is the digest computed?         */
	int Corrupted;             /* Is the message digest corrupted? */


	int Reset() {
		Length_Low             = 0;
		Length_High            = 0;
		Message_Block_Index    = 0;
		Intermediate_Hash[0]   = 0x67452301;
		Intermediate_Hash[1]   = 0xEFCDAB89;
		Intermediate_Hash[2]   = 0x98BADCFE;
		Intermediate_Hash[3]   = 0x10325476;
		Intermediate_Hash[4]   = 0xC3D2E1F0;
		Computed   = 0;
		Corrupted  = 0;
		return shaSuccess;
	}

	int Result(uint8_t *Message_Digest) {
		int i;
		if (!Message_Digest) {
			return shaNull;
		}
		if (Corrupted) {
			return Corrupted;
		}
		if (!Computed) {
			PadMessage();
			for(i=0; i<64; ++i) {
				Message_Block[i] = 0;
			}
			Length_Low = 0;    /* and clear length */
			Length_High = 0;
			Computed = 1;
		}
		for(i = 0; i < HashSize; ++i) {
			Message_Digest[i] = Intermediate_Hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) );
		}
		return shaSuccess;
	}

	int Input(const uint8_t  *message_array,  unsigned length) {
		if (!length) {
			return shaSuccess;
		}
		if (!message_array) {
			return shaNull;
		}
		if (Computed) {
			Corrupted = shaStateError;
			return shaStateError;
		}
		if (Corrupted) {
			return Corrupted;
		}
		while(length-- && !Corrupted) {
			Message_Block[Message_Block_Index++] = (*message_array & 0xFF);
			Length_Low += 8;
			if (Length_Low == 0) {
				Length_High++;
				if (Length_High == 0) {
					/* Message is too long */
					Corrupted = 1;
				}
			}
			if (Message_Block_Index == 64) {
				ProcessMessageBlock();
			}
			message_array++;
		}
		return shaSuccess;
	}

	void ProcessMessageBlock() {
		const uint32_t K[] = {       /* Constants defined in SHA-1   */
			0x5A827999,
			0x6ED9EBA1,
			0x8F1BBCDC,
			0xCA62C1D6
		};
		int           t;                 /* Loop counter                */
		uint32_t      temp;              /* Temporary word value        */
		uint32_t      W[80];             /* Word sequence               */
		uint32_t      A, B, C, D, E;     /* Word buffers                */
		for(t = 0; t < 16; t++) {
			W[t] =  Message_Block[t * 4] << 24;
			W[t] |= Message_Block[t * 4 + 1] << 16;
			W[t] |= Message_Block[t * 4 + 2] << 8;
			W[t] |= Message_Block[t * 4 + 3];
		}
		for(t = 16; t < 80; t++) {
			W[t] = CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
		}
		A = Intermediate_Hash[0];
		B = Intermediate_Hash[1];
		C = Intermediate_Hash[2];
		D = Intermediate_Hash[3];
		E = Intermediate_Hash[4];
		for(t = 0; t < 20; t++)
		{
			temp =  CircularShift(5,A) +
			        ((B & C) | ((~B) & D)) + E + W[t] + K[0];
			E = D;
			D = C;
			C = CircularShift(30,B);
			B = A;
			A = temp;
		}
		for(t = 20; t < 40; t++)
		{
			temp = CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
			E = D;
			D = C;
			C = CircularShift(30,B);
			B = A;
			A = temp;
		}
		for(t = 40; t < 60; t++)
		{
			temp = CircularShift(5,A) +
			       ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
			E = D;
			D = C;
			C = CircularShift(30,B);
			B = A;
			A = temp;
		}
		for(t = 60; t < 80; t++)
		{
			temp = CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
			E = D;
			D = C;
			C = CircularShift(30,B);
			B = A;
			A = temp;
		}
		Intermediate_Hash[0] += A;
		Intermediate_Hash[1] += B;
		Intermediate_Hash[2] += C;
		Intermediate_Hash[3] += D;
		Intermediate_Hash[4] += E;
		Message_Block_Index = 0;
	}

	void PadMessage() {
		if (Message_Block_Index > 55)
		{
			Message_Block[Message_Block_Index++] = 0x80;
			while(Message_Block_Index < 64)
			{
				Message_Block[Message_Block_Index++] = 0;
			}
			ProcessMessageBlock();
			while(Message_Block_Index < 56)
			{
				Message_Block[Message_Block_Index++] = 0;
			}
		}
		else
		{
			Message_Block[Message_Block_Index++] = 0x80;
			while(Message_Block_Index < 56)
			{
				Message_Block[Message_Block_Index++] = 0;
			}
		}
		Message_Block[56] = Length_High >> 24;
		Message_Block[57] = Length_High >> 16;
		Message_Block[58] = Length_High >> 8;
		Message_Block[59] = Length_High;
		Message_Block[60] = Length_Low >> 24;
		Message_Block[61] = Length_Low >> 16;
		Message_Block[62] = Length_Low >> 8;
		Message_Block[63] = Length_Low;
		ProcessMessageBlock();
	}
};


