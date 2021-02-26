// RH850/F1L Peripheral modules Description

// Clock Oscillator Registers

enum{
    ENTRG = 1,
    DISTRG = 2
} MOSC_CE;

enum{
    OSC_ACTIVE = 4
}MOSC_ST;

enum{
    FRQ_20_24 = 0,
    FRQ_16_20 = 1,
    FRQ_8_16 = 2,
    FRQ_0_8 = 3
} MOSC_CC;

struct OSC
{
	int CE; 
	int CS; 
	int CC;
	int CST;
	int Reserved[2];
	int CSTPM; 
//	int MOSCM FFF81118H
};

struct PLLCtl
{
	int Enable;
	int Status;
	int Control;
};

struct TMRClkSelReg
{
	int DivCtl;
	int Reserved;
	int Active;
	int Reserved1[3];
	int StopMask;	
};

struct LPS
{
	int SCTLR;
	int EVFR; 
	int DPSELR0; 
	int DPSELRM; 
	int DPSELRH; 
	int DPDSR0; 
	int DPDSRM; 
	int DPDSRH; 
	int DPDIMR[8];
	int CNTVAL;
	int SOSTR;
};

struct MEMC{
    uint16_t BSC;
    uint16_t DEC;
    int reserved;
    int DWC;
    int  DHC;
    int AWC;
    int ICC;
};

struct CSIG
{
	int CTL0;
	int STR0;
	int STCR0;
	int reserved;
	int CTL1;
	int CTL2;	
	int EMU;
	int reserved1[0x3F9];
	int BCTL0;
	int TX0W;
	int TX0H;
	int RX0;	
    int CFG0;
};

union UI64_32
{
	uint64_t U64;
	struct{
		uint32_t L;
		uint32_t H;
	}SU32;
};

struct CSIH
{
	int CTL0;
	int STR0;
	int STCR0;
	int reserved;
	int CTL1;
	int CTL2;
	int EMU;
	int reserved1[0x3F9];
	int MCTL1;
	int MCTL2;
	int TX0W;
	int TX0H;
	int RX0W;
	int RX0H;
	int MRWP0;
	int reserved2[9];
	int MCTL0;
	int CFG[8];
	int reserved3;
	int BRS[4];
};



struct RLIN2Channel
{
	int MD;
	int BFC;
	int SC;
	int WUP;
	int IE;
	int EDE;
	int CUC;
	int reserved;
	int TRC;
	int MST;
	int ST;
	int EST;
	int DFC;
	int IDB;
	int CBR;
	int UDB0;
	int DBR[8];
};

struct RLIN24x
{
	uint8_t align;
	int GLWBR;
	int GLBRP0;
	int GLBRP1;
	int GLSTC;
	int reserved[3];
	struct RLINChannel M[4];
};

struct RLIN21x
{
	uint8_t align;
	int GLWBR;
	int GLBRP0;
	int GLBRP1;
	int GLSTC;
	int reserved[3];
	struct RLIN2Channel M;
};

struct RLIN3Channel
{
	int MD;
	int BFC;
	int SC;
	int WUP;
	int IE;
	int EDE;
	int CUC;
	int reserved;
	int TRC;
	int MST;
	int ST;
	int EST;
	int DFC;
	int IDB;
	int CBR;
	int UDB0;
	int DBR[8];
	int LUOER;
	int LUOR1;
	int reserved2[2];	
	union UI64_32 LUTDR;
	union UI64_32 LURDR;
	union UI64_32 LUWTDR;
};

struct RLIN3
{
	uint8_t align;
	int LWBR;
	int LBRP0;
	int LBRP1;
	int LSTC;
	int reserved[3];
	RLIN3Channel M;
};

struct IIC
{
	int CR1;
	int CR2;
	int MR1;
	int MR2;
	int MR3;
	int FER;
	int SER;
	int IER;
	int SR1;
	int SR2;
	int SAR[3];
	int BRL;
	int BRH;
	int DRT;
	int DRR;
};

// standby controller
enum{
    // Control protection clusters
    PROTCMD0 = 0xFFF80000, // Protection command register 0
    PROTCMD1 = 0xFFF88000, // Protection command register 1 
    PROTS0 = 0xFFF80004, // Protection status register 0 
    PROTS1 = 0xFFF88004, // Protection status register 1 
    // Clock monitor control and test protection cluster
    CLMA0PCMD = 0xFFF8C010, // Protection command register 0 
    CLMA1PCMD = 0xFFF8D010, // Protection command register 1 
    CLMA2PCMD = 0xFFF8E010, // Protection command register 2 
    CLMA0PS = 0xFFF8C014, // Protection status register 0 
    CLMA1PS = 0xFFF8D014, // Protection status register 1 
    CLMA2PS = 0xFFF8E014, // Protection status register 2 
    PROTCMDCLMA = 0xFFF8C200, // Protection command register 
    PROTSCLMA = 0xFFF8C204, // Protection status register 

    // Port protection cluster 0
    JPPCMD0 = 0xFFC204C0, // Protection command registers 
    PPCMD0 = 0xFFC14C00,
    PPCMD1 = 0xFFC14C04,
    PPCMD2 = 0xFFC14C08,
    PPCMD8 = 0xFFC14C20,
    JPPROTS0 = 0xFFC204B0, // Protection status registers 
    PPROTS0 = 0xFFC14B00,
    PPROTS1 = 0xFFC14B04,
    PPROTS2 = 0xFFC14B08,
    PPROTS8 = 0xFFC14B20,
    // Port protection cluster 1
    PPCMD9 = 0xFFC14C24, // Protection command registers 
    PPCMD10 = 0xFFC14C28,
    PPCMD11 = 0xFFC14C2C,
    PPCMD12 = 0xFFC14C30,
    PPCMD18 = 0xFFC14C48,
    PPCMD20 = 0xFFC14C50,


	STBC0PSC = 0xFFF80100,
	STBC0STPT = 0xFFF80110,
	WUF0 = 0xFFF80400,
	WUF20 = 0xFFF80520,
	WUF_ISO0 = 0xFFF88110,
	WUFMSK0 = 0xFFF80404,
	WUFMSK20 = 0xFFF80524,
	WUFMSK_ISO0 = 0xFFF88114,
	WUFC0 = 0xFFF80408,
	WUFC20 = 0xFFF80528,
	WUFC_ISO0 = 0xFFF88118,
	IOHOLD = 0xFFF80B00,
} SFRs;


struct RSCANChannelCtl
{
	int CFG;
	int CTR;
	int STS;
	int ERFL;
};


struct CANRcvRule
{
	int GAFLID;
	int GAFLM;
	int GAFLP0;
	int GAFLP1;
};

struct CANRcvFilter
{
	int ID;
	int PTR;
	int DF0;
	int DF1;
};



struct CANFifoStat
{
	int FESTS; // Empty status
	int FFSTS; // Full stat	
	int FMSTS; // Msg Lost Status
	int RFISTS;// Rcv Buff Interrut Status	
	int CFRISTS;// Transmit/receive FIFO Buffer Receive Interrupt Flag Status Register
	int CFTISTS;// Transmit/receive FIFO Buffer Transmit Interrupt Flag Status Register
};


struct RSCAN
{
	struct RSCANChannelCtl ChanCtl[6];
	int reserved[0x24];
	struct RSCANChannelCtl GlobalCtl;    //<RSCANn_base> + 0084H
	int GTSC;	
	int GAFLECTR;	
	int GAFLCFG0;	
	int GAFLCFG1;	
	int RMNB;	
	int RMND[3];	
	int reserved2;	
	int RFCC[8];	// <RSCANn_base> + 00B8H + (04H * x)
	int RFSTS[8];	
	int RFPCTR[8];	
	int CFCC[17];	
	int reserved3[7];
	int CFSTS[17];	
	int reserved4[7];
	int CFPCTR[17]; 
	int reserved5[7];
	struct CANFifoStat FifoStat;
	int TMC[95];	
	int reserved6[8];
	int TMSTS[95];	
	int reserved7[8];
	int TMTRSTS[3];
	int TMTARSTS[3];
	int reserved8;
	int TMTCSTS[3];
	int reserved9;
	int TMTASTS[3];
	int reserved10;
	int TMIEC[3];
	int reserved;
	int TXQCC[6];
	int reserved11[2];
	int TXQSTS[6];
	int reserved12[2];
	int TXQPCTR[6];
	int reserved13[2];
	int THLCC[6];
	int reserved14[2];
	int THLSTS[6];
	int reserved15[2];
	int THLPCTR[6];
	int reserved16[2];
	int GTINTSTS0;	//<RSCANn_base> + 0460H
	int GTINTSTS1;	//<RSCANn_base> + 0464H
	int GTSTCFG;	//<RSCANn_base> + 0468H
	int GTSTCTR;	//<RSCANn_base> + 046CH
	int reserved17[3];
	int GLOCKK;	// <RSCANn_base> + 047CH
	int reserved18[32];
	struct CANRcvRule GAFL[16]; /* 0500H */
	struct CANRcvFilter RM[95]; /* 0600H */
	struct CANRcvFilter RF[8];  /* 0E00H */
	struct CANRcvFilter CF[17]; /* 0E80H */
	int reserved19[0x1C];
	struct CANRcvFilter TM[95]; /* 1000H */
	int reserved20[0x84];
	int THLACC[6];	 // 1800H <RSCANn_base> + 1800H + (04H * m)
	int RPGACC[64];	 //. 1900H <RSCANn_base> + 1900H + (04H * r)

};

struct WDTA
{
	int WDTE;
	int EVAC;
	int REF; 
	int MD; 
};

struct TAUB
{
	int CDRm[16];
	int TOL;
	int RDT;
	int RSF;
	int reserved[2];
	int TDL;
	int TO;
	int TOE;
	int reserved2[8];
	int CNT[16];  /* 0080H */
	int CMUR[16]; /* 00C0H */
	int reserved3[16];
	int CSR[16];  /* 0140H */
	int CSC[16];  /* 0180H */
	int TE;       /* 1C0H */
	int TS;
	int TT;
	int reserved4[13];
	int CMOR[16];
	
// TAUBn prescaler registers
	int TPS;
	int reserved;
	int TOM;
	int TOC;
	int TDE;
	int reserved[4];
//TAUBn reload data registers
	int RDE;
	int RDM;
	int RDS;
	int RDC;
//TAUBn emulation register
	int reserved2[16];
	int EMU; /* 0290H */

};


struct TAUD
{
	int CDR[16];
	int TOL;
	int RDT;
	int RSF;
	int TRO;
	int TME;
	int TDL;
	int TO;
	int TOE;
	int reserved2[8];
	int CNT[16];  /* 0080H */
	int CMUR[16]; /* 00C0H */
	int reserved3[16];
	int CSR[16];  /* 0140H */
	int CSC[16];  /* 0180H */
	int TE;       /* 1C0H */
	int TS;
	int TT;
	int reserved4[13];
	int CMOR[16];
	int reserved4[13];
	int CMOR[16];
	int TPS;
	int BRS;
	int TOM;
	int TOC;
	int TDE;
	int TDM;
	int TRE;
	int TRC;
	int RDE;
	int RDM;
	int RDS;
	int RDC;
	int reserved2[16];
	int EMU; /* 0290H */
};


struct TAUJ
{
	int CDR[4];
	int CNT[4];
	int CMUR[4];
	int CSR[4];  /* 0140H */
	int CSC[4];  /* 0180H */
	int TE;
	int TS;
	int TT;
	int TO;
	int TOE;	
	int TOL;
	int RDT;
	int RSF;
	int reserved[4];	
	int CMOR[4];
	int TPS;
	int BRS;
	int TOM;
	int TOC;
	int RDE;
	int RDM;
	int EMU;
};

struct RTCA
{
	int CTL0;// <RTCAn_base> + 00H
	int CTL1;// <RTCAn_base> + 04H
	int CTL2;// <RTCAn_base> + 08H
	int SUBC;// <RTCAn_base> + 0CH
	int SRBU;// <RTCAn_base> + 10H
	int SEC;// <RTCAn_base> + 14H
	int MIN;// <RTCAn_base> + 18H
	int HOUR;// <RTCAn_base> + 1CH
	int WEEK;// <RTCAn_base> + 20H
	int DAY;// <RTCAn_base> + 24H
	int MONTH;// <RTCAn_base> + 28H
	int YEAR;// <RTCAn_base> + 2CH
	int TIME;// <RTCAn_base> + 30H
	int CAL;// <RTCAn_base> + 34H
	int SUBU;// <RTCAn_base> + 38H
	int SCMP;// <RTCAn_base> + 3CH
	int ALM;// <RTCAn_base> + 40H
	int ALH;// <RTCAn_base> + 44H
	int ALW;// <RTCAn_base> + 48H
	int SECC;// <RTCAn_base> + 4CH
	int MINC;// <RTCAn_base> + 50H
	int HOURC;// <RTCAn_base> + 54H
	int WEEKC;// <RTCAn_base> + 58H
	int DAYC;// <RTCAn_base> + 5CH
	int MONC;// <RTCAn_base> + 60H
	int YEARC;// <RTCAn_base> + 64H
	int TIMEC;// <RTCAn_base> + 68H
	int CALC;// <RTCAn_base> + 6CH
	int reserved;
	int EMU;// <RTCAn_base> + 74H

};

struct ENCA
{
	int CCR0; // <ENCAn_base>
	int CCR1; // <ENCAn_base> + 04H
	int CNT; // <ENCAn_base> + 08H
	int FLG; // <ENCAn_base> + 0CH
	int FGC; // <ENCAn_base> + 10H
	int TE; // <ENCAn_base> + 14H
	int TS; // <ENCAn_base> + 18H
	int TT; // <ENCAn_base> + 1CH
	int IOC0; // <ENCAn_base> + 20H
	int reserved[3];
	int CTL; // <ENCAn_base> + 40H
	int IOC1; // <ENCAn_base> + 44H
	int EMU; // <ENCAn_base> + 48H
};

struct OSTM
{
    int CMP; // OSTMn compare register OSTMnCMP <OSTMn_base> + 00H
    int CNT; // OSTMn counter register OSTMnCNT <OSTMn_base> + 04H
    int reserved[2];
    int TE;  // OSTMn count enable status register OSTMnTE <OSTMn_base> + 10H
	int TS;  // OSTMn count start trigger register OSTMnTS <OSTMn_base> + 14H
	int TT;  // OSTMn count stop trigger register OSTMnTT <OSTMn_base> + 18H
	int reserved1;
	int CTL; // OSTMn control register OSTMnCTL <OSTMn_base> + 20H
	int EMU; // OSTMn emulation register OSTMnEMU <OSTMn_base> + 24H
};

struct DMAChannel
{
    uint32_t DSA;             // 14
    uint32_t reserved[3];
    uint32_t DDA;
    uint8_t reserved1[10];
    uint32_t DTC;
    uint8_t reserved2[2];
    uint16_t DTCT;
    uint32_t DTS;
    uint8_t reserved3[6];
};

enum{
    RESF_DeepSTOP = 0x400,  // Reset flag by DeepSTOP mode
    RESF_PUR = 0x200,       // Power-up reset flag
    RESF_EXTR = 0x100,      // External reset flag
    RESF_CVM = 0x80,        // CVM reset flag
    RESF_LVI = 0x40,         // LVI reset flag
    RESF_CLMA2 = 0x20,      // RESF5 CLMA2 reset flag
    RESF_CLMA1 = 0x10,      // RESF5 CLMA1 reset flag
    RESF_CLMA0 = 0x8,       // CLMA0 reset flag
    RESF_WDTA1 = 0x4,       // WDT1 reset flag
    RESF_WDTA0 = 0x2,       // WDTA0 reset flag
    RESF_SR    = 0x01       // Software reset flag
}RESF;
