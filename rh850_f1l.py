# /usr/bin/python3
# coding=cp1251

import idaapi
import idc
from os.path import abspath
idaapi.require("ida_structs")
import ida_structs
import re


print(abspath(__file__))

memmap = [
    {
        'name': 'MainOSC',
        'type': 'OSC',
        'addr': 0xFFF81100,
        'comment': 'Main OSC Control Registers'
    },    
    {
        'name': 'SubOSC',
        'type': 'OSC',
        'addr': 0xFFF81200,
        'comment': 'Sub OSC Control Registers'
    },    
    {
        'name': 'ROSC',
        'type': 'OSC',
        'addr': 0xFFF81000,
        'comment': 'HS IntOSC Control Registers'
    },    
    {
        'name': 'PLLC',
        'type': 'PLLCtl',
        'addr': 0xFFF89000,
        'comment': 'PLL Control Registers'
    },    
    {
        'name': 'CKSC_AWDTAD',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF82000,
        'comment': 'WDTA0 Clock Domain C_AWO_WDTA'
    },    
    {
        'name': 'CKSC_ATAUJS',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF82100,
        'comment': 'TAUJ Clock Domain C_AWO_TAUJ'
    },    
    {
        'name': 'CKSC_ATAUJD',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF82200,
        'comment': 'TAUJ Source Clock C_AWO_TAUJ'
    },    
    {
        'name': 'CKSC_ARTCAS',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF82300,
        'comment': 'RTCA Source Clock Selection'
    },    
    {
        'name': 'CKSC_ARTCAD',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF82400,
        'comment': 'RTCA Clock Divider'
    },    
    {
        'name': 'CKSC_AADCAS',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF82500,
        'comment': 'ADCA Source Clock Selection'
    },    
    {
        'name': 'CKSC_AADCAD',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF82600,
        'comment': 'ADCA Clock Divider'
    },    
    {
        'name': 'CKSC_AFOUTS',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF82700,
        'comment': 'FOUT Source Clock'
    },    
    {
        'name': 'CKSC_CPUCLKS',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF8A000,
        'comment': 'CPU Clock Domain Source'
    },    
    {
        'name': 'CKSC_CPUCLKD',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF8A100,
        'comment': 'CPU Clock Domain Divider'
    },    
    {
        'name': 'CKSC_IPERI1S',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF8A200,
        'comment': 'Peripheral Clock Domain 1 Source'
    },    
    {
        'name': 'CKSC_IPERI2S',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF8A300,
        'comment': 'Peripheral Clock Domain 2 Source'
    },    
    {
        'name': 'CKSC_ILINS',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF8A400,
        'comment': 'RLIN Clock Domains Source'
    },    
    {
        'name': 'CKSC_ILIND',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF8A800,
        'comment': 'RLIN Clock Domains Divider'
    },    
    {
        'name': 'CKSC_IADCAS',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF8A500,
        'comment': 'ADCA1 Clock Domain Source'
    },    
    {
        'name': 'CKSC_IADCAD',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF8A600,
        'comment': 'ADCA1 Clock Domain Divider'
    },    
    {
        'name': 'CKSC_ICANS',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF8A900,
        'comment': 'RS-CAN Clock Domains Source'
    },    
    {
        'name': 'CKSC_ICANOSCD',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF8AA00,
        'comment': 'RS-CAN Clock Divider'
    },    
    {
        'name': 'CKSC_ICSIS',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF8AB00,
        'comment': 'CSI Clock Domain Source'
    },    
    {
        'name': 'CKSC_IIICS',
        'type': 'TMRClkSelReg',
        'addr': 0xFFF8AC00,
        'comment': 'I2C Clock Domain Source'
    },    
    {
        'name': 'LPS0',
        'type': 'LPS',
        'addr': 0xFFBC2000,
        'comment': 'Low-Power Sampler (LPS)'
    },    

    {
        'name': 'CSIG0',
        'type': 'CSIG',
        'addr': 0xFFDB0000,
        'comment': 'Clocked Serial Interface G (CSIG0)'
    },    
    {
        'name': 'CSIG1',
        'type': 'CSIG',
        'addr': 0xFFDB2000,
        'comment': 'Clocked Serial Interface G (CSIG1)'
    },    

    {
        'name': 'CSIH0',
        'type': 'CSIH',
        'addr': 0xFFD80000,
        'comment': 'Clocked Serial Interface H (CSIH0)'
    },    
    {
        'name': 'CSIH1',
        'type': 'CSIH',
        'addr': 0xFFD82000,
        'comment': 'Clocked Serial Interface H (CSIH1)'
    },    
    {
        'name': 'CSIH2',
        'type': 'CSIH',
        'addr': 0xFFD84000,
        'comment': 'Clocked Serial Interface H (CSIH2)'
    },    
    {
        'name': 'CSIH3',
        'type': 'CSIH',
        'addr': 0xFFD86000,
        'comment': 'Clocked Serial Interface H (CSIH3)'
    },    

    {
        'name': 'RLIN240',
        'type': 'RLIN24x',
        'addr': 0xFFCE0000,
        'comment': 'LIN/UART Interface 2 (RLIN2)'
    },    
    {
        'name': 'RLIN241',
        'type': 'RLIN24x',
        'addr': 0xFFCE0080,
        'comment': 'LIN/UART Interface 2 (RLIN2)'
    },    
    {
        'name': 'RLIN210',
        'type': 'RLIN21x',
        'addr': 0xFFCE0100,
        'comment': 'LIN/UART Interface 2 (RLIN2)'
    },    
    {
        'name': 'RLIN211',
        'type': 'RLIN21x',
        'addr': 0xFFCE0120,
        'comment': 'LIN/UART Interface 2 (RLIN2)'
    },    

    {
        'name': 'RLIN30',
        'type': 'RLIN3',
        'addr': 0xFFCF0000,
        'comment': 'LIN/UART Interface 3 (RLIN3)'
    },    
    {
        'name': 'RLIN31',
        'type': 'RLIN3',
        'addr': 0xFFCF0040,
        'comment': 'LIN/UART Interface 3 (RLIN3)'
    },    
    {
        'name': 'RLIN32',
        'type': 'RLIN3',
        'addr': 0xFFCF0080,
        'comment': 'LIN/UART Interface 3 (RLIN3)'
    },    
    {
        'name': 'RLIN33',
        'type': 'RLIN3',
        'addr': 0xFFCF00C0,
        'comment': 'LIN/UART Interface 3 (RLIN3)'
    },    
    {
        'name': 'RLIN34',
        'type': 'RLIN3',
        'addr': 0xFFCF0100,
        'comment': 'LIN/UART Interface 3 (RLIN3)'
    },    
    {
        'name': 'RLIN35',
        'type': 'RLIN3',
        'addr': 0xFFCF0120,
        'comment': 'LIN/UART Interface 3 (RLIN3)'
    },    
    {
        'name': 'RIIC0',
        'type': 'IIC',
        'addr': 0xFFCA0000,
        'comment': 'I2C Bus Interface (RIIC)'
    },    
    {
        'name': 'RIIC1',
        'type': 'IIC',
        'addr': 0xFFCA0080,
        'comment': 'I2C Bus Interface (RIIC)'
    },    
    {
        'name': 'RSCAN0',
        'type': 'RSCAN',
        'addr': 0xFFD00000,
        'comment': 'CAN Interface (RS-CAN)'
    },    
    {
        'name': 'WDTA0',
        'type': 'WDTA',
        'addr': 0xFFED0000,
        'comment': 'Window Watchdog Timer (WDTA)'
    },    
    {
        'name': 'WDTA1',
        'type': 'WDTA',
        'addr': 0xFFED1000,
        'comment': 'Window Watchdog Timer (WDTA)'
    },    
    {
        'name': 'TAUB0',
        'type': 'TAUB',
        'addr': 0xFFE30000,
        'comment': 'Timer Array Unit B (TAUB)'
    },    
    {
        'name': 'TAUB1',
        'type': 'TAUB',
        'addr': 0xFFE31000,
        'comment': 'Timer Array Unit B (TAUB)'
    },    

    {
        'name': 'TAUD0',
        'type': 'TAUD',
        'addr': 0xFFE20000,
        'comment': 'Timer Array Unit D (TAUD)'
    },    

    {
        'name': 'TAUJ0',
        'type': 'TAUJ',
        'addr': 0xFFE50000,
        'comment': 'Timer Array Unit J (TAUJ)'
    },    
    {
        'name': 'TAUJ1',
        'type': 'TAUJ',
        'addr': 0xFFE51000,
        'comment': 'Timer Array Unit J (TAUJ)'
    },    
    {
        'name': 'SELB_TAUJ0I',
        'type': 'int',
        'addr': 0xFFE54000,
        'comment': 'Timer Array Unit J (TAUJ)'
    },    
    {
        'name': 'RTCA0',
        'type': 'RTCA',
        'addr': 0xFFE78000,
        'comment': 'Real-Time Clock (RTCA)'
    },    

    {
        'name': 'ENCA0',
        'type': 'ENCA',
        'addr': 0xFFE80000,
        'comment': 'Encoder Timer (ENCA)'
    },    
    {
        'name': 'MEMC0',
        'type': 'MEMC',
        'addr': 0xFFFF8200,
        'comment': 'External Memory Access Controller(MEMC)'
    },
    {
        'name': 'OSTM0',
        'type': 'OSTM',
        'addr': 0xFFEC0000,
        'comment': 'OS Timer (OSTM)'
    },

    # DMA0
    {
        'name': 'DTRC0',
        'type': 'uint32_t',
        'addr': 0xFFFF8300,
        'comment': 'DMA transfer request control register 0'
    },
    {
        'name': 'DMCM0',
        'type': 'uint32_t',
        'addr': 0xFFFF8304,
        'comment': 'DMA channel master setting register 0'
    },
    {
        'name': 'DMA0U0[8]',
        'type': 'DMAChannel',
        'addr': 0xFFFF8314,
        'comment': 'DMA Channel registers (m = 0 to 7)'
    },
    {
        'name': 'DMA0U1[8]',
        'type': 'DMAChannel',
        'addr': 0xFFFF8514,
        'comment': 'DMA Channel registers (m = 8 to 15)'
    },
    {
        'name': 'DTFR[16]',
        'type': 'uint16_t',
        'addr': 0xFFFF8B00,
        'comment': 'DMA trigger factor registers'
    },
    {
        'name': 'DRQCLR',
        'type': 'uint32_t',
        'addr': 0xFFFF8B40,
        'comment': 'DMA request clear register'
    },
    {
        'name': 'DRQSTR',
        'type': 'uint32_t',
        'addr': 0xFFFF8B44,
        'comment': 'DMA request check register'
    },
]

single_regs = """
PROTCMD0      : 0xFFF80000 : Protection command register 0 
PROTCMD1      : 0xFFF88000 : Protection command register 1 
PROTS0        : 0xFFF80004 : Protection status register 0 
PROTS1        : 0xFFF88004 : Protection status register 1 
CLMA0PCMD     : 0xFFF8C010 : Protection command register 0 
CLMA1PCMD     : 0xFFF8D010 : Protection command register 1 
CLMA2PCMD     : 0xFFF8E010 : Protection command register 2 
CLMA0PS       : 0xFFF8C014 : Protection status register 0 
CLMA1PS       : 0xFFF8D014 : Protection status register 1 
CLMA2PS       : 0xFFF8E014 : Protection status register 2 
PROTCMDCLMA   : 0xFFF8C200 : Protection command register 
PROTSCLMA     : 0xFFF8C204 : Protection status register 
JPPCMD0       : 0xFFC204C0 : Protection command register 
PPCMD0        : 0xFFC14C00 : Protection command register 0
PPCMD1        : 0xFFC14C04 : Protection command register 1
PPCMD2        : 0xFFC14C08 : Protection command register 2
PPCMD8        : 0xFFC14C20 : Protection command register 3
JPPROTS0      : 0xFFC204B0 : Protection status register 
PPROTS0       : 0xFFC14B00 : Protection status register 0
PPROTS1       : 0xFFC14B04 : Protection status register 1
PPROTS2       : 0xFFC14B08 : Protection status register 2
PPROTS8       : 0xFFC14B20 : Protection status register 3
PPCMD9        : 0xFFC14C24 : Protection command registers 
PPCMD10       : 0xFFC14C28 : Protection command registers 
PPCMD11       : 0xFFC14C2C : Protection command registers 
PPCMD12       : 0xFFC14C30 : Protection command registers 
PPCMD18       : 0xFFC14C48 : Protection command registers 
PPCMD20       : 0xFFC14C50 : Protection command registers 
PPROTS9       : 0xFFC14B24 : Protection status registers 
PPROTS10      : 0xFFC14B28 : Protection status registers 
PPROTS11      : 0xFFC14B2C : Protection status registers 
PPROTS12      : 0xFFC14B30 : Protection status registers 
PPROTS18      : 0xFFC14B48 : Protection status registers 
PPROTS20      : 0xFFC14B50 : Protection status registers 
PROTCMDCVM    : 0xFFF50100 : Protection command register 
PROTSCVM      : 0xFFF50104 : Protection status register 
FLMDPCMD      : 0xFFA00004 : Protection command register 
FLMDPS        : 0xFFA00008 : Protection error status register 
RESF          : 0xFFF80760 : Reset factor register 
RESFC         : 0xFFF80768 : Reset factor clear register 
RESFR         : 0xFFF80860 : Redundant reset factor register 
RESFCR        : 0xFFF80868 : Redundant reset factor clear register 
SWRESA        : 0xFFF80A04 : Software reset register 
LVICNT        : 0xFFF80A00 : LVI control register
CVMF          : 0xFFF50000 : CVM factor register
CVMDE         : 0xFFF50004 : CVM detection enable register
CVMDIAG       : 0xFFF50014 : CVM diagnostic mode setting register
VLVF          : 0xFFF80980 : Very-low-voltage detection register
VLVFC         : 0xFFF80988 : Very-low-voltage detection clear register

STBC0PSC      : 0xFFF80100 : Power save control register 
STBC0STPT     : 0xFFF80110 : Power stop trigger register 
WUF0          : 0xFFF80400 : Wake-up factor register
WUF20         : 0xFFF80520 : Wake-up factor 2 register 
WUF_ISO0      : 0xFFF88110 : Wake-up factor ISO register 
WUFMSK0       : 0xFFF80404 : Wake-up factor mask registers 
WUFMSK20      : 0xFFF80524 : Wake-up factor 2 mask registers 
WUFMSK_ISO0   : 0xFFF88114 : Wake-up factor ISO mask registers 
WUFC0         : 0xFFF80408 : Wake-up factor clear registers 
WUFC20        : 0xFFF80528 : Wake-up factor 2 clear registers  
WUFC_ISO0     : 0xFFF88118 : Wake-up factor ISO clear registers  
IOHOLD        : 0xFFF80B00 : I/O buffer hold control register 

RESF          : 0xFFF80760 : Reset factor register 
RESFC         : 0xFFF80768 : Reset factor clear register 
RESFR         : 0xFFF80860 : Redundant reset factor register 
RESFCR        : 0xFFF80868 : Redundant reset factor clear register 
SWRESA        : 0xFFF80A04 : Software reset register 

LVICNT        : 0xFFF80A00 : LVI control register 
CVMF          : 0xFFF50000 : CVM factor register 
CVMDE         : 0xFFF50004 : CVM detection enable register 
CVMDIAG       : 0xFFF50014 : CVM diagnostic mode setting register 
VLVF          : 0xFFF80980 : Very-low-voltage detection register 
VLVFC         : 0xFFF80988 : Very-low-voltage detection clear register 
FOUTDIV       : 0xFFF82800 : FOUT Clock division ratio register 
FOUTSTAT      : 0xFFF82804 : FOUT Clock divider status register 

FLMDCNT       : 0xFFA00000 : FLMDCNT Register
EEPRDCYCL     : 0xFFC5A010 : Data Flash Wait Cycle Control Register
PRDNAME[3]    : 0xFFCD00D0 : Product Name Storage Registers

FCLA0CTL0_NMI   :   0xFFC34000  :   input Signal - NMI 
FCLA0CTL0_INTPL :   0xFFC34020  :   input Signal - INTP0 
FCLA0CTL1_INTPL :   0xFFC34024  :   input Signal - INTP1 
FCLA0CTL2_INTPL :   0xFFC34028  :   input Signal - INTP2 
FCLA0CTL3_INTPL :   0xFFC3402C  :   input Signal - INTP3 
FCLA0CTL4_INTPL :   0xFFC34030  :   input Signal - INTP4 
FCLA0CTL5_INTPL :   0xFFC34034  :   input Signal - INTP5 
FCLA0CTL6_INTPL :   0xFFC34038  :   input Signal - INTP6 
FCLA0CTL7_INTPL :   0xFFC3403C  :   input Signal - INTP7 
FCLA0CTL0_INTPH :   0xFFC34040  :   input Signal - INTP8 
FCLA0CTL1_INTPH :   0xFFC34044  :   input Signal - INTP9 
FCLA0CTL2_INTPH :   0xFFC34048  :   input Signal - INTP10 
FCLA0CTL3_INTPH :   0xFFC3404C  :   input Signal - INTP11 
FCLA0CTL4_INTPH :   0xFFC34050  :   input Signal - INTP12 
FCLA0CTL5_INTPH :   0xFFC34054  :   input Signal - INTP13 
FCLA0CTL6_INTPH :   0xFFC34058  :   input Signal - INTP14 
FCLA0CTL7_INTPH :   0xFFC3405C  :   input Signal - INTP15
DNFA_ADCTL0CTL  :   0xFFC300A0  :   Digital Noise Elimination Control Register
DNFA_ADCTL1CTL  :   0xFFC300C0  :   Digital Noise Elimination Control Register
DNFA_ADCTL0EN   :   0xFFC300A4  :   Digital Noise Elimination Enable Register
DNFA_ADCTL0ENL  :   0xFFC300AC  :   Digital Noise Elimination Enable Register
DNFA_ADCTL1EN   :   0xFFC300C4  :   Digital Noise Elimination Enable Register
DNFAA_DCTL1ENL  :   0xFFC300CC  :   Digital Noise Elimination Enable Register
FCLA0CTL0_ADC0  :   0xFFC34060  :   Filter Control Register
FCLA0CTL1_ADC0  :   0xFFC34064  :   Filter Control Register
FCLA0CTL2_ADC0  :   0xFFC34068  :   Filter Control Register
FCLA0CTL0_ADC1  :   0xFFC34080  :   Filter Control Register
FCLA0CTL1_ADC1  :   0xFFC34084  :   Filter Control Register
FCLA0CTL2_ADC1  :   0xFFC34088  :   Filter Control Register
DNFA_TAUD0ICTL  :   0xFFC30000  :   Digital Noise Elimination Control Register
DNFA_TAUD0IEN   :   0xFFC30004  :   Digital Noise Elimination Enable Register
DNFA_TAUD0IENH  :   0xFFC30008  :   Digital Noise Elimination Enable Register
DNFA_TAUD0IENL  :   0xFFC3000C  :   Digital Noise Elimination Enable Register
DNFA_TAUB0IEN   :   0xFFC30024  :   Digital Noise Elimination Enable Register
DNFA_TAUB0IENH  :   0xFFC30028  :   Digital Noise Elimination Enable Register
DNFA_TAUB0IENL  :   0xFFC3002C  :   Digital Noise Elimination Enable Register
DNFA_TAUB0ICTL  :   0xFFC30020  :   Digital Noise Elimination Control Register
DNFA_TAUB1IEN   :   0xFFC30044  :   Digital Noise Elimination Enable Register
DNFA_TAUB1IENH  :   0xFFC30048  :   Digital Noise Elimination Enable Register
DNFA_TAUB1IENL  :   0xFFC3004C  :   Digital Noise Elimination Enable Register
DNFA_ENCA0IEN   :   0xFFC30064  :   Digital Noise Elimination Enable Register
DNFA_ENCA0IENL  :   0xFFC3006C  :   Digital Noise Elimination Enable Register
DNFA_TAUB1ICTL  :   0xFFC30040  :   Digital Noise Elimination Control Register
DNFA_ENCA0ICTL  :   0xFFC30060  :   Digital Noise Elimination Control Register


"""


port_n = [0, 1, 2, 8, 9, 10, 11, 12, 18, 20]
ap_n = [0,1]


ap_defs="""
APMn        :   <PORTn_base> + 03C8H + n * 4    : Port mode register 
APMSRn      :   <PORTn_base> + 08C8H + n * 4    : Port mode set/reset register 
APIBCn      :   <PORTn_base> + 40C8H + n * 4    : Port input buffer control register 
APBDCn      :   <PORTn_base> + 41C8H + n * 4    : Port bidirection control register 
APPRn       :   <PORTn_base> + 02C8H + n * 4    : Port pin read register 
APn         :   <PORTn_base> + 00C8H + n * 4    : Port register 
APNOTn      :   <PORTn_base> + 07C8H + n * 4    : Port NOT register 
APSRn       :   <PORTn_base> + 01C8H + n * 4    : Port set/reset register 
"""

port_defs="""
PMCn        :   <PORTn_base> + 0400H + n * 4    : Port mode control register
JPMC0       :   <JPORT0_base> + 0040H           : Port mode control register
PMCSRn      :   <PORTn_base> + 0900H + n * 4    : Port mode control set/reset register 
JPMCSR0     :   <JPORT0_base> + 0090H           : Port mode control set/reset register 
PIPCn       :   <PORTn_base> + 4200H + n * 4    : Port IP control register 
PMn         :   <PORTn_base> + 0300H + n * 4    : Port mode register 
JPM0        :  <JPORT0_base> + 0030H            : Port mode register 
PMSRn       :   <PORTn_base> + 0800H + n * 4    : Port mode set/reset register 
JPMSR0      :   <JPORT0_base> + 0080H           : Port mode set/reset register 
PIBCn       :   <PORTn_base> + 4000H + n * 4    : Port input buffer control register 
JPIBC0      :   <JPORT0_base> + 0400H           : Port input buffer control register 
IPIBC0      :   <PORTn_base> + 40F0H            : Port input buffer control register 
PFCn        :   <PORTn_base> + 0500H + n * 4    : Port function control register 
JPFC0       :   <JPORT0_base> + 0050H           : Port function control register 
PFCEn       :   <PORTn_base> + 0600H + n * 4    : Port function control expansion register 
PFCAEn      :   <PORTn_base> + 0A00H + n * 4    : Port function control additional expansion register 
PBDCn       :   <PORTn_base> + 4100H + n * 4    : Port bidirection control register 
JPBDC0      :   <JPORT0_base> + 0410H           : Port bidirection control register
PPRn        :   <PORTn_base> + 0200H + n * 4    : Port pin read register 
JPPR0       :   <JPORT0_base> + 0020H           : Port pin read register 
IPPR0       :   <PORTn_base> + 02F0H            : Port pin read register 
Pn          :   <PORTn_base> + 0000H + n * 4    : Port register 
JP0         :  <JPORT0_base> + 0000H            : Port register 
PNOTn       :   <PORTn_base> + 0700H + n * 4    : Port NOT register 
JPNOT0      :   <JPORT0_base> + 0070H           : Port NOT register
PSRn        :   <PORTn_base> + 0100H + n * 4    : Port set/reset register 
JPSR0       :   <JPORT0_base> + 0010H           : Port set/reset register 
PUn         :   <PORTn_base> + 4300H + n * 4    : Pull-up option register
JPU0        :   <JPORT0_base> + 0430H           : Pull-up option register
PDn         :   <PORTn_base> + 4400H + n * 4    : Pull-down option register 
JPD0        :   <JPORT0_base> + 0440H           : Pull-down option register 
PDSCn       :   <PORTn_base> + 4600H + n * 4    : Port drive strength control register 
PODCn       :   <PORTn_base> + 4500H + n * 4    : Port open drain control register
JPODC0      :   < JPORT0_base> + 0450H          : Port open drain control register
PISn        :   <PORTn_base> + 4700H + n * 4    : Port input buffer selection register 
JPISA0      :   <JPORT0_base> + 04A0H           : Port input buffer selection advanced register 
PPCMDn      :   <PORTn_base> + 4C00H + n * 4    : Port protection command register
JPPCMD0     :   <JPORT0_base> + 04C0H           : Port protection command register
PPROTSn     :   <PORTn_base> + 4B00H + n * 4    : Port protection status register 
JPPROTS0    :   <JPORT0_base> + 04B0H           : Port protection status register 
"""

interrupt_control = """
ICTAUD0I0       :   0xFFFF9000  :   INTTAUD0I0 Interrupt for TAUD0 channel 0, CSIH2 communication status interrupt 
ICTAUD0I2       :   0xFFFF9002  :   INTTAUD0I2 Interrupt for TAUD0 channel 2,  CSIH3 communication status interrupt 
ICTAUD0I4       :   0xFFFF9004  :   INTTAUD0I4 Interrupt for TAUD0 channel 4 
ICTAUD0I6       :   0xFFFF9006  :   INTTAUD0I6 Interrupt for TAUD0 channel 6 
ICTAUD0I8       :   0xFFFF9008  :   INTTAUD0I8 Interrupt for TAUD0 channel 8 
ICTAUD0I10      :   0xFFFF900A  :   INTTAUD0I10 Interrupt for TAUD0 channel 10, CSIH3 receive status interrupt 
ICTAUD0I12      :   0xFFFF900C  :   INTTAUD0I12 Interrupt for TAUD0 channel 12, CSIH3 communication error interrupt 
ICTAUD0I14      :   0xFFFF900E  :   INTTAUD0I14 Interrupt for TAUD0 channel 14, CSIH3 job completion interrupt 
ICTAPA0IPEK0    :   0xFFFF9010  :   INTTAPA0IPEK0 TAPA0 peak interrupt 0, CSIH1 communication status interrupt 
ICTAPA0IVLY0    :   0xFFFF9012  :   INTTAPA0IVLY0 TAPA0 valley interrupt 0, CSIH1 receive status interrupt 
ICADCA0I0       :   0xFFFF9014  :   INTADCA0I0 ADCA0 scan group 1 (SG1) end interrupt
ICADCA0I1       :   0xFFFF9016  :   INTADCA0I1 ADCA0 scan group 2 (SG2) end interrupt
ICADCA0I2       :   0xFFFF9018  :   INTADCA0I2 ADCA0 scan group 3 (SG3) end interrupt
ICDCUTDI        :   0xFFFF901A  :   INTDCUTDI Dedicated interrupt for on-chip debug function
ICRCANGERR      :   0xFFFF901C  :   INTRCANGERR CAN global error interrupt 
ICRCANGRECC     :   0xFFFF901E  :   INTRCANGRECC CAN receive FIFO interrupt
ICRCAN0ERR      :   0xFFFF9020  :   INTRCAN0ERR CAN0 error interrupt 
ICRCAN0REC      :   0xFFFF9022  :   INTRCAN0REC CAN0 transmit/receive FIFO receive complete interrupt
ICRCAN0TRX      :   0xFFFF9024  :   INTRCAN0TRX CAN0 transmit interrupt 
ICCSIG0IC       :   0xFFFF9026  :   INTCSIG0IC CSIG0 communication status interrupt, CSIH1 communication error interrupt
ICCSIG0IR       :   0xFFFF9028  :   INTCSIG0IR CSIG0 receive status interrupt, CSIH1 job complete interrupt
ICCSIH0IC       :   0xFFFF902A  :   INTCSIH0IC CSIH0 communication status interrupt
ICCSIH0IR       :   0xFFFF902C  :   INTCSIH0IR CSIH0 receive status interrupt
ICCSIH0IRE      :   0xFFFF902E  :   INTCSIH0IRE CSIH0 communication error interrupt
ICCSIH0IJC      :   0xFFFF9030  :   INTCSIH0IJC CSIH0 job completion interrupt
ICRLIN30        :   0xFFFF9032  :   INTRLIN30 RLIN30 interrupt
ICRLIN30UR0     :   0xFFFF9034  :   INTRLIN30UR0 RLIN30 transmit interrupt
ICRLIN30UR1     :   0xFFFF9036  :   INTRLIN30UR1 RLIN30 reception complete interrupt
ICRLIN30UR2     :   0xFFFF9038  :   INTRLIN30UR2 RLIN30 status interrupt
ICP0            :   0xFFFF903A  :   INTP0 External interrupt
ICP1            :   0xFFFF903C  :   INTP1 External interrupt, CSIH2 communication error interrupt 
ICP2            :   0xFFFF903E  :   INTP2 External interrupt, CSIH2 job completion interrupt
ICWDTA0         :   0xFFFFA040  :   INTWDTA0 WDTA0 75% interrupt
ICWDTA1         :   0xFFFFA042  :   INTWDTA1 WDTA1 75% interrupt
ICP3            :   0xFFFFA044  :   INTP3 External interrupt 
ICP4            :   0xFFFFA046  :   INTP4 External interrupt 
ICP5            :   0xFFFFA048  :   INTP5 External interrupt 
ICP10           :   0xFFFFA04A  :   INTP10 External interrupt
ICP11           :   0xFFFFA04C  :   INTP11 External interrupt
ICTAUD0I1       :   0xFFFFA04E  :   INTTAUD0I1 Interrupt for TAUD0 channel 1
ICTAUD0I3       :   0xFFFFA050  :   INTTAUD0I3 Interrupt for TAUD0 channel 3
ICTAUD0I5       :   0xFFFFA052  :   INTTAUD0I5 Interrupt for TAUD0 channel 5
ICTAUD0I7       :   0xFFFFA054  :   INTTAUD0I7 Interrupt for TAUD0 channel 7
ICTAUD0I9       :   0xFFFFA056  :   INTTAUD0I9 Interrupt for TAUD0 channel 9
ICTAUD0I11      :   0xFFFFA058  :   INTTAUD0I11 Interrupt for TAUD0 channel 11 
ICTAUD0I13      :   0xFFFFA05A  :   INTTAUD0I13 Interrupt for TAUD0 channel 13 
ICTAUD0I15      :   0xFFFFA05C  :   INTTAUD0I15 Interrupt for TAUD0 channel 15 
ICADCA0ERR      :   0xFFFFA05E  :   INTADCA0ERR ADCA0 error interrupt ADCA0 
ICCSIG0IRE      :   0xFFFFA062  :   INTCSIG0IRE CSIG0 communication error interrupt
ICRLIN20        :   0xFFFFA064  :   INTRLIN20 RLIN20 interrupt 
ICRLIN21        :   0xFFFFA066  :   INTRLIN21 RLIN21 interrupt 
ICDMA0          :   0xFFFFA068  :   INTDMA0 DMA0 transfer completion 
ICDMA1          :   0xFFFFA06A  :   INTDMA1 DMA1 transfer completion 
ICDMA2          :   0xFFFFA06C  :   INTDMA2 DMA2 transfer completion 
ICDMA3          :   0xFFFFA06E  :   INTDMA3 DMA3 transfer completion 
ICDMA4          :   0xFFFFA070  :   INTDMA4 DMA4 transfer completion 
ICDMA5          :   0xFFFFA072  :   INTDMA5 DMA5 transfer completion 
ICDMA6          :   0xFFFFA074  :   INTDMA6 DMA6 transfer completion 
ICDMA7          :   0xFFFFA076  :   INTDMA7 DMA7 transfer completion 
ICDMA8          :   0xFFFFA078  :   INTDMA8 DMA8 transfer completion 
ICDMA9          :   0xFFFFA07A  :   INTDMA9 DMA9 transfer completion 
ICDMA10         :   0xFFFFA07C  :   INTDMA10 DMA10 transfer completion
ICDMA11         :   0xFFFFA07E  :   INTDMA11 DMA11 transfer completion
ICDMA12         :   0xFFFFA080  :   INTDMA12 DMA12 transfer completion
ICDMA13         :   0xFFFFA082  :   INTDMA13 DMA13 transfer completion
ICDMA14         :   0xFFFFA084  :   INTDMA14 DMA14 transfer completion
ICDMA15         :   0xFFFFA086  :   INTDMA15 DMA15 transfer completion
ICRIIC0TI       :   0xFFFFA088  :   INTRIIC0TI RIIC transmit data empty interrupt
ICRIIC0TEI      :   0xFFFFA08A  :   INTRIIC0TEI RIIC transmit complete interrupt
ICRIIC0RI       :   0xFFFFA08C  :   INTRIIC0RI RIIC receive complete interrupt 
ICRIIC0EE       :   0xFFFFA08E  :   INTRIIC0EE RIIC communication error/event interrupt
ICTAUJ0I0       :   0xFFFFA090  :   INTTAUJ0I0 Interrupt for TAUJ0 channel 0
ICTAUJ0I1       :   0xFFFFA092  :   INTTAUJ0I1 Interrupt for TAUJ0 channel 1
ICTAUJ0I2       :   0xFFFFA094  :   INTTAUJ0I2 Interrupt for TAUJ0 channel 2
ICTAUJ0I3       :   0xFFFFA096  :   INTTAUJ0I3 Interrupt for TAUJ0 channel 3
ICOSTM0         :   0xFFFFA098  :   INTOSTM0*11 OSTM0 interrupt
ICENCA0IOV      :   0xFFFFA09A  :   INTENCA0IOV ENCA0 overflow interrupt, PWGA4 interrupt
ICENCA0IUD      :   0xFFFFA09C  :   INTENCA0IUD ENCA0 underflow interrupt, PWGA5 interrupt
ICENCA0I0       :   0xFFFFA09E  :   INTENCA0I0 ENCA0 capture/compare match interrupt 0, PWGA6 interrupt
ICENCA0I1       :   0xFFFFA0A0  :   INTENCA0I1 ENCA0 capture/compare match interrupt 1, PWGA7 interrupt
ICENCA0IEC      :   0xFFFFA0A2  :   INTENCA0IEC ENCA0 encoder clear interrupt
ICKR0           :   0xFFFFA0A4  :   INTKR0 KR0 key interrupt KR0
ICQFULL         :   0xFFFFA0A6  :   INTQFULL PWSA queue full interrupt
ICPWGA0         :   0xFFFFA0A8  :   INTPWGA0 PWGA0 interrupt 
ICPWGA1         :   0xFFFFA0AA  :   INTPWGA1 PWGA1 interrupt 
ICPWGA2         :   0xFFFFA0AC  :   INTPWGA2 PWGA2 interrupt 
ICPWGA3         :   0xFFFFA0AE  :   INTPWGA3 PWGA3 interrupt 
ICPWGA8         :   0xFFFFA0B0  :   INTPWGA8 PWGA8 interrupt 
ICPWGA9         :   0xFFFFA0B2  :   INTPWGA9 PWGA9 interrupt 
ICPWGA10        :   0xFFFFA0B4  :   INTPWGA10 PWGA10 interrupt
ICPWGA11        :   0xFFFFA0B6  :   INTPWGA11 PWGA11 interrupt
ICPWGA12        :   0xFFFFA0B8  :   INTPWGA12 PWGA12 interrupt
ICPWGA13        :   0xFFFFA0BA  :   INTPWGA13 PWGA13 interrupt
ICPWGA14        :   0xFFFFA0BC  :   INTPWGA14 PWGA14 interrupt
ICPWGA15        :   0xFFFFA0BE  :   INTPWGA15 PWGA15 interrupt
ICFLERR         :   0xFFFFA0CC  :   INTFLERR Flash sequencer access error interrupt
ICFLENDNM       :   0xFFFFA0CE  :   INTFLENDNM Flash sequencer end interrupt
ICCWEND         :   0xFFFFA0D0  :   INTCWEND LPS0 port polling end interrupt
ICRCAN1ERR      :   0xFFFFA0D2  :   INTRCAN1ERR CAN1 error interrupt
ICRCAN1REC      :   0xFFFFA0D4  :   INTRCAN1REC CAN1 transmit/receive FIFO receive complete interrupt
ICRCAN1TRX      :   0xFFFFA0D6  :   INTRCAN1TRX CAN1 transmit interrupt
ICCSIH1IC       :   0xFFFFA0D8  :   INTCSIH1IC CSIH1 communication status interrupt, TAPA0 peak interrupt 0
ICCSIH1IR       :   0xFFFFA0DA  :   INTCSIH1IR CSIH1 receive status interrupt, TAPA0 valley interrupt 0
ICCSIH1IRE      :   0xFFFFA0DC  :   INTCSIH1IRE CSIH1 communication error interrupt, CSIG0 communication status interrupt
ICCSIH1IJC      :   0xFFFFA0DE  :   INTCSIH1IJC CSIH1 job completion interrupt, CSIG0 receive status interrupt
ICRLIN31        :   0xFFFFA0E0  :   INTRLIN31 RLIN31 interrupt
ICRLIN31UR0     :   0xFFFFA0E2  :   INTRLIN31UR0 RLIN31 transmit interrupt
ICRLIN31UR1     :   0xFFFFA0E4  :   INTRLIN31UR1 RLIN31 reception complete interrupt
ICRLIN31UR2     :   0xFFFFA0E6  :   INTRLIN31UR2 RLIN31 status interrupt
ICPWGA20        :   0xFFFFA0E8  :   INTPWGA20 PWGA20 interrupt
ICPWGA21        :   0xFFFFA0EA  :   INTPWGA21 PWGA21 interrupt
ICPWGA22        :   0xFFFFA0EC  :   INTPWGA22 PWGA22 interrupt
ICPWGA23        :   0xFFFFA0EE  :   INTPWGA23 PWGA23 interrupt
ICP6            :   0xFFFFA0F0  :   INTP6 External interrupt
ICP7            :   0xFFFFA0F2  :   INTP7 External interrupt
ICP8            :   0xFFFFA0F4  :   INTP8 External interrupt
ICP12           :   0xFFFFA0F6  :   INTP12 External interrupt
ICCSIH2IC       :   0xFFFFA0F8  :   INTCSIH2IC CSIH2 communication status interrupt, Interrupt for TAUD0 channel 0
ICCSIH2IR       :   0xFFFFA0FA  :   INTCSIH2IR CSIH2 receive status interrupt, INTP0_2 External interrupt
ICCSIH2IRE      :   0xFFFFA0FC  :   INTCSIH2IRE CSIH2 communication error interrupt,  INTP1_2 External interrupt
ICCSIH2IJC      :   0xFFFFA0FE  :   INTCSIH2IJC CSIH2 job completion interrupt, INTP2_2 External interrupt
ICTAUB0I0       :   0xFFFFA10C  :   INTTAUB0I0 Interrupt for TAUB0 channel 0 
ICTAUB0I1       :   0xFFFFA10E  :   INTTAUB0I1 Interrupt for TAUB0 channel 1 
ICTAUB0I2       :   0xFFFFA110  :   INTTAUB0I2 Interrupt for TAUB0 channel 2 
ICTAUB0I3       :   0xFFFFA112  :   INTTAUB0I3 Interrupt for TAUB0 channel 3, PWGA16 interrupt
ICTAUB0I4       :   0xFFFFA114  :   INTTAUB0I4 Interrupt for TAUB0 channel 4
ICTAUB0I5       :   0xFFFFA116  :   INTTAUB0I5 Interrupt for TAUB0 channel 5, PWGA17 interrupt
ICTAUB0I6       :   0xFFFFA118  :   INTTAUB0I6 Interrupt for TAUB0 channel 6
ICTAUB0I7       :   0xFFFFA11A  :   INTTAUB0I7 Interrupt for TAUB0 channel 7, PWGA18 interrupt
ICTAUB0I8       :   0xFFFFA11C  :   INTTAUB0I8 Interrupt for TAUB0 channel 8 
ICTAUB0I9       :   0xFFFFA11E  :   INTTAUB0I9 Interrupt for TAUB0 channel 9, PWGA19 interrupt
ICTAUB0I10      :   0xFFFFA120  :   INTTAUB0I10 Interrupt for TAUB0 channel 10
ICTAUB0I11      :   0xFFFFA122  :   INTTAUB0I11 Interrupt for TAUB0 channel 11, PWGA26 interrupt
ICTAUB0I12      :   0xFFFFA124  :   INTTAUB0I12 Interrupt for TAUB0 channel 12
ICTAUB0I13      :   0xFFFFA126  :   INTTAUB0I13 Interrupt for TAUB0 channel 13, PWGA30 interrupt
ICTAUB0I14      :   0xFFFFA128  :   INTTAUB0I14 Interrupt for TAUB0 channel 14
ICTAUB0I15      :   0xFFFFA12A  :   INTTAUB0I15 Interrupt for TAUB0 channel 15, PWGA31 interrupt
ICCSIH3IC       :   0xFFFFA12C  :   INTCSIH3IC CSIH3 communication status interrupt, TAUD0 channel 2
ICCSIH3IR       :   0xFFFFA12E  :   INTCSIH3IR CSIH3 receive status interrupt, TAUD0 channel 10
ICCSIH3IRE      :   0xFFFFA130  :   INTCSIH3IRE CSIH3 communication error interrupt, Interrupt for TAUD0 channel 12
ICCSIH3IJC      :   0xFFFFA132  :   INTCSIH3IJC CSIH3 job completion interrupt, Interrupt for TAUD0 channel 14
ICRLIN22        :   0xFFFFA134  :   INTRLIN22 RLIN22 interrupt
ICRLIN23        :   0xFFFFA136  :   INTRLIN23 RLIN23 interrupt
ICRLIN32        :   0xFFFFA138  :   INTRLIN32 RLIN32 interrupt
ICRLIN32UR0     :   0xFFFFA13A  :   INTRLIN32UR0 RLIN32 transmit interrupt
ICRLIN32UR1     :   0xFFFFA13C  :   INTRLIN32UR1 RLIN32 reception complete interrupt
ICRLIN32UR2     :   0xFFFFA13E  :   INTRLIN32UR2 RLIN32 status interrupt
ICTAUJ1I0       :   0xFFFFA140  :   INTTAUJ1I0 Interrupt for TAUJ1 channel 0
ICTAUJ1I1       :   0xFFFFA142  :   INTTAUJ1I1 Interrupt for TAUJ1 channel 1
ICTAUJ1I2       :   0xFFFFA144  :   INTTAUJ1I2 Interrupt for TAUJ1 channel 2
ICTAUJ1I3       :   0xFFFFA146  :   INTTAUJ1I3 Interrupt for TAUJ1 channel 3
ICPWGA24        :   0xFFFFA160  :   INTPWGA24 PWGA24 interrupt 
ICPWGA25        :   0xFFFFA162  :   INTPWGA25 PWGA25 interrupt 
ICPWGA27        :   0xFFFFA164  :   INTPWGA27 PWGA27 interrupt 
ICPWGA28        :   0xFFFFA166  :   INTPWGA28 PWGA28 interrupt
ICPWGA29        :   0xFFFFA168  :   INTPWGA29 PWGA29 interrupt
ICPWGA32        :   0xFFFFA16A  :   INTPWGA32 PWGA32 interrupt
ICPWGA33        :   0xFFFFA16C  :   INTPWGA33 PWGA33 interrupt
ICPWGA34        :   0xFFFFA16E  :   INTPWGA34 PWGA34 interrupt
ICPWGA35        :   0xFFFFA170  :   INTPWGA35 PWGA35 interrupt
ICPWGA36        :   0xFFFFA172  :   INTPWGA36 PWGA36 interrupt
ICPWGA37        :   0xFFFFA174  :   INTPWGA37 PWGA37 interrupt
ICPWGA38        :   0xFFFFA176  :   INTPWGA38 PWGA38 interrupt
ICPWGA39        :   0xFFFFA178  :   INTPWGA39 PWGA39 interrupt
ICPWGA40        :   0xFFFFA17A  :   INTPWGA40 PWGA40 interrupt
ICPWGA41        :   0xFFFFA17C  :   INTPWGA41 PWGA41 interrupt
ICPWGA42        :   0xFFFFA17E  :   INTPWGA42 PWGA42 interrupt
ICPWGA43        :   0xFFFFA180  :   INTPWGA43 PWGA43 interrupt
ICPWGA44        :   0xFFFFA182  :   INTPWGA44 PWGA44 interrupt
ICPWGA45        :   0xFFFFA184  :   INTPWGA45 PWGA45 interrupt
ICPWGA46        :   0xFFFFA186  :   INTPWGA46 PWGA46 interrupt
ICPWGA47        :   0xFFFFA188  :   INTPWGA47 PWGA47 interrupt
ICP9            :   0xFFFFA18A  :   INTP9 External interrupt
ICP13           :   0xFFFFA18C  :   INTP13 External interrupt
ICP14           :   0xFFFFA18E  :   INTP14 External interrupt
ICP15           :   0xFFFFA190  :   INTP15 External interrupt
ICRTCA01S       :   0xFFFFA192  :   INTRTCA01S RTCA0 1 second interval interrupt
ICRTCA0AL       :   0xFFFFA194  :   INTRTCA0AL RTCA0 alarm interrupt
ICRTCA0R        :   0xFFFFA196  :   INTRTCA0R RTCA0 periodic interrupt
ICADCA1ERR      :   0xFFFFA198  :   INTADCA1ERR ADCA1 error interrupt
ICADCA1I0       :   0xFFFFA19A  :   INTADCA1I0 ADCA1 scan group 1 (SG1) end interrupt
ICADCA1I1       :   0xFFFFA19C  :   INTADCA1I1 ADCA1 scan group 2 (SG2) end interrupt
ICADCA1I2       :   0xFFFFA19E  :   INTADCA1I2 ADCA1 scan group 3 (SG3) end interrupt
ICRCAN2ERR      :   0xFFFFA1A2  :   INTRCAN2ERR CAN2 error interrupt
ICRCAN2REC      :   0xFFFFA1A4  :   INTRCAN2REC CAN2 transmit/receive FIFO receive complete interrupt
ICRCAN2TRX      :   0xFFFFA1A6  :   INTRCAN2TRX CAN2 transmit interrupt
ICRCAN3ERR      :   0xFFFFA1A8  :   INTRCAN3ERR CAN3 error interrupt
ICRCAN3REC      :   0xFFFFA1AA  :   INTRCAN3REC CAN3 transmit/receive FIFO receive complete interrupt
ICRCAN3TRX      :   0xFFFFA1AC  :   INTRCAN3TRX CAN3 transmit interrupt 
ICCSIG1IC       :   0xFFFFA1AE  :   INTCSIG1IC CSIG1 communication status interrupt
ICCSIG1IR       :   0xFFFFA1B0  :   INTCSIG1IR CSIG1 receive status interrupt
ICCSIG1IRE      :   0xFFFFA1B2  :   INTCSIG1IRE CSIG1 communication error interrupt
ICRLIN24        :   0xFFFFA1B4  :   INTRLIN24 RLIN24 interrupt
ICRLIN25        :   0xFFFFA1B6  :   INTRLIN25 RLIN25 interrupt
ICRLIN33        :   0xFFFFA1B8  :   INTRLIN33 RLIN33 interrupt
ICRLIN33UR0     :   0xFFFFA1BA  :   INTRLIN33UR0 RLIN33 transmit interrupt
ICRLIN33UR1     :   0xFFFFA1BC  :   INTRLIN33UR1 RLIN33 reception complete interrupt
ICRLIN33UR2     :   0xFFFFA1BE  :   INTRLIN33UR2 RLIN33 status interrupt
ICRLIN34        :   0xFFFFA1C0  :   INTRLIN34 RLIN34 interrupt
ICRLIN34UR0     :   0xFFFFA1C2  :   INTRLIN34UR0 RLIN34 transmit interrupt
ICRLIN34UR1     :   0xFFFFA1C4  :   INTRLIN34UR1 RLIN34 reception complete interrupt
ICRLIN34UR2     :   0xFFFFA1C6  :   INTRLIN34UR2 RLIN34 status interrupt 
ICRLIN35        :   0xFFFFA1C8  :   INTRLIN35 RLIN35 interrupt 
ICRLIN35UR0     :   0xFFFFA1CA  :   INTRLIN35UR0 RLIN35 transmit interrupt
ICRLIN35UR1     :   0xFFFFA1CC  :   INTRLIN35UR1 RLIN35 reception complete interrupt
ICRLIN35UR2     :   0xFFFFA1CE  :   INTRLIN35UR2 RLIN35 status interrupt
ICPWGA48        :   0xFFFFA1D0  :   INTPWGA48 PWGA48 interrupt 
ICPWGA49        :   0xFFFFA1D2  :   INTPWGA49 PWGA49 interrupt 
ICPWGA50        :   0xFFFFA1D4  :   INTPWGA50 PWGA50 interrupt 
ICPWGA51        :   0xFFFFA1D6  :   INTPWGA51 PWGA51 interrupt 
ICPWGA52        :   0xFFFFA1D8  :   INTPWGA52 PWGA52 interrupt 
ICPWGA53        :   0xFFFFA1DA  :   INTPWGA53 PWGA53 interrupt 
ICPWGA54        :   0xFFFFA1DC  :   INTPWGA54 PWGA54 interrupt 
ICPWGA55        :   0xFFFFA1DE  :   INTPWGA55 PWGA55 interrupt 
ICPWGA56        :   0xFFFFA1E0  :   INTPWGA56 PWGA56 interrupt 
ICPWGA57        :   0xFFFFA1E2  :   INTPWGA57 PWGA57 interrupt 
ICPWGA58        :   0xFFFFA1E4  :   INTPWGA58 PWGA58 interrupt 
ICPWGA59        :   0xFFFFA1E6  :   INTPWGA59 PWGA59 interrupt 
ICPWGA60        :   0xFFFFA1E8  :   INTPWGA60 PWGA60 interrupt 
ICPWGA61        :   0xFFFFA1EA  :   INTPWGA61 PWGA61 interrupt 
ICPWGA62        :   0xFFFFA1EC  :   INTPWGA62 PWGA62 interrupt 
ICPWGA63        :   0xFFFFA1EE  :   INTPWGA63 PWGA63 interrupt 
ICTAUB1I0       :   0xFFFFA1F0  :   INTTAUB1I0 Interrupt for TAUB1 channel 0
ICTAUB1I1       :   0xFFFFA1F2  :   INTTAUB1I1 Interrupt for TAUB1 channel 1
ICTAUB1I2       :   0xFFFFA1F4  :   INTTAUB1I2 Interrupt for TAUB1 channel 2
ICTAUB1I3       :   0xFFFFA1F6  :   INTTAUB1I3 Interrupt for TAUB1 channel 3
ICTAUB1I4       :   0xFFFFA1F8  :   INTTAUB1I4 Interrupt for TAUB1 channel 4
ICTAUB1I5       :   0xFFFFA1FA  :   INTTAUB1I5 Interrupt for TAUB1 channel 5
ICTAUB1I6       :   0xFFFFA1FC  :   INTTAUB1I6 Interrupt for TAUB1 channel 6
ICTAUB1I7       :   0xFFFFA1FE  :   INTTAUB1I7 Interrupt for TAUB1 channel 7
ICTAUB1I8       :   0xFFFFA200  :   INTTAUB1I8 Interrupt for TAUB1 channel 8
ICTAUB1I9       :   0xFFFFA202  :   INTTAUB1I9 Interrupt for TAUB1 channel 9
ICTAUB1I10      :   0xFFFFA204  :   INTTAUB1I10 Interrupt for TAUB1 channel 10
ICTAUB1I11      :   0xFFFFA206  :   INTTAUB1I11 Interrupt for TAUB1 channel 11
ICTAUB1I12      :   0xFFFFA208  :   INTTAUB1I12 Interrupt for TAUB1 channel 12
ICTAUB1I13      :   0xFFFFA20A  :   INTTAUB1I13 Interrupt for TAUB1 channel 13
ICTAUB1I14      :   0xFFFFA20C  :   INTTAUB1I14 Interrupt for TAUB1 channel 14
ICTAUB1I15      :   0xFFFFA20E  :   INTTAUB1I15 Interrupt for TAUB1 channel 15
ICRCAN4ERR      :   0xFFFFA210  :   INTRCAN4ERR CAN4 error interrupt
ICRCAN4REC      :   0xFFFFA212  :   INTRCAN4REC CAN4 transmit/receive FIFO receivecomplete interrupt
ICRCAN4TRX      :   0xFFFFA214  :   INTRCAN4TRX CAN4 transmit interrupt 
ICRLIN26        :   0xFFFFA216  :   INTRLIN26 RLIN26 interrupt
ICRLIN27        :   0xFFFFA218  :   INTRLIN27 RLIN27 interrupt
ICPWGA64        :   0xFFFFA21A  :   INTPWGA64 PWGA64 interrupt
ICPWGA65        :   0xFFFFA21C  :   INTPWGA65 PWGA65 interrupt
ICPWGA66        :   0xFFFFA21E  :   INTPWGA66 PWGA66 interrupt
ICPWGA67        :   0xFFFFA220  :   INTPWGA67 PWGA67 interrupt
ICPWGA68        :   0xFFFFA222  :   INTPWGA68 PWGA68 interrupt
ICPWGA69        :   0xFFFFA224  :   INTPWGA69 PWGA69 interrupt
ICPWGA70        :   0xFFFFA226  :   INTPWGA70 PWGA70 interrupt
ICPWGA71        :   0xFFFFA228  :   INTPWGA71 PWGA71 interrupt
ICRLIN28        :   0xFFFFA22A  :   INTRLIN28 RLIN28 interrupt
ICRLIN29        :   0xFFFFA22C  :   INTRLIN29 RLIN29 interrupt
ICRCAN5ERR      :   0xFFFFA22E  :   INTRCAN5ERR CAN5 error interrupt
ICRCAN5REC      :   0xFFFFA230  :   INTRCAN5REC CAN5 transmit/receive FIFO receive complete interrupt
ICRCAN5TRX      :   0xFFFFA232  :   INTRCAN5TRX CAN5 transmit interrupt 
"""


def replace_hex(src: str) -> str:
    return re.sub(r"([0-9a-fA-F]+H)", lambda m: f'0x{m.group(0)[:-1]}', src)


def prepare_math_ports(src:str, n_values: list, bases: dict) -> str:
    result = list()
    v = bases.copy()
    v.update(n=0)
    for line in src.split('\n'):
        parts = line.split(':')
        print(f"line:{parts}\n")
        if parts == "" or len(parts) < 2:
            continue
        parts[1] = replace_hex(parts[1]).strip()
        variants = n_values if 'n' in parts[1] else [0]
        saddr = parts[1].replace('<', '').replace('>', '')
        for n in variants:
            reg = parts[0].replace('n', str(n))
            v['n'] = n
            addr = eval(saddr, v)
            print(f"{reg}\t:  0x{addr:X}\t: {parts[2]}\n")
            result.append(f"{reg}\t:  0x{addr:X}\t: {parts[2]}\n")
    return '\n'.join(result)


def make_seg(start, end, name, class_name):
    if not idc.AddSeg(start, end, 0, 1, 0, idaapi.scPub):
        logger.error('failed to add segment: 0x%x', start)
        return -1
    if not idc.set_segm_name(start, name):
        logger.warning('failed to rename segment: %s', name)

    if not idc.set_segm_class(start, class_name):
        logger.warning('failed to set segment class %s: %s', class_name, name)

    if not idc.set_segm_alignment(start, idc.saRelPara):
        logger.warning('failed to align segment: %s', name)


def make_sfr_seg():
    make_seg(0xFF400000, 0xFFFF7FFF, 'SFR', 'SFR')


def make_dma_seg():
    make_seg(0xFFFF8000, 0xFFFFAFFF, 'DMA_INTC', 'DATA')


make_sfr_seg()
make_dma_seg()
hpp_files = ['E:/images/Новая папка (2)/defs/rh850_f1l.hpp']
ida_structs.import_hpp_files(hpp_files)
ida_structs.apply_memmap(memmap)
ida_structs.apply_simple_reg_defs(single_regs)

bases = {
    'PORTn_base': 0xFFC10000,
    'JPORT0_base': 0xFFC10000
}
ida_structs.apply_simple_reg_defs(prepare_math_ports(ap_defs, ap_n, bases))
ida_structs.apply_simple_reg_defs(prepare_math_ports(port_defs, port_n, bases))

ida_structs.apply_simple_reg_defs(interrupt_control)