;;; For Capstone Engine. AUTO-GENERATED FILE, DO NOT EDIT [xcore-const.el]

;; Operand type for instruction's operands

(defconst capstone-XCORE_OP_INVALID 0)
(defconst capstone-XCORE_OP_REG 1)
(defconst capstone-XCORE_OP_IMM 2)
(defconst capstone-XCORE_OP_MEM 3)

;; XCore registers

(defconst capstone-XCORE_REG_INVALID 0)
(defconst capstone-XCORE_REG_CP 1)
(defconst capstone-XCORE_REG_DP 2)
(defconst capstone-XCORE_REG_LR 3)
(defconst capstone-XCORE_REG_SP 4)
(defconst capstone-XCORE_REG_R0 5)
(defconst capstone-XCORE_REG_R1 6)
(defconst capstone-XCORE_REG_R2 7)
(defconst capstone-XCORE_REG_R3 8)
(defconst capstone-XCORE_REG_R4 9)
(defconst capstone-XCORE_REG_R5 10)
(defconst capstone-XCORE_REG_R6 11)
(defconst capstone-XCORE_REG_R7 12)
(defconst capstone-XCORE_REG_R8 13)
(defconst capstone-XCORE_REG_R9 14)
(defconst capstone-XCORE_REG_R10 15)
(defconst capstone-XCORE_REG_R11 16)

;; pseudo registers
(defconst capstone-XCORE_REG_PC 17)
(defconst capstone-XCORE_REG_SCP 18)
(defconst capstone-XCORE_REG_SSR 19)
(defconst capstone-XCORE_REG_ET 20)
(defconst capstone-XCORE_REG_ED 21)
(defconst capstone-XCORE_REG_SED 22)
(defconst capstone-XCORE_REG_KEP 23)
(defconst capstone-XCORE_REG_KSP 24)
(defconst capstone-XCORE_REG_ID 25)
(defconst capstone-XCORE_REG_ENDING 26)

;; XCore instruction

(defconst capstone-XCORE_INS_INVALID 0)
(defconst capstone-XCORE_INS_ADD 1)
(defconst capstone-XCORE_INS_ANDNOT 2)
(defconst capstone-XCORE_INS_AND 3)
(defconst capstone-XCORE_INS_ASHR 4)
(defconst capstone-XCORE_INS_BAU 5)
(defconst capstone-XCORE_INS_BITREV 6)
(defconst capstone-XCORE_INS_BLA 7)
(defconst capstone-XCORE_INS_BLAT 8)
(defconst capstone-XCORE_INS_BL 9)
(defconst capstone-XCORE_INS_BF 10)
(defconst capstone-XCORE_INS_BT 11)
(defconst capstone-XCORE_INS_BU 12)
(defconst capstone-XCORE_INS_BRU 13)
(defconst capstone-XCORE_INS_BYTEREV 14)
(defconst capstone-XCORE_INS_CHKCT 15)
(defconst capstone-XCORE_INS_CLRE 16)
(defconst capstone-XCORE_INS_CLRPT 17)
(defconst capstone-XCORE_INS_CLRSR 18)
(defconst capstone-XCORE_INS_CLZ 19)
(defconst capstone-XCORE_INS_CRC8 20)
(defconst capstone-XCORE_INS_CRC32 21)
(defconst capstone-XCORE_INS_DCALL 22)
(defconst capstone-XCORE_INS_DENTSP 23)
(defconst capstone-XCORE_INS_DGETREG 24)
(defconst capstone-XCORE_INS_DIVS 25)
(defconst capstone-XCORE_INS_DIVU 26)
(defconst capstone-XCORE_INS_DRESTSP 27)
(defconst capstone-XCORE_INS_DRET 28)
(defconst capstone-XCORE_INS_ECALLF 29)
(defconst capstone-XCORE_INS_ECALLT 30)
(defconst capstone-XCORE_INS_EDU 31)
(defconst capstone-XCORE_INS_EEF 32)
(defconst capstone-XCORE_INS_EET 33)
(defconst capstone-XCORE_INS_EEU 34)
(defconst capstone-XCORE_INS_ENDIN 35)
(defconst capstone-XCORE_INS_ENTSP 36)
(defconst capstone-XCORE_INS_EQ 37)
(defconst capstone-XCORE_INS_EXTDP 38)
(defconst capstone-XCORE_INS_EXTSP 39)
(defconst capstone-XCORE_INS_FREER 40)
(defconst capstone-XCORE_INS_FREET 41)
(defconst capstone-XCORE_INS_GETD 42)
(defconst capstone-XCORE_INS_GET 43)
(defconst capstone-XCORE_INS_GETN 44)
(defconst capstone-XCORE_INS_GETR 45)
(defconst capstone-XCORE_INS_GETSR 46)
(defconst capstone-XCORE_INS_GETST 47)
(defconst capstone-XCORE_INS_GETTS 48)
(defconst capstone-XCORE_INS_INCT 49)
(defconst capstone-XCORE_INS_INIT 50)
(defconst capstone-XCORE_INS_INPW 51)
(defconst capstone-XCORE_INS_INSHR 52)
(defconst capstone-XCORE_INS_INT 53)
(defconst capstone-XCORE_INS_IN 54)
(defconst capstone-XCORE_INS_KCALL 55)
(defconst capstone-XCORE_INS_KENTSP 56)
(defconst capstone-XCORE_INS_KRESTSP 57)
(defconst capstone-XCORE_INS_KRET 58)
(defconst capstone-XCORE_INS_LADD 59)
(defconst capstone-XCORE_INS_LD16S 60)
(defconst capstone-XCORE_INS_LD8U 61)
(defconst capstone-XCORE_INS_LDA16 62)
(defconst capstone-XCORE_INS_LDAP 63)
(defconst capstone-XCORE_INS_LDAW 64)
(defconst capstone-XCORE_INS_LDC 65)
(defconst capstone-XCORE_INS_LDW 66)
(defconst capstone-XCORE_INS_LDIVU 67)
(defconst capstone-XCORE_INS_LMUL 68)
(defconst capstone-XCORE_INS_LSS 69)
(defconst capstone-XCORE_INS_LSUB 70)
(defconst capstone-XCORE_INS_LSU 71)
(defconst capstone-XCORE_INS_MACCS 72)
(defconst capstone-XCORE_INS_MACCU 73)
(defconst capstone-XCORE_INS_MJOIN 74)
(defconst capstone-XCORE_INS_MKMSK 75)
(defconst capstone-XCORE_INS_MSYNC 76)
(defconst capstone-XCORE_INS_MUL 77)
(defconst capstone-XCORE_INS_NEG 78)
(defconst capstone-XCORE_INS_NOT 79)
(defconst capstone-XCORE_INS_OR 80)
(defconst capstone-XCORE_INS_OUTCT 81)
(defconst capstone-XCORE_INS_OUTPW 82)
(defconst capstone-XCORE_INS_OUTSHR 83)
(defconst capstone-XCORE_INS_OUTT 84)
(defconst capstone-XCORE_INS_OUT 85)
(defconst capstone-XCORE_INS_PEEK 86)
(defconst capstone-XCORE_INS_REMS 87)
(defconst capstone-XCORE_INS_REMU 88)
(defconst capstone-XCORE_INS_RETSP 89)
(defconst capstone-XCORE_INS_SETCLK 90)
(defconst capstone-XCORE_INS_SET 91)
(defconst capstone-XCORE_INS_SETC 92)
(defconst capstone-XCORE_INS_SETD 93)
(defconst capstone-XCORE_INS_SETEV 94)
(defconst capstone-XCORE_INS_SETN 95)
(defconst capstone-XCORE_INS_SETPSC 96)
(defconst capstone-XCORE_INS_SETPT 97)
(defconst capstone-XCORE_INS_SETRDY 98)
(defconst capstone-XCORE_INS_SETSR 99)
(defconst capstone-XCORE_INS_SETTW 100)
(defconst capstone-XCORE_INS_SETV 101)
(defconst capstone-XCORE_INS_SEXT 102)
(defconst capstone-XCORE_INS_SHL 103)
(defconst capstone-XCORE_INS_SHR 104)
(defconst capstone-XCORE_INS_SSYNC 105)
(defconst capstone-XCORE_INS_ST16 106)
(defconst capstone-XCORE_INS_ST8 107)
(defconst capstone-XCORE_INS_STW 108)
(defconst capstone-XCORE_INS_SUB 109)
(defconst capstone-XCORE_INS_SYNCR 110)
(defconst capstone-XCORE_INS_TESTCT 111)
(defconst capstone-XCORE_INS_TESTLCL 112)
(defconst capstone-XCORE_INS_TESTWCT 113)
(defconst capstone-XCORE_INS_TSETMR 114)
(defconst capstone-XCORE_INS_START 115)
(defconst capstone-XCORE_INS_WAITEF 116)
(defconst capstone-XCORE_INS_WAITET 117)
(defconst capstone-XCORE_INS_WAITEU 118)
(defconst capstone-XCORE_INS_XOR 119)
(defconst capstone-XCORE_INS_ZEXT 120)
(defconst capstone-XCORE_INS_ENDING 121)

;; Group of XCore instructions

(defconst capstone-XCORE_GRP_INVALID 0)

;; Generic groups
(defconst capstone-XCORE_GRP_JUMP 1)
(defconst capstone-XCORE_GRP_ENDING 2)

(provide 'capstone-xcore-const)
