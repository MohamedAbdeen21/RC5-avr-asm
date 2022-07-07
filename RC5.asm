; Mohamed Yasser Abdeen 
; 120190031

; remove the definitions since we will not be using the X register
.UNDEF XH
.UNDEF XL

// --- Input ---
.EQU A = 0x3040
.EQU B = 0x7080
KEY: .DB 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC

.EQU P = 0xB7E1 ; constant
.EQU Q = 0x9E37 ; constant

.EQU L = 0x0500 ; L array for key expansion
.EQU S = 0x0600 ; S array for key expansion

// --- ADD/REMOVE KEY ---
; Add S[_] to @0
.MACRO ADD_KEY_TO 
	LD R20, Z+ ; where we store S
	LD R21, Z+
	ADD LOW@0, R20
	ADC HIGH@0, R21
.ENDMACRO

.MACRO RM_KEY_FROM 
	LD R21, -Z
	LD R20, -Z
	SUB LOW@0, R20
	SBC HIGH@0, R21
.ENDMACRO

// --- SHIFTS ---
; shift entire word through carry, the shift amount is in R20
.MACRO SHIFTL
SHIFTL@0:
	CLC 
	SBRC HIGH@0, 7
	SEC 
	ROL LOW@0 
	ROL HIGH@0
	DEC R20 
	BRNE SHIFTL@0
.ENDMACRO

; same as SHIFTL, used for decryption
.MACRO SHIFTR 
SHIFTR@0:
	CLC 
	SBRC HIGH@0, 0
	SEC 
	ROR LOW@0
	ROR HIGH@0
	DEC R20
	BRNE SHIFTR@0
.ENDMACRO

// --- ENCRYPTION/DECRYPTION half rounds ---
; @0 = (@0 XOR @1) <<< @1 + S[_]
.MACRO HALFROUNDE ; half round encryption
	EOR LOW@0 , LOW@1
	EOR HIGH@0 , HIGH@1
	
	; take the first 4 bits for rotating
	MOV R20, LOW@1
	ANDI R20, 0b00001111

	BREQ END ; skip shift is the amount is zero, shift macro doesn't handle that case
	SHIFTL @0
END:
	ADD_KEY_TO @0
.ENDMACRO

.MACRO HALFROUNDD ; half round decryption
	RM_KEY_FROM @0
	MOV R20, LOW@1
	ANDI R20,0b00001111
	BREQ NO_SHIFT
	SHIFTR @0
NO_SHIFT:
	EOR LOW@0, LOW@1
	EOR HIGH@0, HIGH@1
.ENDMACRO

.// --- MOD ---
.MACRO MOD 
	CPI @0, @1
	BRNE END
	LDI @0, 0
END:
	NOP 
.ENDMACRO

// --- Half of third key expansion step ---
; A = S[i] =  (S[i] + A + B) <<< (3) or
; B = L[j] =  (L[j] + A + B) <<< (A+B)
.MACRO HALFTHIRD ; L or S, I or J, Y or Z
	LDI @2L, LOW(@0) ; reset pointer
	ADD @2L, @1
	ADD @2L, @1 ; jump to @0 [ @1 ]
	LD LOW@0, @2
	LDD HIGH@0, @2+1 ; doesn't add the value to the register
	ADD LOW@0, R18
	ADC HIGH@0, R19
	ADD LOW@0, R21
	ADC HIGH@0, R22
	.IF @0 == L ; shift amount
		MOV R20, R18
		ADD R20, R21
		ANDI R20, 0b00001111 
	.ELSE
		LDI R20, 3
	.ENDIF
	CPI R20, 0
	BREQ SKIPSHIFT ; in case A + B == 0. shift macro doesn't handle that case
	SHIFTL @0
	MOV R18, LOWS
	MOV R19, HIGHS ; updating A both times (with L and S) will not cause bugs
SKIPSHIFT:
	ST @2+, LOW@0
	ST @2+, HIGH@0
.ENDMACRO

// Key expansion first step
; why we multiply by 2: http://www.rjhcoding.com/avr-asm-pm.php
LDI ZL, LOW(2*KEY)
LDI ZH, HIGH(2*KEY) ; Z register
LDI YL, LOW(L)
LDI YH, HIGH(L) ; store L in memory 0x0500 through Y register
LDI R25, 6 ; Counter: 6 instead of 12 because we load 2-bytes per loop
.DEF LOWL = R26
.DEF HIGHL = R27

KX_FIRSTSTEP:
	LPM LOWL, Z+
	LPM HIGHL, Z+
	ST Y+, LOWL
	ST Y+, HIGHL
	DEC R25
	BRNE KX_FIRSTSTEP

LDI YL, LOW(L)
LDI YH, HIGH(L) ; return the pointer to top of L

// key expansion second step
.UNDEF LOWL
.UNDEF HIGHL
.DEF LOWS = R24
.DEF HIGHS = R25

LDI ZL, LOW(S)
LDI ZH, HIGH(S) ; store s in memory 0x0600 through Z register
CLR LOWS
CLR HIGHS
LDI R26, LOW(P)
LDI R27, HIGH(P)
ADD LOWS, R26
ADC HIGHS, R27
ST Z+, LOWS
ST Z+, HIGHS

LDI R18, 17
LDI R26, LOW(Q)
LDI R27, HIGH(Q)
KX_SECONDSTEP:
	ADD LOWS, R26
	ADD HIGHS, R27
	ST Z+, LOWS
	ST Z+, HIGHS
	DEC R18
	BRNE KX_SECONDSTEP

.DEF I = R16
.DEF J = R17

// key expansion third step
.DEF LOWL = R26
.DEF HIGHL = R27

LDI I, 0x00 ; i
LDI J, 0x00 ; j
LDI R18, 0x00 ; LOW(A)
LDI R19, 0x00 ; HIGH(A)
LDI R21, 0x00 ; LOW(B)
LDI R22, 0x00 ; HIGH(A)

LDI R23, 54 ; COUNTER (3 * t:18)
LDI ZL, LOW(S)
LDI ZH, HIGH(S) ; S through Z
; we already returned Y to point to top of L
KX_THIRDSTEP:
	HALFTHIRD S, I, Z ; updates A
	HALFTHIRD L, J, Y
	MOV R20, LOWL
	MOV R21, HIGHL ; update B
	; increment I and J
	LDI LOWL, 1 ; Ran out of upper registers (can use MOV though), we can safely use LOWL since we reset it at the start anyway
	ADD I, LOWL
	ADD J, LOWL
	MOD I, 18 ; if I == 18, set I to zero
	MOD J, 6 ; if J == 6, set J to zero

	DEC R23
	BRNE KX_THIRDSTEP

// --- Key expansion done, S is found in 0x600 ---
; remove unnecessary .DEF
.UNDEF I
.UNDEF J
.UNDEF LOWL
.UNDEF HIGHL

.DEF LOWA = R16
.DEF HIGHA = R17
.DEF LOWB = R18
.DEF HIGHB = R19

LDI LOWA, LOW(A)
LDI HIGHA, HIGH(A)
LDI LOWB, LOW(B)
LDI HIGHB, HIGH(B)

// start encryption
.MACRO ENCRYPT
	LDI ZL, LOW(S)
	LDI ZH, HIGH(S)

	ADD_KEY_TO A
	ADD_KEY_TO B

	LDI R29, 8
	STARTROUNDE: ; start round encryption
		HALFROUNDE A, B
		HALFROUNDE B, A
		DEC R29
		BRNE STARTROUNDE
.ENDMACRO

// start decryption 
.MACRO DECRYPT
	LDI ZL, LOW(S) + 18 * 2 ; end of memory block, right after where S is stored
	LDI ZH, HIGH(S) ; The lower part of S doesn't overflow to the higher part of S

	LDI R29, 8
	STARTROUNDD: ; start round decryption
		HALFROUNDD B, A
		HALFROUNDD A, B
		DEC R29
		BRNE STARTROUNDD
		 
	RM_KEY_FROM B
	RM_KEY_FROM A
.ENDMACRO

ENCRYPT
DECRYPT
