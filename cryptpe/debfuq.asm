; cryptpe -- Encryption tool for PE binaries
; (C) 2012-2016 Martin Wolters
;
; This program is free software. It comes without any warranty, to
; the extent permitted by applicable law. You can redistribute it
; and/or modify it under the terms of the Do What The Fuck You Want
; To Public License, Version 2, as published by Sam Hocevar. See
; http://sam.zoy.org/wtfpl/COPYING for more details.
;

IFDEF RAX							; Nicer check for x64?

.code
detrlvl PROC						; Code to hide the debugger detector
		mov rax, _label
		db 0ebh						; EB FF	JMP -1 The Disassembler should lose sync here.
		jmp rax						; FF E0	Note the FF coming from the previous instruction.
		db 8dh, 0ffh

_label:								; Debugger detector proper, part I
		mov rax, gs:[60h]
		mov rax, [rax + 0bch]		; PEB, offset 0xbc

		; FLG_HEAP_ENABLE_TAIL_CHECK	(0x10)
		; FLG_HEAP_ENABLE_FREE_CHECK	(0x20)
		; FLG_HEAP_VALIDATE_PARAMETERS	(0x40)
		;								------
		and rax,						   70h

		mov rbx, _label2			; Same as above, rbx this time, because
		db 0ebh						; we use eax to test for the debugger.
		jmp rbx
		db 8dh, 0ffh

_label2:							; Debugger detector, part II
		cmp rax, 70h				; Actual check.

		je _xor						; If there is a debugger present, skip
		mov rbx, 42h				; Set return value to known state

_xor:
		xor rbx, 42h				; Manipulate the return value, so that a
									; random initial state gives a bad result.
		mov rax, rbx
		ret
detrlvl ENDP

ELSE
									
.386								; Win32 variant. Pretty much the same as above.
.model flat, c
.code		
assume fs:nothing

detrlvl PROC
		mov eax, _label
		db 0ebh
		jmp eax
		db 8dh, 0ffh

_label:
		mov eax, fs:[30h]
		mov eax, [eax+68h]

		mov ebx, _label2
		db 0ebh
		jmp ebx
		db 8dh, 0ffh

_label2:
		and eax, 70h
		cmp eax, 70h
		je _xor			
		mov ebx, 42h

_xor:
		xor ebx, 42h
		mov eax, ebx
		retn
detrlvl ENDP

ENDIF

end