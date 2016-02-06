; cryptpe -- Encryption tool for PE binaries
; (C) 2012-2016 Martin Wolters
;
; This program is free software. It comes without any warranty, to
; the extent permitted by applicable law. You can redistribute it
; and/or modify it under the terms of the Do What The Fuck You Want
; To Public License, Version 2, as published by Sam Hocevar. See
; http://sam.zoy.org/wtfpl/COPYING for more details.
;

 .386
.model flat, c
.code		
assume fs:nothing
detrlvl PROC
; Code to hide the debugger detector
		mov eax, _label
		db 0ebh			; EB FF	JMP -1 The Disassembler should lose sync here.
		jmp eax			; FF E0	Note the FF coming from the previous instruction.
		db 8dh, 0ffh

; Debugger detector proper, part I
_label:
		mov eax, fs:[30h]
		mov eax, [eax+68h]

		mov ebx, _label2
		db 0ebh			; Same as above, ebx this time, because 
		jmp ebx			; we use eax to test for the debugger. 

; Debugger detector, part II
_label2:
		and eax, 70h
		test eax, eax
		jne _xor			; If there is a debugger present, skip
		mov ebx, 42h

_xor:
		xor ebx, 42h
		mov eax, ebx
		retn
detrlvl ENDP

end