; Comprehensive Array Test - Static and Dynamic Arrays
; Tests all array functionality with clear output

start:
    ; ===========================================
    ; STATIC ARRAY TESTS
    ; ===========================================
    
    ; Test 1: Direct Memory Array
    MOV R0, 100
    STORE R0, 1024      ; static_array[0] = 100
    MOV R0, 200
    STORE R0, 1028      ; static_array[1] = 200
    MOV R0, 300
    STORE R0, 1032      ; static_array[2] = 300
    
    ; Access static array[1]
    LOAD R1, 1028       ; Direct access
    SYS R1, PRINT       ; Print 200 (static array[1])
    
    ; Test 2: Indexed Addressing
    MOV R2, 1040        ; Base address for indexed array
    MOV R3, 400
    STORE R3, 1040      ; indexed_array[0] = 400
    MOV R3, 500
    STORE R3, 1044      ; indexed_array[1] = 500
    MOV R3, 600
    STORE R3, 1048      ; indexed_array[2] = 600
    
    ; Access indexed_array[2] using LOAD_INDEXED
    MOV R4, 2           ; Index
    MUL R5, R4, 4       ; Calculate offset
    LOAD_INDEXED R6, R2, R5    ; Load indexed_array[2]
    SYS R6, PRINT       ; Print 600 (indexed array[2])
    
    ; Test 3: STORE_INDEXED
    MOV R7, 1056        ; Base address
    MOV R8, 700
    STORE R8, 1056      ; store_array[0] = 700
    
    ; Modify store_array[0] using STORE_INDEXED
    MOV R9, 0           ; Index
    MUL R10, R9, 4      ; Calculate offset
    MOV R11, 800        ; New value
    STORE_INDEXED R11, R7, R10   ; store_array[0] = 800
    
    ; Verify the change
    LOAD_INDEXED R12, R7, R10    ; Load store_array[0]
    SYS R12, PRINT      ; Print 800 (modified static array[0])
    
    ; ===========================================
    ; DYNAMIC ARRAY TESTS
    ; ===========================================
    
    ; Initialize dynamic array
    MOV R0, 1088        ; Base address
    MOV R1, 0           ; Current size
    MOV R2, 5           ; Maximum capacity
    
    ; Store metadata
    STORE R1, 1088      ; size = 0
    STORE R2, 1092      ; max_capacity = 5
    
    ; Add elements to dynamic array
    MOV R3, 1200        ; Value to add
    CALL append_element
    
    MOV R3, 1300        ; Value to add
    CALL append_element
    
    MOV R3, 1400        ; Value to add
    CALL append_element
    
    ; Print dynamic array size
    LOAD R4, 1088       ; Load size
    SYS R4, PRINT       ; Print size (should be 3)
    
    ; Access dynamic array elements
    MOV R5, 0           ; Index
    CALL get_element
    SYS R6, PRINT       ; Print array[0] (should be 1200)
    
    MOV R5, 1           ; Index
    CALL get_element
    SYS R6, PRINT       ; Print array[1] (should be 1300)
    
    MOV R5, 2           ; Index
    CALL get_element
    SYS R6, PRINT       ; Print array[2] (should be 1400)
    
    ; Test bounds checking
    MOV R5, 10          ; Invalid index
    CALL get_element
    SYS R6, PRINT       ; Print error (should be 999)
    
    ; Modify dynamic array element
    MOV R5, 1           ; Index
    MOV R7, 9999        ; New value
    CALL set_element
    
    ; Verify the change
    MOV R5, 1           ; Index
    CALL get_element
    SYS R6, PRINT       ; Print array[1] (should be 9999)
    
    HALT

; ===========================================
; DYNAMIC ARRAY FUNCTIONS
; ===========================================

; Append element to dynamic array
append_element:
    ; Get current size
    LOAD R8, 1088       ; Load size
    
    ; Check if we have space
    LOAD R9, 1092       ; Load max_capacity
    CMP R8, R9          ; if (size >= max_capacity)
    JGE append_error    ; No space
    
    ; Calculate address for new element
    ADD R10, R8, 2      ; R10 = size + 2 (skip header)
    MUL R10, R10, 4     ; R10 = offset * 4
    ADD R10, R10, R0    ; R10 = base + offset
    
    ; Store the new element
    STORE_INDIRECT R3, R10   ; array[size] = value
    
    ; Increment size
    ADD R8, R8, 1       ; size++
    STORE R8, 1088      ; Store new size
    
    RET

append_error:
    RET

; Get element from dynamic array
get_element:
    ; Check bounds
    LOAD R8, 1088       ; Load size
    CMP R5, R8          ; if (index >= size)
    JGE bounds_error    ; Index out of bounds
    
    ; Calculate address
    ADD R9, R5, 2       ; R9 = index + 2 (skip header)
    MUL R9, R9, 4       ; R9 = offset * 4
    ADD R9, R9, R0      ; R9 = base + offset
    
    ; Load element
    LOAD_INDIRECT R6, R9    ; R6 = array[index]
    
    RET

; Set element in dynamic array
set_element:
    ; Check bounds
    LOAD R8, 1088       ; Load size
    CMP R5, R8          ; if (index >= size)
    JGE bounds_error    ; Index out of bounds
    
    ; Calculate address
    ADD R9, R5, 2       ; R9 = index + 2 (skip header)
    MUL R9, R9, 4       ; R9 = offset * 4
    ADD R9, R9, R0      ; R9 = base + offset
    
    ; Store element
    STORE_INDIRECT R7, R9   ; array[index] = value
    
    RET

bounds_error:
    MOV R6, 999         ; Error value
    RET