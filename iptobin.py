ip = '192.168.1.1'
print '.'.join([bin(int(x)+256)[3:] for x in ip.split('.')])

#bin = "11110000.1111000.11111111.11110000"

#print '.'.join((str(int(bin[x:x+8], 2)) for x in range(4)))



bin1 = "11110000.10110011.10001001.11111100"
print bin1


print '.'.join([str((int(y,2))) for y in bin1.split('.')])
