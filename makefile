all: pingo snif

pingo:myping.c
	gcc -o pingo myping.c -lpcap

snif:sniffer.c
	gcc -o snif sniffer.c -lpcap
